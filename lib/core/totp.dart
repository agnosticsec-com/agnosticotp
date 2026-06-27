// AgnosticOTP — TOTP core (RFC 6238 / RFC 4226).
//
// Hand-rolled on `package:crypto` only — deliberately NOT pulling a third-party
// OTP package, to keep the security-critical path free of extra supply-chain
// surface. Algorithm policy: SHA256 is the default; SHA1/SHA512 are supported
// for legacy/interop and are only selected when an imported otpauth:// URI
// explicitly asks for them.

import 'dart:typed_data';

import 'package:crypto/crypto.dart';

/// Hash algorithm used inside the HMAC. The wire names match the `algorithm`
/// field of an otpauth:// URI (RFC 6238 §1.2 / Google otpauth spec).
enum TotpAlgorithm {
  sha1('SHA1'),
  sha256('SHA256'),
  sha512('SHA512');

  const TotpAlgorithm(this.wireName);

  /// Canonical uppercase token as it appears in an otpauth:// URI.
  final String wireName;

  /// The product default for new/manually-entered accounts.
  static const TotpAlgorithm defaultAlgorithm = TotpAlgorithm.sha256;

  /// Parse the otpauth `algorithm` parameter. An absent/unknown value falls
  /// back to [defaultAlgorithm] (SHA256) — see [parseStrict] for import paths
  /// that must NOT silently coerce.
  static TotpAlgorithm parse(String? raw) {
    switch (raw?.trim().toUpperCase()) {
      case 'SHA1':
        return TotpAlgorithm.sha1;
      case 'SHA256':
        return TotpAlgorithm.sha256;
      case 'SHA512':
        return TotpAlgorithm.sha512;
      default:
        return defaultAlgorithm;
    }
  }
}

/// The `crypto` [Hash] backing each algorithm.
Hash _hashFor(TotpAlgorithm algo) {
  switch (algo) {
    case TotpAlgorithm.sha1:
      return sha1;
    case TotpAlgorithm.sha256:
      return sha256;
    case TotpAlgorithm.sha512:
      return sha512;
  }
}

/// Bounds on user-facing parameters. Defends against malicious otpauth URIs
/// that smuggle absurd `digits`/`period` values (see threat model: enrolment
/// surface). RFC 4226 allows 6..8 digits; we permit up to 10 (the truncation
/// math caps usefully at 10 anyway).
const int kMinDigits = 6;
const int kMaxDigits = 10;
const int kMinPeriodSeconds = 5;
const int kMaxPeriodSeconds = 300;

/// Immutable TOTP parameters for one account, minus the secret key bytes
/// (which live only transiently, sourced from secure storage).
class TotpParams {
  TotpParams({
    this.algorithm = TotpAlgorithm.sha256,
    this.digits = 6,
    this.period = 30,
  }) {
    if (digits < kMinDigits || digits > kMaxDigits) {
      throw ArgumentError.value(digits, 'digits', 'must be $kMinDigits..$kMaxDigits');
    }
    if (period < kMinPeriodSeconds || period > kMaxPeriodSeconds) {
      throw ArgumentError.value(
          period, 'period', 'must be $kMinPeriodSeconds..$kMaxPeriodSeconds seconds');
    }
  }

  final TotpAlgorithm algorithm;
  final int digits;
  final int period;
}

/// Generates RFC 6238 TOTP codes.
///
/// [keyBytes] is the raw (base32-decoded) shared secret. The caller owns its
/// lifetime; this class neither stores nor copies it beyond the call.
class TotpGenerator {
  const TotpGenerator(this.params);

  final TotpParams params;

  /// The current TOTP code as a zero-padded string of [TotpParams.digits].
  ///
  /// [now] defaults to the device wall clock; injectable for testing and for
  /// callers that want NTP-corrected time (clock-manipulation hardening).
  String code(Uint8List keyBytes, {DateTime? now}) {
    final t = now ?? DateTime.now();
    final counter = _counterFor(t.toUtc());
    return _hotp(keyBytes, counter);
  }

  /// Seconds remaining in the current time-step, for the countdown UI.
  int secondsRemaining({DateTime? now}) {
    final epochSeconds = (now ?? DateTime.now()).toUtc().millisecondsSinceEpoch ~/ 1000;
    return params.period - (epochSeconds % params.period);
  }

  /// floor(unixtime / period), per RFC 6238 with T0 = 0.
  int _counterFor(DateTime utc) {
    final epochSeconds = utc.millisecondsSinceEpoch ~/ 1000;
    return epochSeconds ~/ params.period;
  }

  /// HOTP (RFC 4226 §5.3): HMAC over the 8-byte big-endian counter, dynamic
  /// truncation, then reduce mod 10^digits.
  String _hotp(Uint8List keyBytes, int counter) {
    final msg = _counterToBytes(counter);
    final hmac = Hmac(_hashFor(params.algorithm), keyBytes);
    final digest = hmac.convert(msg).bytes;

    final offset = digest[digest.length - 1] & 0x0f;
    final binary = ((digest[offset] & 0x7f) << 24) |
        ((digest[offset + 1] & 0xff) << 16) |
        ((digest[offset + 2] & 0xff) << 8) |
        (digest[offset + 3] & 0xff);

    final modulo = _pow10(params.digits);
    final otp = binary % modulo;
    return otp.toString().padLeft(params.digits, '0');
  }

  /// 8-byte big-endian counter block (RFC 4226 §5.1).
  Uint8List _counterToBytes(int counter) {
    final bytes = Uint8List(8);
    var value = counter;
    for (var i = 7; i >= 0; i--) {
      bytes[i] = value & 0xff;
      value >>= 8;
    }
    return bytes;
  }

  static int _pow10(int n) {
    var result = 1;
    for (var i = 0; i < n; i++) {
      result *= 10;
    }
    return result;
  }
}
