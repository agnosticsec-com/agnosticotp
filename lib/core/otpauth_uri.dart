// AgnosticOTP — otpauth:// URI parsing (Key Uri Format).
//
// This is the enrolment trust boundary for QR / deep-link input. Everything
// here treats the URI as ATTACKER-CONTROLLED: a QR code (live or from the
// gallery) can carry an oversized, malformed, or downgrade-shaped URI. The
// parser is strict, bounds every field, and hands off to Account.create which
// re-validates the secret.

import '../data/account.dart';
import 'totp.dart';

/// Hard cap on the raw URI length we will even attempt to parse — a QR can
/// encode several KB; an authenticator credential needs only ~100 bytes.
const int kMaxOtpauthUriLength = 1024;

class OtpauthParseException implements Exception {
  const OtpauthParseException(this.message);
  final String message;
  @override
  String toString() => 'OtpauthParseException: $message';
}

class OtpauthUri {
  /// Parse a `otpauth://totp/...` URI into a validated [Account].
  ///
  /// Throws [OtpauthParseException] for anything we won't accept. HOTP
  /// (counter-based) is explicitly rejected — this app is TOTP-only in v1.
  static Account parseToAccount(String raw) {
    final input = raw.trim();
    if (input.isEmpty) {
      throw const OtpauthParseException('Empty QR / URI.');
    }
    if (input.length > kMaxOtpauthUriLength) {
      throw const OtpauthParseException('URI is implausibly long; refusing.');
    }

    final Uri uri;
    try {
      uri = Uri.parse(input);
    } on FormatException {
      throw const OtpauthParseException('Not a valid URI.');
    }

    if (uri.scheme.toLowerCase() != 'otpauth') {
      throw const OtpauthParseException('Not an otpauth:// QR code.');
    }
    final type = uri.host.toLowerCase();
    if (type == 'hotp') {
      throw const OtpauthParseException(
          'Counter-based (HOTP) codes are not supported.');
    }
    if (type != 'totp') {
      throw OtpauthParseException('Unsupported otpauth type: ${uri.host}.');
    }

    final params = uri.queryParameters;

    // --- secret (required) ---
    final secret = params['secret'];
    if (secret == null || secret.trim().isEmpty) {
      throw const OtpauthParseException('QR is missing the secret.');
    }

    // --- label / issuer ---
    // Path is "/Issuer:Account" or "/Account"; the issuer query param wins.
    final rawLabel =
        uri.pathSegments.isNotEmpty ? uri.pathSegments.first : '';
    String label = rawLabel;
    String issuerFromLabel = '';
    final colon = rawLabel.indexOf(':');
    if (colon >= 0) {
      issuerFromLabel = rawLabel.substring(0, colon).trim();
      label = rawLabel.substring(colon + 1).trim();
    }
    final issuer = (params['issuer']?.trim().isNotEmpty ?? false)
        ? params['issuer']!.trim()
        : issuerFromLabel;

    // --- algorithm: THE policy. Absent/unknown ⇒ SHA256 (the product default),
    //     SHA1 only honoured when the URI explicitly says so (legacy interop).
    final algorithm = TotpAlgorithm.parse(params['algorithm']);

    // --- digits / period: parse defensively; Account.create/TotpParams bound
    //     them and will reject out-of-range values from a hostile QR. ---
    final digits = _parseIntOr(params['digits'], 6, field: 'digits');
    final period = _parseIntOr(params['period'], 30, field: 'period');

    try {
      return Account.create(
        issuer: issuer,
        label: label.isEmpty ? (issuer.isEmpty ? 'Unnamed' : issuer) : label,
        rawSecret: secret,
        algorithm: algorithm,
        digits: digits,
        period: period,
      );
    } on FormatException catch (e) {
      // Re-wrap the secret/param validation failure as a parse error so the UI
      // shows one consistent "bad QR" surface (and never echoes the secret).
      throw OtpauthParseException(e.message);
    } on ArgumentError catch (e) {
      throw OtpauthParseException('${e.name ?? 'parameter'}: ${e.message}');
    }
  }

  static int _parseIntOr(String? raw, int fallback, {required String field}) {
    if (raw == null || raw.trim().isEmpty) return fallback;
    final v = int.tryParse(raw.trim());
    if (v == null) {
      throw OtpauthParseException('Non-numeric $field in QR.');
    }
    return v;
  }
}
