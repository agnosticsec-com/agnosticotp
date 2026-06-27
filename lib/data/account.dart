// AgnosticOTP — account model.
//
// One [Account] = one enrolled TOTP secret plus its parameters. The base32
// secret is validated and length-checked at construction so that a malformed
// or weak secret is rejected at the enrolment boundary, never at code-gen time
// (where the failure would be a silent wrong-code).

import 'dart:convert';
import 'dart:typed_data';

import 'package:base32/base32.dart';
import 'package:crypto/crypto.dart';

import '../core/totp.dart';

/// Minimum decoded secret length we accept. RFC 4226 §4 R6 recommends ≥128 bits
/// (and ≥160 for SHA1); we hard-floor at 80 bits for interop with services that
/// issue 16-char base32 secrets, and surface anything weaker as a rejection.
const int kMinSecretBytes = 10; // 80 bits

class Account {
  Account._({
    required this.id,
    required this.issuer,
    required this.label,
    required this.secretBase32,
    required this.params,
  });

  /// Stable identifier derived from issuer|label|secret — lets re-imports of
  /// the same credential dedupe without a random-id dependency, while distinct
  /// secrets for the same label stay distinct.
  final String id;

  final String issuer;
  final String label;

  /// Normalised base32 secret (uppercase, no spaces/padding). Treat as
  /// sensitive — never log this.
  final String secretBase32;

  final TotpParams params;

  TotpAlgorithm get algorithm => params.algorithm;

  /// Decode the secret to raw key bytes for HMAC. Caller owns the lifetime and
  /// should avoid retaining it. Throws nothing the constructor didn't already
  /// validate.
  Uint8List keyBytes() => base32.decode(secretBase32);

  /// Construct + validate. [rawSecret] may contain spaces and lowercase and
  /// trailing '=' padding (as users paste it); it is normalised here.
  ///
  /// Throws [FormatException] on a non-base32 or too-short secret.
  factory Account.create({
    required String issuer,
    required String label,
    required String rawSecret,
    TotpAlgorithm algorithm = TotpAlgorithm.sha256,
    int digits = 6,
    int period = 30,
  }) {
    final normalized = normalizeSecret(rawSecret);
    if (normalized.isEmpty) {
      throw const FormatException('Secret is empty.');
    }
    if (!base32.isValid(normalized)) {
      throw const FormatException('Secret is not valid base32 (A–Z, 2–7).');
    }

    final Uint8List decoded;
    try {
      decoded = base32.decode(normalized);
    } on FormatException {
      throw const FormatException('Secret is not valid base32.');
    }
    if (decoded.length < kMinSecretBytes) {
      throw FormatException(
          'Secret too short: ${decoded.length * 8} bits (minimum ${kMinSecretBytes * 8}).');
    }

    // TotpParams enforces digits/period bounds (rejects malicious URI values).
    final params =
        TotpParams(algorithm: algorithm, digits: digits, period: period);

    final id = _deriveId(issuer, label, normalized);
    return Account._(
      id: id,
      issuer: issuer.trim(),
      label: label.trim(),
      secretBase32: normalized,
      params: params,
    );
  }

  /// Strip spaces and ASCII grouping, uppercase, drop '=' padding (decode
  /// re-pads). Keeps only what could be base32.
  static String normalizeSecret(String raw) =>
      raw.replaceAll(RegExp(r'[\s-]'), '').replaceAll('=', '').toUpperCase();

  static String _deriveId(String issuer, String label, String secret) {
    final digest =
        sha256.convert(utf8.encode('${issuer.trim()}|${label.trim()}|$secret'));
    return digest.toString().substring(0, 16);
  }

  // --- Persistence (encrypted at rest by the secure store; never plaintext) ---

  Map<String, dynamic> toJson() => {
        'id': id,
        'issuer': issuer,
        'label': label,
        'secret': secretBase32,
        'algorithm': params.algorithm.wireName,
        'digits': params.digits,
        'period': params.period,
      };

  factory Account.fromJson(Map<String, dynamic> json) => Account.create(
        issuer: json['issuer'] as String? ?? '',
        label: json['label'] as String? ?? '',
        rawSecret: json['secret'] as String,
        algorithm: TotpAlgorithm.parse(json['algorithm'] as String?),
        digits: (json['digits'] as num?)?.toInt() ?? 6,
        period: (json['period'] as num?)?.toInt() ?? 30,
      );
}
