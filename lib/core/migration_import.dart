// AgnosticOTP — bulk import from other authenticators / browsers.
//
// Two input shapes:
//   1. otpauth-migration://offline?data=<base64>  — Google Authenticator's
//      "export accounts" QR (a protobuf MigrationPayload). Also emitted by
//      several compatible apps.
//   2. A text/file of newline-separated otpauth:// URIs — how most browser
//      password managers / 2FA extensions export.
//
// The protobuf is decoded by a tiny hand-rolled reader (no protobuf dependency
// in the security-critical path).
//
// CORRECTNESS: in a Google migration payload an UNSPECIFIED algorithm means
// SHA1 — that is the legacy default those secrets were enrolled under. We must
// preserve SHA1 here; coercing them to the app's SHA256 default would silently
// break every imported code. (This is the one place SHA1 is the import default,
// deliberately, and distinct from manual entry where SHA256 is default.)

import 'dart:convert';
import 'dart:typed_data';

import 'package:base32/base32.dart';

import '../data/account.dart';
import 'otpauth_uri.dart';
import 'totp.dart';

/// Outcome of an import: the accounts we could build, plus human-readable
/// reasons for anything skipped (HOTP, MD5, malformed) so the UI can report it.
class ImportResult {
  ImportResult(this.accounts, this.skipped);
  final List<Account> accounts;
  final List<String> skipped;

  int get importedCount => accounts.length;
  int get skippedCount => skipped.length;
}

/// Cap on the base64 `data=` payload of a migration QR — bounds the allocation
/// from a hostile/oversized file (pentest C-LOW-1). 64 KiB covers hundreds of
/// accounts; real exports are a few hundred bytes.
const int kMaxMigrationDataChars = 65536;

class AuthenticatorImport {
  AuthenticatorImport._();

  /// Detect and import from any supported text (a scanned QR's raw value, or a
  /// pasted/loaded file). Handles otpauth-migration://, otpauth://, and
  /// newline-separated lists of either.
  static ImportResult fromText(String text) {
    final accounts = <Account>[];
    final skipped = <String>[];
    final seenIds = <String>{};

    void add(Account a) {
      if (seenIds.add(a.id)) accounts.add(a);
    }

    for (final rawLine in text.split(RegExp(r'[\r\n]+'))) {
      final line = rawLine.trim();
      if (line.isEmpty) continue;
      if (line.startsWith('otpauth-migration://')) {
        // A malformed migration block must NOT abort the whole import (pentest
        // C-MED-2): record it and keep processing the remaining lines.
        try {
          final r = fromMigrationUri(line);
          for (final a in r.accounts) {
            add(a);
          }
          skipped.addAll(r.skipped);
        } on OtpauthParseException catch (e) {
          skipped.add('Skipped a migration block: ${e.message}');
        }
      } else if (line.startsWith('otpauth://')) {
        try {
          add(OtpauthUri.parseToAccount(line));
        } on OtpauthParseException catch (e) {
          skipped.add('Skipped a line: ${e.message}');
        }
      } else {
        skipped.add('Skipped unrecognised line.');
      }
    }
    return ImportResult(accounts, skipped);
  }

  /// Parse a single `otpauth-migration://offline?data=...` URI.
  static ImportResult fromMigrationUri(String uri) {
    final parsed = Uri.tryParse(uri);
    if (parsed == null ||
        parsed.scheme.toLowerCase() != 'otpauth-migration') {
      throw const OtpauthParseException('Not an otpauth-migration URI.');
    }
    final data = parsed.queryParameters['data'];
    if (data == null || data.isEmpty) {
      throw const OtpauthParseException('Migration QR has no data.');
    }
    if (data.length > kMaxMigrationDataChars) {
      throw const OtpauthParseException('Migration QR payload is too large.');
    }
    final bytes = _decodeBase64(data);
    return _parseMigrationPayload(bytes);
  }

  // --- MigrationPayload protobuf ---

  static ImportResult _parseMigrationPayload(Uint8List bytes) {
    final accounts = <Account>[];
    final skipped = <String>[];
    final r = _ProtoReader(bytes);

    while (!r.eof) {
      final (field, wire) = r.readTag();
      if (field == 1 && wire == 2) {
        // repeated OtpParameters
        final msg = r.readLengthDelimited();
        final acc = _parseOtpParameters(msg, skipped);
        if (acc != null) accounts.add(acc);
      } else {
        r.skip(wire);
      }
    }
    return ImportResult(accounts, skipped);
  }

  static Account? _parseOtpParameters(Uint8List bytes, List<String> skipped) {
    final r = _ProtoReader(bytes);
    Uint8List? secret;
    String name = '';
    String issuer = '';
    int algo = 0; // 0 unspecified -> SHA1 for migration (see note above)
    int digits = 0; // 0 unspecified -> 6
    int type = 0; // 0 unspecified, 1 HOTP, 2 TOTP

    while (!r.eof) {
      final (field, wire) = r.readTag();
      switch (field) {
        case 1 when wire == 2:
          secret = r.readLengthDelimited();
        case 2 when wire == 2:
          name = r.readString();
        case 3 when wire == 2:
          issuer = r.readString();
        case 4 when wire == 0:
          algo = r.readVarint();
        case 5 when wire == 0:
          digits = r.readVarint();
        case 6 when wire == 0:
          type = r.readVarint();
        default:
          r.skip(wire);
      }
    }

    if (secret == null || secret.isEmpty) {
      skipped.add('An entry had no secret.');
      return null;
    }
    if (type == 1) {
      skipped.add('Skipped "$name": counter-based (HOTP) is not supported.');
      return null;
    }

    final TotpAlgorithm algorithm;
    switch (algo) {
      case 2:
        algorithm = TotpAlgorithm.sha256;
      case 3:
        algorithm = TotpAlgorithm.sha512;
      case 0:
      case 1:
        algorithm = TotpAlgorithm.sha1; // legacy default for migrated secrets
      default:
        skipped.add('Skipped "$name": unsupported algorithm (e.g. MD5).');
        return null;
    }

    // Google's name field is conventionally "Issuer:label". Always take the
    // part after the first colon as the label; use the prefix as the issuer
    // only when the dedicated issuer field is absent.
    String label = name.trim();
    final colon = name.indexOf(':');
    if (colon >= 0) {
      if (issuer.isEmpty) issuer = name.substring(0, colon).trim();
      label = name.substring(colon + 1).trim();
    }

    try {
      return Account.create(
        issuer: issuer,
        label: label.isEmpty ? (issuer.isEmpty ? 'Imported' : issuer) : label,
        rawSecret: base32.encode(secret), // migration secret is raw bytes
        algorithm: algorithm,
        digits: digits == 2 ? 8 : 6,
        period: 30, // migration format carries no period; Google uses 30s
      );
    } on FormatException catch (e) {
      skipped.add('Skipped "$name": ${e.message}');
      return null;
    }
  }

  static Uint8List _decodeBase64(String data) {
    // The URI layer already %-decoded the value; it may still be standard or
    // url-safe base64, padded or not. Normalise both.
    var s = data.replaceAll('-', '+').replaceAll('_', '/');
    final pad = s.length % 4;
    if (pad != 0) s = s.padRight(s.length + (4 - pad), '=');
    try {
      return Uint8List.fromList(base64.decode(s));
    } catch (_) {
      throw const OtpauthParseException('Migration data is not valid base64.');
    }
  }
}

/// Minimal protobuf wire reader (varint + length-delimited only — all the
/// MigrationPayload schema uses).
class _ProtoReader {
  _ProtoReader(this._b);
  final Uint8List _b;
  int _i = 0;

  bool get eof => _i >= _b.length;

  int readVarint() {
    var result = 0;
    var shift = 0;
    while (true) {
      if (_i >= _b.length) {
        throw const OtpauthParseException('Truncated migration data.');
      }
      final byte = _b[_i++];
      result |= (byte & 0x7f) << shift;
      if (byte & 0x80 == 0) break;
      shift += 7;
      if (shift > 63) {
        throw const OtpauthParseException('Malformed varint.');
      }
    }
    return result;
  }

  (int, int) readTag() {
    final tag = readVarint();
    return (tag >> 3, tag & 0x07);
  }

  Uint8List readLengthDelimited() {
    final len = readVarint();
    // A length >= 2^63 wraps to a NEGATIVE Dart int (signed 64-bit). Reject it
    // up front: a negative `len` would slip past the truncation check below
    // (since _i + len < _i) and then make sublistView throw an uncaught
    // RangeError (pentest C-MED-1). Treat it as a controlled parse error.
    if (len < 0 || _i + len > _b.length) {
      throw const OtpauthParseException('Malformed migration field length.');
    }
    final out = Uint8List.sublistView(_b, _i, _i + len);
    _i += len;
    return out;
  }

  String readString() => String.fromCharCodes(readLengthDelimited());

  void skip(int wire) {
    switch (wire) {
      case 0:
        readVarint();
      case 2:
        readLengthDelimited();
      case 5:
        _i += 4; // fixed32
      case 1:
        _i += 8; // fixed64
      default:
        throw OtpauthParseException('Unsupported wire type $wire.');
    }
  }
}
