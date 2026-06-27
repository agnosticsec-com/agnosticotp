// AgnosticOTP — encrypted backup codec.
//
// Produces a self-describing, passphrase-encrypted envelope of the vault so the
// user can store it on ANY cloud (iCloud/Drive/Proton/Dropbox/Files) via the OS
// document picker. The app itself never touches the network — it only emits and
// reads ciphertext; the user's cloud app does the upload. Zero-knowledge: the
// cloud only ever sees this opaque blob.
//
// Crypto: passphrase -> KDF -> 256-bit key -> AES-256-GCM(vault JSON).
// The KDF is the USER'S CHOICE and is recorded (with its parameters) in the
// envelope header, so restore auto-detects it:
//   - PBKDF2-HMAC-SHA256 (600k iters) — FIPS 140-approved; pick this for a
//     FIPS/FedRAMP posture.
//   - Argon2id (RFC 9106, OWASP params) — memory-hard, far stronger against
//     GPU/ASIC cracking; not FIPS-approved.
//
// This module is a pure codec over String plaintext, decoupled from the account
// model, so it can be tested in isolation.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

enum BackupKdf {
  pbkdf2('pbkdf2-hmac-sha256'),
  argon2id('argon2id');

  const BackupKdf(this.wire);
  final String wire;

  static BackupKdf fromWire(String s) =>
      values.firstWhere((k) => k.wire == s,
          orElse: () => throw const BackupFormatException('Unknown KDF.'));

  /// The KDF is presented to the user as a USAGE question, not a crypto choice:
  /// "Is this backup work-related (and so needs FIPS-approved crypto)?"
  ///   - work-related  -> PBKDF2-HMAC-SHA256 (FIPS 140-approved)
  ///   - personal      -> Argon2id (the default; stronger against cracking)
  static BackupKdf forUsage({required bool workRelated}) =>
      workRelated ? BackupKdf.pbkdf2 : BackupKdf.argon2id;

  /// Default when the user makes no explicit choice.
  static const BackupKdf defaultKdf = BackupKdf.argon2id;
}

// --- Tuned parameters (OWASP / FIPS guidance) ---
const int _kKeyBytes = 32; // 256-bit AES key
const int _kSaltBytes = 16;
const int _kPbkdf2Iterations = 600000; // OWASP 2023, PBKDF2-HMAC-SHA256
const int _kArgonMemoryKiB = 19456; // 19 MiB (OWASP mobile-friendly)
const int _kArgonIterations = 2;
const int _kArgonParallelism = 1;

const String _kFormat = 'AgnosticOTP-backup';
const int _kVersion = 1;

/// Backstop against a trivially-weak USER-TYPED passphrase (pentest B-HIGH-1).
/// The recommended path is the generated Recovery Key (~128 bits); this only
/// rejects the obviously-broken cases (too short / too repetitive). It is NOT a
/// substitute for generating the passphrase.
const int _kMinPassphraseLength = 12;
const int _kMinPassphraseDistinct = 6;

class BackupFormatException implements Exception {
  const BackupFormatException(this.message);
  final String message;
  @override
  String toString() => 'BackupFormatException: $message';
}

/// Thrown when decryption fails — wrong passphrase OR a tampered/corrupt file
/// (AES-GCM authentication failure). Deliberately indistinguishable.
class BackupDecryptException implements Exception {
  const BackupDecryptException();
  @override
  String toString() => 'BackupDecryptException: wrong passphrase or corrupt backup';
}

class BackupCodec {
  BackupCodec._();

  static final Random _rng = Random.secure();

  static Uint8List _randomBytes(int n) {
    final b = Uint8List(n);
    for (var i = 0; i < n; i++) {
      b[i] = _rng.nextInt(256);
    }
    return b;
  }

  static KdfAlgorithm _kdfFor(BackupKdf kdf) {
    switch (kdf) {
      case BackupKdf.pbkdf2:
        return Pbkdf2(
          macAlgorithm: Hmac.sha256(),
          iterations: _kPbkdf2Iterations,
          bits: _kKeyBytes * 8,
        );
      case BackupKdf.argon2id:
        return Argon2id(
          memory: _kArgonMemoryKiB,
          parallelism: _kArgonParallelism,
          iterations: _kArgonIterations,
          hashLength: _kKeyBytes,
        );
    }
  }

  static Map<String, dynamic> _kdfParams(BackupKdf kdf) {
    switch (kdf) {
      case BackupKdf.pbkdf2:
        return {'iterations': _kPbkdf2Iterations, 'hash': 'sha256'};
      case BackupKdf.argon2id:
        return {
          'memoryKiB': _kArgonMemoryKiB,
          'iterations': _kArgonIterations,
          'parallelism': _kArgonParallelism,
        };
    }
  }

  /// Encrypt [plaintext] under [passphrase] using the chosen [kdf].
  /// Returns a JSON envelope string safe to write to a file / cloud.
  static Future<String> encrypt({
    required String plaintext,
    required String passphrase,
    BackupKdf kdf = BackupKdf.argon2id, // personal default; work => PBKDF2
  }) async {
    if (passphrase.length < _kMinPassphraseLength ||
        passphrase.runes.toSet().length < _kMinPassphraseDistinct) {
      throw const BackupFormatException(
          'Passphrase too weak. Use the generated Recovery Key, or at least '
          '12 characters with real variety.');
    }
    final salt = _randomBytes(_kSaltBytes);
    final key = await _kdfFor(kdf).deriveKeyFromPassword(
      password: passphrase,
      nonce: salt,
    );

    final aes = AesGcm.with256bits();
    final nonce = aes.newNonce();
    // Bind the (plaintext) header to the ciphertext as AAD so tampering with
    // kdf/salt/nonce is detected by the GCM tag, not silently tolerated
    // (pentest B-MED-1). The KDF determines its own params, so binding the kdf
    // wire name covers kdfParams too.
    final aad = _headerAad(
      kdfWire: kdf.wire,
      saltB64: base64.encode(salt),
      nonceB64: base64.encode(nonce),
    );
    final box = await aes.encrypt(
      utf8.encode(plaintext),
      secretKey: key,
      nonce: nonce,
      aad: aad,
    );

    final envelope = {
      'format': _kFormat,
      'version': _kVersion,
      'kdf': kdf.wire,
      'kdfParams': _kdfParams(kdf),
      'cipher': 'aes-256-gcm',
      'salt': base64.encode(salt),
      'nonce': base64.encode(box.nonce),
      'ciphertext': base64.encode(box.cipherText),
      'tag': base64.encode(box.mac.bytes),
    };
    return const JsonEncoder.withIndent('  ').convert(envelope);
  }

  /// Decrypt an envelope produced by [encrypt]. Throws [BackupDecryptException]
  /// on a wrong passphrase or any tampering; [BackupFormatException] if the
  /// file is not a recognisable AgnosticOTP backup.
  static Future<String> decrypt({
    required String envelopeJson,
    required String passphrase,
  }) async {
    final Map<String, dynamic> env;
    try {
      env = jsonDecode(envelopeJson) as Map<String, dynamic>;
    } catch (_) {
      throw const BackupFormatException('Not a valid backup file.');
    }
    if (env['format'] != _kFormat) {
      throw const BackupFormatException('Not an AgnosticOTP backup.');
    }
    if (env['version'] != _kVersion) {
      throw BackupFormatException('Unsupported backup version: ${env['version']}.');
    }
    if (env['cipher'] != 'aes-256-gcm') {
      throw BackupFormatException('Unsupported cipher: ${env['cipher']}.');
    }

    // Every field is validated as a String before use so a hostile/corrupt
    // file raises a clean BackupFormatException instead of a TypeError crash
    // (pentest B-MED-2).
    final kdfWire = _requireString(env, 'kdf');
    final saltB64 = _requireString(env, 'salt');
    final nonceB64 = _requireString(env, 'nonce');
    final kdf = BackupKdf.fromWire(kdfWire);
    final salt = _decodeB64(env, 'salt', saltB64);
    final nonce = _decodeB64(env, 'nonce', nonceB64);
    final cipherText = _decodeB64(env, 'ciphertext', _requireString(env, 'ciphertext'));
    final tag = _decodeB64(env, 'tag', _requireString(env, 'tag'));

    final key =
        await _kdfFor(kdf).deriveKeyFromPassword(password: passphrase, nonce: salt);

    // Reconstruct the AAD from the header; if any bound field was altered the
    // GCM tag check fails (B-MED-1).
    final aad =
        _headerAad(kdfWire: kdfWire, saltB64: saltB64, nonceB64: nonceB64);
    final aes = AesGcm.with256bits();
    try {
      final clear = await aes.decrypt(
        SecretBox(cipherText, nonce: nonce, mac: Mac(tag)),
        secretKey: key,
        aad: aad,
      );
      return utf8.decode(clear);
    } on SecretBoxAuthenticationError {
      throw const BackupDecryptException();
    }
  }

  /// Canonical AAD over the integrity-relevant header fields (fixed order).
  static List<int> _headerAad({
    required String kdfWire,
    required String saltB64,
    required String nonceB64,
  }) =>
      utf8.encode('$_kFormat|$_kVersion|aes-256-gcm|$kdfWire|$saltB64|$nonceB64');

  static String _requireString(Map<String, dynamic> env, String key) {
    final v = env[key];
    if (v is! String) {
      throw BackupFormatException('Backup field "$key" is missing or malformed.');
    }
    return v;
  }

  static Uint8List _decodeB64(Map<String, dynamic> env, String key, String value) {
    try {
      return base64.decode(value);
    } on FormatException {
      throw BackupFormatException('Backup field "$key" is not valid base64.');
    }
  }

  /// Peek the KDF a backup uses without decrypting (for UI display).
  static BackupKdf kdfOf(String envelopeJson) {
    try {
      final env = jsonDecode(envelopeJson) as Map<String, dynamic>;
      return BackupKdf.fromWire(env['kdf'] as String);
    } catch (e) {
      if (e is BackupFormatException) rethrow;
      throw const BackupFormatException('Not a valid backup file.');
    }
  }
}
