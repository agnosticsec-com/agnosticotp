// Encrypted-backup codec tests: round-trip under both KDFs, the work/personal
// usage mapping, and the security properties (wrong passphrase & tamper both
// rejected, indistinguishably).

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:agnosticotp/data/backup.dart';

void main() {
  const vaultJson =
      '[{"id":"abc","issuer":"ACME","label":"a@x","secret":"GEZDGNBVGY3TQOJQ","algorithm":"SHA256","digits":6,"period":30}]';

  group('usage → KDF policy', () {
    test('work-related selects PBKDF2 (FIPS)', () {
      expect(BackupKdf.forUsage(workRelated: true), BackupKdf.pbkdf2);
    });
    test('personal selects Argon2id (default)', () {
      expect(BackupKdf.forUsage(workRelated: false), BackupKdf.argon2id);
      expect(BackupKdf.defaultKdf, BackupKdf.argon2id);
    });
  });

  group('round-trip', () {
    test('Argon2id (personal default)', () async {
      final env = await BackupCodec.encrypt(
          plaintext: vaultJson, passphrase: 'correct horse battery staple');
      expect(BackupCodec.kdfOf(env), BackupKdf.argon2id); // default
      final out = await BackupCodec.decrypt(
          envelopeJson: env, passphrase: 'correct horse battery staple');
      expect(out, vaultJson);
    });

    test('PBKDF2 (work)', () async {
      final env = await BackupCodec.encrypt(
          plaintext: vaultJson,
          passphrase: 'work-laptop-backup-2026',
          kdf: BackupKdf.forUsage(workRelated: true));
      expect(BackupCodec.kdfOf(env), BackupKdf.pbkdf2);
      // header records the FIPS KDF + params
      final header = jsonDecode(env) as Map<String, dynamic>;
      expect(header['kdf'], 'pbkdf2-hmac-sha256');
      expect(header['cipher'], 'aes-256-gcm');
      final out = await BackupCodec.decrypt(
          envelopeJson: env, passphrase: 'work-laptop-backup-2026');
      expect(out, vaultJson);
    });
  });

  group('security properties', () {
    test('wrong passphrase is rejected', () async {
      final env = await BackupCodec.encrypt(
          plaintext: vaultJson, passphrase: 'right-recovery-key-01', kdf: BackupKdf.pbkdf2);
      expect(
        () => BackupCodec.decrypt(envelopeJson: env, passphrase: 'wrong'),
        throwsA(isA<BackupDecryptException>()),
      );
    });

    test('tampered ciphertext is rejected (GCM auth)', () async {
      final env = await BackupCodec.encrypt(
          plaintext: vaultJson, passphrase: 'tamper-test-pass-9x', kdf: BackupKdf.pbkdf2);
      final m = jsonDecode(env) as Map<String, dynamic>;
      final ct = base64.decode(m['ciphertext'] as String);
      ct[0] ^= 0xFF; // flip a byte
      m['ciphertext'] = base64.encode(ct);
      expect(
        () => BackupCodec.decrypt(
            envelopeJson: jsonEncode(m), passphrase: 'tamper-test-pass-9x'),
        throwsA(isA<BackupDecryptException>()),
      );
    });

    test('weak passphrase refused at encrypt (B-HIGH-1)', () async {
      // empty, single char, too short, and no-variety must all be rejected.
      for (final weak in ['', 'a', 'short', 'aaaaaaaaaaaa']) {
        expect(
          () => BackupCodec.encrypt(plaintext: vaultJson, passphrase: weak),
          throwsA(isA<BackupFormatException>()),
          reason: 'should reject "$weak"',
        );
      }
    });

    test('non-backup input refused', () async {
      expect(
        () => BackupCodec.decrypt(envelopeJson: '{"hello":1}', passphrase: 'x'),
        throwsA(isA<BackupFormatException>()),
      );
    });

    test('header tampering is rejected via AAD (B-MED-1)', () async {
      final env = await BackupCodec.encrypt(
          plaintext: vaultJson,
          passphrase: 'header-tamper-test-1',
          kdf: BackupKdf.pbkdf2);
      final m = jsonDecode(env) as Map<String, dynamic>;
      // alter a bound header field to another valid 12-byte base64 nonce
      m['nonce'] = base64.encode(List<int>.filled(12, 7));
      expect(
        () => BackupCodec.decrypt(
            envelopeJson: jsonEncode(m), passphrase: 'header-tamper-test-1'),
        throwsA(isA<BackupDecryptException>()),
      );
    });

    test('hostile field types raise a clean error, not a crash (B-MED-2)',
        () async {
      final env = await BackupCodec.encrypt(
          plaintext: vaultJson,
          passphrase: 'type-guard-test-12',
          kdf: BackupKdf.pbkdf2);
      final base = jsonDecode(env) as Map<String, dynamic>;
      final mutations = <Map<String, dynamic> Function(Map<String, dynamic>)>[
        (m) => m..['salt'] = 12345, // number, not string
        (m) => m..remove('tag'), // missing field
        (m) => m..['nonce'] = '!!!not-base64!!!', // invalid base64
      ];
      for (final mutate in mutations) {
        final m = mutate(Map<String, dynamic>.from(base));
        expect(
          () => BackupCodec.decrypt(
              envelopeJson: jsonEncode(m), passphrase: 'type-guard-test-12'),
          throwsA(isA<BackupFormatException>()),
        );
      }
    });
  });
}
