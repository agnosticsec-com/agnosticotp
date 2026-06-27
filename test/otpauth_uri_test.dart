// Enrolment-boundary tests: otpauth:// parsing, algorithm policy, base32
// validation, and hostile-QR rejection. Includes an end-to-end vector proving
// the base32 → key bytes → TOTP path matches RFC 6238.

import 'package:flutter_test/flutter_test.dart';
import 'package:agnosticotp/core/otpauth_uri.dart';
import 'package:agnosticotp/core/totp.dart';
import 'package:agnosticotp/data/account.dart';

// base32("12345678901234567890") — the RFC 6238 SHA1 seed.
const _rfcSeedB32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

DateTime _utc(int s) => DateTime.fromMillisecondsSinceEpoch(s * 1000, isUtc: true);

void main() {
  group('otpauth happy paths', () {
    test('full URI parses all fields', () {
      final a = OtpauthUri.parseToAccount(
          'otpauth://totp/ACME%20Co:alice@acme.com?secret=$_rfcSeedB32&issuer=ACME%20Co&algorithm=SHA256&digits=6&period=30');
      expect(a.issuer, 'ACME Co');
      expect(a.label, 'alice@acme.com');
      expect(a.algorithm, TotpAlgorithm.sha256);
      expect(a.params.digits, 6);
      expect(a.params.period, 30);
    });

    test('end-to-end: base32 secret → RFC6238 SHA1 vector', () {
      final a = OtpauthUri.parseToAccount(
          'otpauth://totp/Test?secret=$_rfcSeedB32&algorithm=SHA1&digits=8');
      final gen = TotpGenerator(a.params);
      expect(gen.code(a.keyBytes(), now: _utc(59)), '94287082');
    });

    test('issuer derived from "Issuer:label" path when query absent', () {
      final a = OtpauthUri.parseToAccount(
          'otpauth://totp/GitHub:octocat?secret=$_rfcSeedB32');
      expect(a.issuer, 'GitHub');
      expect(a.label, 'octocat');
    });
  });

  group('algorithm policy', () {
    test('omitted algorithm ⇒ SHA256 default', () {
      final a = OtpauthUri.parseToAccount(
          'otpauth://totp/X?secret=$_rfcSeedB32');
      expect(a.algorithm, TotpAlgorithm.sha256);
    });

    test('explicit SHA1 honoured for legacy', () {
      final a = OtpauthUri.parseToAccount(
          'otpauth://totp/X?secret=$_rfcSeedB32&algorithm=SHA1');
      expect(a.algorithm, TotpAlgorithm.sha1);
    });
  });

  group('hostile / malformed QR rejection', () {
    test('non-otpauth scheme', () {
      expect(() => OtpauthUri.parseToAccount('https://evil/x'),
          throwsA(isA<OtpauthParseException>()));
    });
    test('HOTP rejected', () {
      expect(
          () => OtpauthUri.parseToAccount(
              'otpauth://hotp/X?secret=$_rfcSeedB32&counter=0'),
          throwsA(isA<OtpauthParseException>()));
    });
    test('missing secret', () {
      expect(() => OtpauthUri.parseToAccount('otpauth://totp/X?issuer=Y'),
          throwsA(isA<OtpauthParseException>()));
    });
    test('oversized URI refused', () {
      final huge = 'otpauth://totp/X?secret=$_rfcSeedB32&issuer=${'A' * 2000}';
      expect(() => OtpauthUri.parseToAccount(huge),
          throwsA(isA<OtpauthParseException>()));
    });
    test('out-of-range digits refused', () {
      expect(
          () => OtpauthUri.parseToAccount(
              'otpauth://totp/X?secret=$_rfcSeedB32&digits=99'),
          throwsA(isA<OtpauthParseException>()));
    });
    test('non-numeric period refused', () {
      expect(
          () => OtpauthUri.parseToAccount(
              'otpauth://totp/X?secret=$_rfcSeedB32&period=abc'),
          throwsA(isA<OtpauthParseException>()));
    });
    test('non-base32 secret refused', () {
      expect(
          () => OtpauthUri.parseToAccount('otpauth://totp/X?secret=1810!!!'),
          throwsA(isA<OtpauthParseException>()));
    });
    test('too-short secret refused', () {
      // "AAAA" decodes to < 80 bits.
      expect(() => OtpauthUri.parseToAccount('otpauth://totp/X?secret=AAAA'),
          throwsA(isA<OtpauthParseException>()));
    });
  });

  group('account model', () {
    test('normalises spaced/lowercase secret', () {
      final a = Account.create(
          issuer: 'I', label: 'L', rawSecret: 'gezd gnbv gy3t qojq gezd gnbv gy3t qojq');
      expect(a.secretBase32, _rfcSeedB32);
    });
    test('json round-trips', () {
      final a = Account.create(
          issuer: 'I', label: 'L', rawSecret: _rfcSeedB32, algorithm: TotpAlgorithm.sha1);
      final b = Account.fromJson(a.toJson());
      expect(b.id, a.id);
      expect(b.algorithm, TotpAlgorithm.sha1);
      expect(b.secretBase32, a.secretBase32);
    });
    test('stable id dedupes identical credential', () {
      final a = Account.create(issuer: 'I', label: 'L', rawSecret: _rfcSeedB32);
      final b = Account.create(issuer: 'I', label: 'L', rawSecret: _rfcSeedB32);
      expect(a.id, b.id);
    });
  });
}
