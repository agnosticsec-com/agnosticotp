// RFC 6238 Appendix B known-answer tests — the correctness gate for the TOTP
// core. Algorithm mismatch fails SILENTLY (valid-looking codes that never
// verify), so these vectors are the guard that SHA1/SHA256/SHA512 are each
// wired correctly and that SHA256 is honoured as the default.
//
// Seeds (RFC 6238 Appendix B): the ASCII string "12345678901234567890"
// truncated/extended to the block size of each hash.

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:agnosticotp/core/totp.dart';

Uint8List _seed(int lengthBytes) {
  const base = '1234567890';
  final sb = StringBuffer();
  while (sb.length < lengthBytes) {
    sb.write(base);
  }
  return Uint8List.fromList(utf8.encode(sb.toString().substring(0, lengthBytes)));
}

final _seedSha1 = _seed(20); // 160-bit
final _seedSha256 = _seed(32); // 256-bit
final _seedSha512 = _seed(64); // 512-bit

DateTime _utc(int epochSeconds) =>
    DateTime.fromMillisecondsSinceEpoch(epochSeconds * 1000, isUtc: true);

void main() {
  group('RFC 6238 Appendix B known-answer vectors (8 digits, period 30)', () {
    // time → expected code, per algorithm.
    const sha1 = {
      59: '94287082',
      1111111109: '07081804',
      1111111111: '14050471',
      1234567890: '89005924',
      2000000000: '69279037',
      20000000000: '65353130',
    };
    const sha256 = {
      59: '46119246',
      1111111109: '68084774',
      1111111111: '67062674',
      1234567890: '91819424',
      2000000000: '90698825',
      20000000000: '77737706',
    };
    const sha512 = {
      59: '90693936',
      1111111109: '25091201',
      1111111111: '99943326',
      1234567890: '93441116',
      2000000000: '38618901',
      20000000000: '47863826',
    };

    void runVectors(
        TotpAlgorithm algo, Uint8List seed, Map<int, String> vectors) {
      final gen = TotpGenerator(
          TotpParams(algorithm: algo, digits: 8, period: 30));
      vectors.forEach((t, expected) {
        test('${algo.wireName} @ t=$t → $expected', () {
          expect(gen.code(seed, now: _utc(t)), expected);
        });
      });
    }

    runVectors(TotpAlgorithm.sha1, _seedSha1, sha1);
    runVectors(TotpAlgorithm.sha256, _seedSha256, sha256);
    runVectors(TotpAlgorithm.sha512, _seedSha512, sha512);
  });

  group('Algorithm policy (SHA256 default, SHA1 legacy)', () {
    test('omitted algorithm defaults to SHA256', () {
      expect(TotpAlgorithm.parse(null), TotpAlgorithm.sha256);
      expect(TotpAlgorithm.parse(''), TotpAlgorithm.sha256);
      expect(TotpAlgorithm.parse('bogus'), TotpAlgorithm.sha256);
      expect(TotpAlgorithm.defaultAlgorithm, TotpAlgorithm.sha256);
    });

    test('explicit legacy algorithms are honoured, case-insensitively', () {
      expect(TotpAlgorithm.parse('SHA1'), TotpAlgorithm.sha1);
      expect(TotpAlgorithm.parse('sha1'), TotpAlgorithm.sha1);
      expect(TotpAlgorithm.parse(' SHA512 '), TotpAlgorithm.sha512);
    });
  });

  group('Default 6-digit code shape', () {
    test('produces a zero-padded 6-digit string', () {
      final gen = TotpGenerator(TotpParams()); // SHA256, 6 digits, 30s
      final code = gen.code(_seedSha256, now: _utc(59));
      expect(code, matches(RegExp(r'^\d{6}$')));
    });
  });

  group('Parameter bounds reject malicious otpauth values', () {
    test('digits out of range throws', () {
      expect(() => TotpParams(digits: 4), throwsArgumentError);
      expect(() => TotpParams(digits: 99), throwsArgumentError);
    });
    test('period out of range throws', () {
      expect(() => TotpParams(period: 0), throwsArgumentError);
      expect(() => TotpParams(period: 99999), throwsArgumentError);
    });
  });

  group('Countdown', () {
    test('secondsRemaining is within (0, period]', () {
      final gen = TotpGenerator(TotpParams(period: 30));
      final r = gen.secondsRemaining(now: _utc(1111111109));
      expect(r, greaterThan(0));
      expect(r, lessThanOrEqualTo(30));
      // t=1111111109 → 1111111109 % 30 = 29 → remaining 1
      expect(r, 1);
    });
  });
}
