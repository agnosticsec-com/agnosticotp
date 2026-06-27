// Full-flow integration test. Runs on a real device/emulator:
//   flutter test integration_test/app_test.dart
//
// A live biometric prompt can't be automated, so we inject an in-memory
// [Vault] (FakeVault) that satisfies the same contract as the real
// biometric-bound SecureVault. This exercises the entire UI + state path —
// lock → unlock → enrol (manual) → live code renders → delete → re-lock —
// without a fingerprint. The crypto/storage layer is covered by the unit
// suites (totp_test, otpauth_uri_test) and the C1 native audit.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

import 'package:agnosticotp/data/account.dart';
import 'package:agnosticotp/data/secure_store.dart';
import 'package:agnosticotp/main.dart';

/// In-memory stand-in for SecureVault — no biometric, no platform channels.
class FakeVault implements Vault {
  final List<Account> _store = [];

  @override
  Future<VaultAvailability> availability() async => VaultAvailability.ready;

  @override
  Future<List<Account>> unlockAndLoad() async => List.of(_store);

  @override
  Future<void> save(List<Account> accounts) async {
    _store
      ..clear()
      ..addAll(accounts);
  }

  @override
  Future<void> wipe() async => _store.clear();
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  // base32("12345678901234567890") — RFC 6238 SHA1 seed.
  const rfcSeedB32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

  testWidgets('lock → unlock → enrol → live code → delete', (tester) async {
    await tester.pumpWidget(AgnosticOtpApp(vault: FakeVault()));
    await tester.pumpAndSettle();

    // 1. Starts locked.
    expect(find.text('Unlock with biometrics'), findsOneWidget);

    // 2. Unlock (fake vault returns immediately) → empty state.
    await tester.tap(find.text('Unlock with biometrics'));
    await tester.pumpAndSettle();
    expect(find.text('No accounts yet'), findsOneWidget);

    // 3. Add → manual entry.
    await tester.tap(find.text('Add'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Enter secret manually'));
    await tester.pumpAndSettle();

    await tester.enterText(
        find.widgetWithText(TextFormField, 'Issuer (service name)'), 'ACME');
    await tester.enterText(
        find.widgetWithText(TextFormField, 'Account'), 'alice@acme.com');
    await tester.enterText(
        find.widgetWithText(TextFormField, 'Secret (base32)'), rfcSeedB32);
    await tester.tap(find.text('Add account'));
    await tester.pumpAndSettle();

    // 4. Account appears with a live 6-digit code (default SHA256) + badge.
    expect(find.text('ACME'), findsOneWidget);
    expect(find.text('SHA256'), findsOneWidget);
    expect(find.byWidgetPredicate((w) {
      if (w is Text && w.data != null) {
        return RegExp(r'^\d{3} \d{3}$').hasMatch(w.data!);
      }
      return false;
    }), findsOneWidget);

    // 5. Delete it.
    await tester.tap(find.byIcon(Icons.delete_outline));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Remove'));
    await tester.pumpAndSettle();
    expect(find.text('No accounts yet'), findsOneWidget);

    // 6. Manual lock returns to the lock screen.
    await tester.tap(find.byIcon(Icons.lock_outline));
    await tester.pumpAndSettle();
    expect(find.text('Unlock with biometrics'), findsOneWidget);
  });
}
