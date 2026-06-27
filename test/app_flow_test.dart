// Headless widget-level run of the full app flow (lock → unlock → enrol →
// live code → delete → re-lock), using the in-memory FakeVault. Mirrors
// integration_test/app_test.dart but runs under `flutter test` with no device,
// so the flow is exercised on every CI/local run. The on-device integration
// test additionally validates real platform plugins.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:agnosticotp/data/account.dart';
import 'package:agnosticotp/data/secure_store.dart';
import 'package:agnosticotp/main.dart';

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
  const rfcSeedB32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

  testWidgets('full flow: lock → unlock → enrol → live code → delete',
      (tester) async {
    await tester.pumpWidget(AgnosticOtpApp(vault: FakeVault()));
    await tester.pumpAndSettle();

    expect(find.text('Unlock with biometrics'), findsOneWidget);

    await tester.tap(find.text('Unlock with biometrics'));
    await tester.pumpAndSettle();
    expect(find.text('No accounts yet'), findsOneWidget);

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

    expect(find.text('ACME'), findsOneWidget);
    expect(find.text('SHA256'), findsOneWidget); // default algorithm
    expect(
        find.byWidgetPredicate((w) =>
            w is Text &&
            w.data != null &&
            RegExp(r'^\d{3} \d{3}$').hasMatch(w.data!)),
        findsOneWidget); // live 6-digit code

    await tester.tap(find.byIcon(Icons.delete_outline));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Remove'));
    await tester.pumpAndSettle();
    expect(find.text('No accounts yet'), findsOneWidget);

    await tester.tap(find.byIcon(Icons.lock_outline));
    await tester.pumpAndSettle();
    expect(find.text('Unlock with biometrics'), findsOneWidget);
  });
}
