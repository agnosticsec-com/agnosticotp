// Smoke test: the app boots to the lock screen (no biometric prompt until the
// user taps Unlock). Full UI flows need an integration test with a device.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:agnosticotp/app_state.dart';
import 'package:agnosticotp/ui/lock_screen.dart';

void main() {
  testWidgets('lock screen shows the unlock affordance', (tester) async {
    final state = AppState();
    await tester.pumpWidget(MaterialApp(home: LockScreen(state: state)));
    expect(find.text('AgnosticOTP'), findsOneWidget);
    expect(find.text('Unlock with biometrics'), findsOneWidget);
  });
}
