// Widget tests for the "Paste otpauth:// link" enrolment path. Proves the page
// routes a pasted URI through the same OtpauthUri trust boundary and returns a
// validated Account (with algorithm/digits/period read from the link), and that
// a hostile / malformed link is rejected in-place with an error, not popped.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:agnosticotp/core/totp.dart';
import 'package:agnosticotp/data/account.dart';
import 'package:agnosticotp/ui/paste_otpauth_page.dart';

// base32("12345678901234567890") — the RFC 6238 seed (a valid, strong secret).
const _seed = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

void main() {
  testWidgets('valid otpauth:// link returns an Account with its fields',
      (tester) async {
    Account? captured;
    await tester.pumpWidget(MaterialApp(
      home: Builder(
        builder: (context) => Scaffold(
          body: Center(
            child: ElevatedButton(
              onPressed: () async {
                captured = await Navigator.push<Account>(
                  context,
                  MaterialPageRoute(builder: (_) => const PasteOtpauthPage()),
                );
              },
              child: const Text('open'),
            ),
          ),
        ),
      ),
    ));
    await tester.tap(find.text('open'));
    await tester.pumpAndSettle();

    await tester.enterText(
      find.byType(TextField),
      'otpauth://totp/Yashigani:orca?secret=$_seed&issuer=Yashigani'
          '&algorithm=SHA512&digits=8&period=30',
    );
    await tester.tap(find.text('Add account'));
    await tester.pumpAndSettle();

    expect(captured, isNotNull);
    expect(captured!.issuer, 'Yashigani');
    expect(captured!.label, 'orca');
    expect(captured!.algorithm, TotpAlgorithm.sha512);
    expect(captured!.params.digits, 8);
    expect(captured!.params.period, 30);
  });

  testWidgets('malformed link shows an error and does not pop', (tester) async {
    var popped = false;
    await tester.pumpWidget(MaterialApp(
      home: Builder(
        builder: (context) => Scaffold(
          body: Center(
            child: ElevatedButton(
              onPressed: () async {
                await Navigator.push<Account>(
                  context,
                  MaterialPageRoute(builder: (_) => const PasteOtpauthPage()),
                );
                popped = true;
              },
              child: const Text('open'),
            ),
          ),
        ),
      ),
    ));
    await tester.tap(find.text('open'));
    await tester.pumpAndSettle();

    await tester.enterText(find.byType(TextField), 'https://evil.example/x');
    await tester.tap(find.text('Add account'));
    await tester.pumpAndSettle();

    // Still on the paste page, an error is shown, nothing was returned.
    expect(popped, isFalse);
    expect(find.text('Add account'), findsOneWidget);
    expect(find.textContaining('otpauth'), findsWidgets);
  });

  testWidgets('empty input is rejected in-place', (tester) async {
    await tester.pumpWidget(const MaterialApp(home: PasteOtpauthPage()));
    await tester.tap(find.text('Add account'));
    await tester.pumpAndSettle();
    expect(find.text('Paste an otpauth:// link first.'), findsOneWidget);
  });
}
