import 'package:flutter/material.dart';

import '../core/totp.dart';
import '../data/account.dart';

/// Manual secret entry — the fallback when there's no QR. The algorithm
/// defaults to SHA256; the user only drops to SHA1 for an explicitly legacy
/// service. Validation happens via [Account.create], so a bad base32 / weak
/// secret is rejected here, not at code-gen time.
class ManualEntryPage extends StatefulWidget {
  const ManualEntryPage({super.key});

  @override
  State<ManualEntryPage> createState() => _ManualEntryPageState();
}

class _ManualEntryPageState extends State<ManualEntryPage> {
  final _formKey = GlobalKey<FormState>();
  final _issuer = TextEditingController();
  final _label = TextEditingController();
  final _secret = TextEditingController();

  TotpAlgorithm _algorithm = TotpAlgorithm.sha256; // default
  int _digits = 6;
  int _period = 30;
  String? _secretError;

  @override
  void dispose() {
    _issuer.dispose();
    _label.dispose();
    _secret.dispose();
    super.dispose();
  }

  void _save() {
    setState(() => _secretError = null);
    if (!_formKey.currentState!.validate()) return;
    try {
      final account = Account.create(
        issuer: _issuer.text,
        label: _label.text,
        rawSecret: _secret.text,
        algorithm: _algorithm,
        digits: _digits,
        period: _period,
      );
      Navigator.of(context).pop<Account>(account);
    } on FormatException catch (e) {
      setState(() => _secretError = e.message);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Enter secret')),
      body: Form(
        key: _formKey,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            TextFormField(
              controller: _issuer,
              decoration: const InputDecoration(
                labelText: 'Issuer (service name)',
                hintText: 'e.g. GitHub',
              ),
            ),
            const SizedBox(height: 12),
            TextFormField(
              controller: _label,
              decoration: const InputDecoration(
                labelText: 'Account',
                hintText: 'e.g. you@example.com',
              ),
            ),
            const SizedBox(height: 12),
            TextFormField(
              controller: _secret,
              autocorrect: false,
              enableSuggestions: false,
              decoration: InputDecoration(
                labelText: 'Secret (base32)',
                hintText: 'JBSWY3DPEHPK3PXP',
                errorText: _secretError,
              ),
              validator: (v) =>
                  (v == null || v.trim().isEmpty) ? 'Required' : null,
            ),
            const SizedBox(height: 24),
            DropdownButtonFormField<TotpAlgorithm>(
              initialValue: _algorithm,
              decoration: const InputDecoration(labelText: 'Algorithm'),
              items: TotpAlgorithm.values
                  .map((a) => DropdownMenuItem(
                        value: a,
                        child: Text(a == TotpAlgorithm.sha256
                            ? '${a.wireName} (default)'
                            : a == TotpAlgorithm.sha1
                                ? '${a.wireName} (legacy)'
                                : a.wireName),
                      ))
                  .toList(),
              onChanged: (a) => setState(() => _algorithm = a ?? _algorithm),
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: DropdownButtonFormField<int>(
                    initialValue: _digits,
                    decoration: const InputDecoration(labelText: 'Digits'),
                    items: const [6, 7, 8]
                        .map((d) =>
                            DropdownMenuItem(value: d, child: Text('$d')))
                        .toList(),
                    onChanged: (d) => setState(() => _digits = d ?? _digits),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: DropdownButtonFormField<int>(
                    initialValue: _period,
                    decoration:
                        const InputDecoration(labelText: 'Period (s)'),
                    items: const [30, 60]
                        .map((p) =>
                            DropdownMenuItem(value: p, child: Text('$p')))
                        .toList(),
                    onChanged: (p) => setState(() => _period = p ?? _period),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 24),
            FilledButton(onPressed: _save, child: const Text('Add account')),
          ],
        ),
      ),
    );
  }
}
