import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../core/otpauth_uri.dart';
import '../data/account.dart';

/// Add an account by pasting a full `otpauth://` URI — the same string a QR
/// code encodes. This is the path for when there is no camera (desktop /
/// emulator) or when a service shows the enrolment link as text rather than a
/// QR.
///
/// The pasted string is ATTACKER-CONTROLLED and goes through exactly the same
/// trust boundary as the scanner: [OtpauthUri.parseToAccount] bounds every
/// field, rejects HOTP / oversized / malformed / non-otpauth input, and hands
/// the secret to [Account.create] for re-validation. Algorithm, digits and
/// period are read from the URI (so SHA512 / 8-digit enrolments come across
/// intact), never guessed.
class PasteOtpauthPage extends StatefulWidget {
  const PasteOtpauthPage({super.key});

  @override
  State<PasteOtpauthPage> createState() => _PasteOtpauthPageState();
}

class _PasteOtpauthPageState extends State<PasteOtpauthPage> {
  final _controller = TextEditingController();
  String? _error;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Future<void> _pasteFromClipboard() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    final text = data?.text?.trim() ?? '';
    if (!mounted) return;
    setState(() {
      if (text.isEmpty) {
        _error = 'Clipboard is empty.';
      } else {
        _controller.text = text;
        _error = null;
      }
    });
  }

  void _add() {
    final raw = _controller.text.trim();
    if (raw.isEmpty) {
      setState(() => _error = 'Paste an otpauth:// link first.');
      return;
    }
    try {
      final account = OtpauthUri.parseToAccount(raw);
      Navigator.of(context).pop<Account>(account);
    } on OtpauthParseException catch (e) {
      // Show one consistent "bad link" surface; the parser never echoes the
      // secret back in its message.
      setState(() => _error = e.message);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Paste otpauth:// link')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Text(
            'Paste the full otpauth:// link — the same value a QR code carries. '
            'The algorithm, digits and period are read from the link.',
            style: Theme.of(context).textTheme.bodyMedium,
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _controller,
            autocorrect: false,
            enableSuggestions: false,
            minLines: 3,
            maxLines: 6,
            keyboardType: TextInputType.multiline,
            decoration: InputDecoration(
              labelText: 'otpauth:// link',
              hintText:
                  'otpauth://totp/Issuer:account?secret=...&algorithm=SHA512&digits=8',
              errorText: _error,
              border: const OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 12),
          OutlinedButton.icon(
            onPressed: _pasteFromClipboard,
            icon: const Icon(Icons.content_paste),
            label: const Text('Paste from clipboard'),
          ),
          const SizedBox(height: 24),
          FilledButton(onPressed: _add, child: const Text('Add account')),
        ],
      ),
    );
  }
}
