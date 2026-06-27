import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';
import 'package:share_plus/share_plus.dart';

import '../app_state.dart';
import '../data/backup.dart';
import '../data/passphrase.dart';

/// Encrypted backup: generate a Recovery Key, encrypt the vault locally, then
/// hand the CIPHERTEXT to the OS share sheet so the user saves it to ANY cloud
/// (iCloud/Drive/Proton/Files). The app never touches the network; the cloud
/// only ever sees an opaque blob.
class BackupPage extends StatefulWidget {
  const BackupPage({super.key, required this.state});
  final AppState state;

  @override
  State<BackupPage> createState() => _BackupPageState();
}

class _BackupPageState extends State<BackupPage> {
  bool _workRelated = false; // personal => Argon2id (default); work => PBKDF2
  GeneratedPassphrase? _key;
  bool _saved = false;
  bool _busy = false;
  String? _error;

  Future<void> _generate() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final locale = Localizations.localeOf(context).languageCode;
      final words = await PassphraseGenerator.loadWordlist(locale);
      setState(() => _key = PassphraseGenerator.generate(words: words));
    } catch (e) {
      setState(() => _error = 'Could not generate a Recovery Key.');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _createBackup() async {
    final key = _key;
    if (key == null) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final plaintext = jsonEncode(
          widget.state.accounts.map((a) => a.toJson()).toList());
      final envelope = await BackupCodec.encrypt(
        plaintext: plaintext,
        passphrase: key.value,
        kdf: BackupKdf.forUsage(workRelated: _workRelated),
      );
      final dir = await getTemporaryDirectory();
      final file = File('${dir.path}/AgnosticOTP-backup.aotp.json');
      await file.writeAsString(envelope);
      await SharePlus.instance.share(ShareParams(
        files: [XFile(file.path, mimeType: 'application/json')],
        subject: 'AgnosticOTP encrypted backup',
        text: 'Encrypted AgnosticOTP backup — restore only with AgnosticOTP and '
            'your Recovery Key.',
      ));
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
            content: Text('Encrypted backup ready to save to your cloud.')));
      }
    } catch (e) {
      setState(() => _error = 'Backup failed.');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final count = widget.state.accounts.length;
    return Scaffold(
      appBar: AppBar(title: const Text('Encrypted backup')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Text('Back up $count account${count == 1 ? '' : 's'}',
              style: theme.textTheme.titleMedium),
          const SizedBox(height: 4),
          Text(
            'Your accounts are encrypted on this device and saved to a cloud of '
            'your choice. The cloud only ever sees an encrypted file — never your '
            'secrets.',
            style: theme.textTheme.bodySmall,
          ),
          const Divider(height: 32),

          // 1. usage -> KDF
          Text('1. Usage', style: theme.textTheme.titleSmall),
          SwitchListTile(
            contentPadding: EdgeInsets.zero,
            value: _workRelated,
            onChanged: _key == null ? (v) => setState(() => _workRelated = v) : null,
            title: const Text('Work-related (FIPS)'),
            subtitle: Text(_workRelated
                ? 'PBKDF2-HMAC-SHA256 — FIPS 140-3 compliant (NIST SP 800-132)'
                : 'Argon2id (RFC 9106) — memory-hard, strongest vs cracking '
                    '(personal default)'),
          ),
          const SizedBox(height: 16),

          // 2. recovery key
          Text('2. Recovery Key', style: theme.textTheme.titleSmall),
          const SizedBox(height: 8),
          if (_key == null)
            FilledButton.icon(
              onPressed: _busy ? null : _generate,
              icon: const Icon(Icons.key),
              label: const Text('Generate Recovery Key'),
            )
          else
            _RecoveryKeyBox(
              passphrase: _key!,
              saved: _saved,
              onSavedChanged: (v) => setState(() => _saved = v),
            ),
          const SizedBox(height: 16),

          // 3. create
          Text('3. Create backup', style: theme.textTheme.titleSmall),
          const SizedBox(height: 8),
          FilledButton.icon(
            onPressed: (_key != null && _saved && !_busy) ? _createBackup : null,
            icon: const Icon(Icons.cloud_upload_outlined),
            label: const Text('Encrypt & save to cloud…'),
          ),
          if (_error != null) ...[
            const SizedBox(height: 16),
            Text(_error!, style: TextStyle(color: theme.colorScheme.error)),
          ],
        ],
      ),
    );
  }
}

class _RecoveryKeyBox extends StatelessWidget {
  const _RecoveryKeyBox({
    required this.passphrase,
    required this.saved,
    required this.onSavedChanged,
  });
  final GeneratedPassphrase passphrase;
  final bool saved;
  final ValueChanged<bool> onSavedChanged;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: theme.colorScheme.surfaceContainerHighest,
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: theme.colorScheme.outlineVariant),
          ),
          child: SelectableText(
            passphrase.value,
            style: const TextStyle(fontFamily: 'monospace', fontSize: 16, height: 1.4),
          ),
        ),
        const SizedBox(height: 6),
        Row(
          children: [
            Text('~${passphrase.entropyBits.round()}-bit',
                style: theme.textTheme.labelSmall),
            const Spacer(),
            TextButton.icon(
              onPressed: () {
                Clipboard.setData(ClipboardData(text: passphrase.value));
                ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Recovery Key copied')));
              },
              icon: const Icon(Icons.copy, size: 18),
              label: const Text('Copy'),
            ),
          ],
        ),
        Container(
          padding: const EdgeInsets.all(10),
          decoration: BoxDecoration(
            color: theme.colorScheme.errorContainer.withValues(alpha: 0.4),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Row(
            children: [
              Icon(Icons.warning_amber, color: theme.colorScheme.error, size: 20),
              const SizedBox(width: 8),
              const Expanded(
                child: Text(
                  'Save this in your password manager. It is the ONLY way to '
                  'restore — it can\'t be reset, and we never see it.',
                ),
              ),
            ],
          ),
        ),
        CheckboxListTile(
          contentPadding: EdgeInsets.zero,
          value: saved,
          onChanged: (v) => onSavedChanged(v ?? false),
          title: const Text('I have saved my Recovery Key'),
        ),
      ],
    );
  }
}
