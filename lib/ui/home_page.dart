import 'dart:async';

import 'package:flutter/foundation.dart' show kDebugMode;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../app_state.dart';
import '../core/totp.dart';
import '../data/account.dart';
import 'backup_page.dart';
import 'brand_wordmark.dart';
import 'import_page.dart';
import 'manual_entry_page.dart';
import 'restore_page.dart';
import 'scan_page.dart';

class HomePage extends StatefulWidget {
  const HomePage({super.key, required this.state});

  final AppState state;

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  Timer? _ticker;

  @override
  void initState() {
    super.initState();
    // Drive the per-second countdown / code rollover.
    _ticker = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted) setState(() {});
    });
  }

  @override
  void dispose() {
    _ticker?.cancel();
    super.dispose();
  }

  Future<void> _add() async {
    final choice = await showModalBottomSheet<String>(
      context: context,
      builder: (ctx) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.qr_code_scanner),
              title: const Text('Scan QR code'),
              onTap: () => Navigator.pop(ctx, 'scan'),
            ),
            ListTile(
              leading: const Icon(Icons.keyboard),
              title: const Text('Enter secret manually'),
              onTap: () => Navigator.pop(ctx, 'manual'),
            ),
          ],
        ),
      ),
    );
    if (!mounted || choice == null) return;

    Account? account;
    if (choice == 'scan') {
      account = await Navigator.push<Account>(
        context,
        MaterialPageRoute(builder: (_) => const ScanPage()),
      );
    } else if (choice == 'manual') {
      account = await Navigator.push<Account>(
        context,
        MaterialPageRoute(builder: (_) => const ManualEntryPage()),
      );
    }
    if (account == null || !mounted) return;
    try {
      await widget.state.addAccount(account);
    } catch (e) {
      _snack('Could not save account.');
    }
  }

  /// Copy a code, then auto-clear the clipboard after 30s (threat model M3:
  /// the clipboard is readable by other apps). Only clears if the clipboard
  /// still holds OUR code, so we never wipe something the user copied later.
  void _copyCode(String code) {
    Clipboard.setData(ClipboardData(text: code));
    _snack('Code copied — clipboard clears in 30s');
    Timer(const Duration(seconds: 30), () async {
      final current = await Clipboard.getData(Clipboard.kTextPlain);
      if (current?.text == code) {
        await Clipboard.setData(const ClipboardData(text: ''));
      }
    });
  }

  void _snack(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text(msg)));
  }

  @override
  Widget build(BuildContext context) {
    final accounts = widget.state.accounts;
    return Scaffold(
      appBar: AppBar(
        leading: const Padding(
          padding: EdgeInsets.all(8),
          child: Image(
            image: AssetImage('assets/brand/AS_Logo_Primary.png'), // full colour
          ),
        ),
        title: const AppWordmark(),
        actions: [
          if (kDebugMode)
            IconButton(
              tooltip: 'Load test data (debug)',
              icon: const Icon(Icons.science_outlined),
              onPressed: () {
                widget.state.loadTestDataDebug();
                _snack('Loaded test accounts (in-memory)');
              },
            ),
          IconButton(
            tooltip: 'Lock',
            icon: const Icon(Icons.lock_outline),
            onPressed: widget.state.lockNow,
          ),
          PopupMenuButton<String>(
            onSelected: (v) {
              final page = switch (v) {
                'backup' => BackupPage(state: widget.state),
                'restore' => RestorePage(state: widget.state),
                'import' => ImportPage(state: widget.state),
                _ => null,
              };
              if (page != null) {
                Navigator.push(context, MaterialPageRoute(builder: (_) => page));
              }
            },
            itemBuilder: (_) => const [
              PopupMenuItem(
                value: 'backup',
                child: ListTile(
                    leading: Icon(Icons.cloud_upload_outlined),
                    title: Text('Encrypted backup')),
              ),
              PopupMenuItem(
                value: 'restore',
                child: ListTile(
                    leading: Icon(Icons.restore), title: Text('Restore backup')),
              ),
              PopupMenuItem(
                value: 'import',
                child: ListTile(
                    leading: Icon(Icons.download_outlined),
                    title: Text('Import accounts')),
              ),
            ],
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _add,
        icon: const Icon(Icons.add),
        label: const Text('Add'),
      ),
      body: accounts.isEmpty
          ? const _EmptyState()
          : ListView.separated(
              padding: const EdgeInsets.symmetric(vertical: 8),
              itemCount: accounts.length,
              separatorBuilder: (_, _) => const Divider(height: 1),
              itemBuilder: (context, i) {
                final a = accounts[i];
                final r = widget.state.codeFor(a);
                return _CodeTile(
                  account: a,
                  code: r.code,
                  remaining: r.remaining,
                  onCopy: () => _copyCode(r.code),
                  onDelete: () => _confirmDelete(a),
                );
              },
            ),
    );
  }

  Future<void> _confirmDelete(Account a) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Remove account?'),
        content: Text('Remove ${a.issuer.isEmpty ? a.label : a.issuer}? '
            'You will lose this secret unless you have a backup.'),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel')),
          FilledButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('Remove')),
        ],
      ),
    );
    if (ok == true) {
      try {
        await widget.state.removeAccount(a.id);
      } catch (e) {
        _snack('Could not remove account.');
      }
    }
  }
}

class _CodeTile extends StatelessWidget {
  const _CodeTile({
    required this.account,
    required this.code,
    required this.remaining,
    required this.onCopy,
    required this.onDelete,
  });

  final Account account;
  final String code;
  final int remaining;
  final VoidCallback onCopy;
  final VoidCallback onDelete;

  String get _grouped {
    // 6 → "123 456", 8 → "1234 5678".
    final half = code.length ~/ 2;
    return '${code.substring(0, half)} ${code.substring(half)}';
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final title = account.issuer.isNotEmpty ? account.issuer : account.label;
    final subtitle = account.issuer.isNotEmpty && account.label.isNotEmpty
        ? account.label
        : null;

    return ListTile(
      title: Row(
        children: [
          Expanded(child: Text(title, overflow: TextOverflow.ellipsis)),
          _StrengthDot(strength: account.strength, bits: account.secretBits),
          const SizedBox(width: 8),
          _AlgoBadge(algorithm: account.algorithm),
        ],
      ),
      subtitle: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (subtitle != null) Text(subtitle),
          const SizedBox(height: 4),
          Text(
            _grouped,
            style: theme.textTheme.headlineMedium?.copyWith(
              fontFeatures: const [FontFeature.tabularFigures()],
              letterSpacing: 2,
            ),
          ),
        ],
      ),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          _Countdown(remaining: remaining, period: account.params.period),
          IconButton(icon: const Icon(Icons.copy), onPressed: onCopy),
          IconButton(
              icon: const Icon(Icons.delete_outline), onPressed: onDelete),
        ],
      ),
    );
  }
}

/// Per-account hash-type badge: a distinct icon + colour per algorithm so the
/// hash is recognisable at a glance.
class _AlgoBadge extends StatelessWidget {
  const _AlgoBadge({required this.algorithm});
  final TotpAlgorithm algorithm;

  static const Color _amber = Color(0xFFE0A030);
  static const Color _green = Color(0xFF3FB36B);

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final (IconData icon, Color color, String label) = switch (algorithm) {
      TotpAlgorithm.sha1 => (Icons.gpp_maybe, _amber, 'SHA1 · legacy'),
      TotpAlgorithm.sha256 => (Icons.gpp_good, theme.colorScheme.primary, 'SHA256'),
      TotpAlgorithm.sha512 => (Icons.verified_user, _green, 'SHA512'),
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        border: Border.all(color: color),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 13, color: color),
          const SizedBox(width: 3),
          Text(label, style: theme.textTheme.labelSmall?.copyWith(color: color)),
        ],
      ),
    );
  }
}

/// Small coloured dot reflecting the secret's NIST strength tier (tap/hover for
/// the bit count).
class _StrengthDot extends StatelessWidget {
  const _StrengthDot({required this.strength, required this.bits});
  final SecretStrength strength;
  final int bits;

  @override
  Widget build(BuildContext context) {
    final color = switch (strength) {
      SecretStrength.belowAal2 => Theme.of(context).colorScheme.error,
      SecretStrength.aal2 => const Color(0xFFE0A030),
      SecretStrength.futureProof => Theme.of(context).colorScheme.primary,
      SecretStrength.recommended => const Color(0xFF3FB36B),
    };
    return Tooltip(
      message: 'Secret strength: ${strength.label} ($bits-bit)',
      child: Container(
        width: 10,
        height: 10,
        decoration: BoxDecoration(color: color, shape: BoxShape.circle),
      ),
    );
  }
}

class _Countdown extends StatelessWidget {
  const _Countdown({required this.remaining, required this.period});
  final int remaining;
  final int period;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: 32,
      height: 32,
      child: Stack(
        alignment: Alignment.center,
        children: [
          CircularProgressIndicator(
            value: remaining / period,
            strokeWidth: 3,
          ),
          Text('$remaining', style: Theme.of(context).textTheme.labelSmall),
        ],
      ),
    );
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState();

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.lock_clock, size: 56),
            const SizedBox(height: 12),
            Text('No accounts yet',
                style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            const Text(
              'Tap Add to scan a QR code or enter a secret. '
              'New accounts default to SHA256.',
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }
}
