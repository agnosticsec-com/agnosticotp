import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../app_state.dart';
import '../core/totp.dart';
import '../data/account.dart';
import 'manual_entry_page.dart';
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
        leading: Padding(
          padding: const EdgeInsets.all(8),
          child: Image.asset('assets/brand/AS_Logo_Reversed_White.png'),
        ),
        title: const Text('AgnosticOTP'),
        actions: [
          IconButton(
            tooltip: 'Lock',
            icon: const Icon(Icons.lock_outline),
            onPressed: widget.state.lockNow,
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

class _AlgoBadge extends StatelessWidget {
  const _AlgoBadge({required this.algorithm});
  final TotpAlgorithm algorithm;

  @override
  Widget build(BuildContext context) {
    final legacy = algorithm == TotpAlgorithm.sha1;
    final theme = Theme.of(context);
    final color = legacy ? theme.colorScheme.error : theme.colorScheme.primary;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        border: Border.all(color: color),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(
        legacy ? '${algorithm.wireName} · legacy' : algorithm.wireName,
        style: theme.textTheme.labelSmall?.copyWith(color: color),
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
