// AgnosticOTP — app entry.
//
// Re-locks (drops in-memory secrets) whenever the app leaves the foreground,
// so backgrounding or the app-switcher snapshot never exposes live codes.

import 'package:flutter/material.dart';

import 'app_state.dart';
import 'data/secure_store.dart';
import 'ui/home_page.dart';
import 'ui/lock_screen.dart';
import 'ui/theme.dart';

void main() {
  runApp(const AgnosticOtpApp());
}

class AgnosticOtpApp extends StatefulWidget {
  /// [vault] is injectable for integration tests (an in-memory fake); production
  /// leaves it null and gets the real biometric-bound [SecureVault].
  const AgnosticOtpApp({super.key, this.vault});

  final Vault? vault;

  @override
  State<AgnosticOtpApp> createState() => _AgnosticOtpAppState();
}

class _AgnosticOtpAppState extends State<AgnosticOtpApp>
    with WidgetsBindingObserver {
  late final AppState _state = AppState(vault: widget.vault);

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _state.probe();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _state.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState lifecycle) {
    // Lock as soon as we lose the foreground — secrets leave memory before any
    // app-switcher snapshot or background pause.
    if (lifecycle == AppLifecycleState.inactive ||
        lifecycle == AppLifecycleState.paused ||
        lifecycle == AppLifecycleState.hidden) {
      if (_state.lock == VaultLockState.unlocked) {
        _state.lockNow();
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'AgnosticOTP',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.light(),
      darkTheme: AppTheme.dark(),
      themeMode: ThemeMode.dark, // dark by default
      home: AnimatedBuilder(
        animation: _state,
        builder: (context, _) {
          if (_state.lock == VaultLockState.unlocked) {
            return HomePage(state: _state);
          }
          return LockScreen(state: _state);
        },
      ),
    );
  }
}
