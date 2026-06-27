import 'package:flutter/material.dart';

import '../app_state.dart';
import '../data/secure_store.dart';
import 'theme.dart';

class LockScreen extends StatelessWidget {
  const LockScreen({super.key, required this.state});

  final AppState state;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final unavailable = state.lock == VaultLockState.unavailable;

    return Scaffold(
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Image.asset(AppTheme.logoPrimary, height: 96),
              const SizedBox(height: 16),
              Text('AgnosticOTP', style: theme.textTheme.headlineSmall),
              const SizedBox(height: 8),
              Text(
                'SHA256-default authenticator',
                style: theme.textTheme.bodySmall
                    ?.copyWith(color: theme.colorScheme.outline),
              ),
              const SizedBox(height: 40),
              if (unavailable)
                _Unavailable(availability: state.availability)
              else ...[
                FilledButton.icon(
                  onPressed: state.lock == VaultLockState.unlocking
                      ? null
                      : () => state.unlock(),
                  icon: const Icon(Icons.fingerprint),
                  label: Text(state.lock == VaultLockState.unlocking
                      ? 'Authenticating…'
                      : 'Unlock with biometrics'),
                ),
                if (state.error != null) ...[
                  const SizedBox(height: 16),
                  Text(state.error!,
                      style: TextStyle(color: theme.colorScheme.error)),
                ],
              ],
            ],
          ),
        ),
      ),
    );
  }
}

class _Unavailable extends StatelessWidget {
  const _Unavailable({required this.availability});
  final VaultAvailability availability;

  @override
  Widget build(BuildContext context) {
    final msg = switch (availability) {
      VaultAvailability.noBiometricEnrolled =>
        'No biometrics enrolled. Add a fingerprint or face in system settings to use AgnosticOTP.',
      VaultAvailability.noHardware =>
        'This device has no biometric hardware. AgnosticOTP requires biometric-backed secure storage.',
      VaultAvailability.passcodeNotSet =>
        'Set a device passcode/screen lock first — it anchors the secure storage key.',
      _ => 'Biometric secure storage is currently unavailable.',
    };
    return Text(msg, textAlign: TextAlign.center);
  }
}
