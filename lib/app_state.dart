// AgnosticOTP — app state / session controller.
//
// Holds the in-memory decrypted accounts for the duration of an unlocked
// session. Secrets are loaded once after biometric unlock and dropped from
// memory whenever the app is locked or backgrounded (see AgnosticOtpApp's
// lifecycle handling) — so a stolen-while-locked device exposes nothing.

import 'package:flutter/foundation.dart';

import 'core/totp.dart';
import 'data/account.dart';
import 'data/secure_store.dart';

enum VaultLockState { locked, unlocking, unlocked, unavailable }

class AppState extends ChangeNotifier {
  AppState({Vault? vault}) : _vault = vault ?? SecureVault();

  final Vault _vault;

  VaultLockState _lock = VaultLockState.locked;
  VaultLockState get lock => _lock;

  VaultAvailability _availability = VaultAvailability.ready;
  VaultAvailability get availability => _availability;

  // Only populated while unlocked.
  List<Account> _accounts = <Account>[];
  List<Account> get accounts => List.unmodifiable(_accounts);

  String? _error;
  String? get error => _error;

  Future<void> probe() async {
    _availability = await _vault.availability();
    if (_availability != VaultAvailability.ready) {
      _lock = VaultLockState.unavailable;
    }
    notifyListeners();
  }

  Future<void> unlock() async {
    if (_lock == VaultLockState.unlocking) return;
    _lock = VaultLockState.unlocking;
    _error = null;
    notifyListeners();
    try {
      _accounts = await _vault.unlockAndLoad();
      _lock = VaultLockState.unlocked;
    } on VaultAuthCancelled {
      _lock = VaultLockState.locked;
    } catch (e) {
      _error = 'Could not unlock the vault.';
      _lock = VaultLockState.locked;
    }
    notifyListeners();
  }

  /// Drop decrypted secrets from memory and return to the lock screen.
  void lockNow() {
    _accounts = const <Account>[];
    _lock = VaultLockState.locked;
    notifyListeners();
  }

  Future<void> addAccount(Account account) async {
    // Dedupe on stable id (re-import of same credential is a no-op).
    final next = [..._accounts.where((a) => a.id != account.id), account];
    await _vault.save(next);
    _accounts = next;
    notifyListeners();
  }

  Future<void> removeAccount(String id) async {
    final next = _accounts.where((a) => a.id != id).toList();
    await _vault.save(next);
    _accounts = next;
    notifyListeners();
  }

  /// Current code + remaining seconds for an account (pure compute from the
  /// in-memory secret; no storage access).
  ({String code, int remaining}) codeFor(Account a) {
    final gen = TotpGenerator(a.params);
    return (code: gen.code(a.keyBytes()), remaining: gen.secondsRemaining());
  }
}
