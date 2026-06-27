// AgnosticOTP — biometric-bound secure vault ("Level B").
//
// All TOTP secrets live in a single encrypted blob whose key is generated in
// hardware (Android Keystore / StrongBox where available, iOS Secure Enclave)
// and is *user-authentication-required*: a successful biometric is what unlocks
// the key that decrypts the blob. Access is therefore cryptographically bound
// to the biometric, not gated by an app-level boolean.
//
// Options rationale:
//  - authenticationRequired: true        → no plaintext-without-auth path.
//  - androidBiometricOnly:  true         → no class-2/credential downgrade on
//                                          Android (also required for the
//                                          auth-every-use key below).
//  - darwinBiometricOnly:   true         → iOS uses .biometryCurrentSet, so
//                                          ADDING/CHANGING a fingerprint/face
//                                          INVALIDATES the key (anti-coercion).
//  - validityDuration: -1                → re-auth on every storage access; we
//                                          cache decrypted accounts in memory
//                                          for the session so the per-second
//                                          code refresh never re-prompts.
//
// ⚠️ LOAD-BEARING INVARIANT (verified against biometric_storage 5.0.1 native
//    source — CryptographyManager.kt / BiometricStoragePlugin.kt:180,408):
//    `authenticationValidityDurationSeconds` MUST stay -1. Only at -1 does the
//    plugin use a Keystore CryptoObject, cryptographically binding the AES-256
//    key to the biometric. Any value >= 0 makes it authenticate WITHOUT the
//    cipher (a boolean-ish gate a rooted device can bypass). Do not change.
//    (StrongBox is not requested by the package → keys are TEE-backed, not
//    secure-element-backed; tracked as a deferred enhancement.)

import 'dart:convert';

import 'package:biometric_storage/biometric_storage.dart';

import 'account.dart';

/// Result of probing whether the device can do biometric-bound storage.
enum VaultAvailability {
  ready,
  noBiometricEnrolled,
  noHardware,
  passcodeNotSet,
  unavailable,
}

/// Raised when the user cancels / fails the biometric prompt, so the UI can
/// distinguish "locked out" from "real error".
class VaultAuthCancelled implements Exception {
  const VaultAuthCancelled();
}

/// The storage contract the app depends on. [SecureVault] is the real
/// biometric-bound implementation; tests inject an in-memory fake so the UI
/// flow can be exercised on a device without a live biometric prompt.
abstract interface class Vault {
  Future<VaultAvailability> availability();
  Future<List<Account>> unlockAndLoad();
  Future<void> save(List<Account> accounts);
  Future<void> wipe();
}

class SecureVault implements Vault {
  SecureVault({BiometricStorage? backend})
      : _backend = backend ?? BiometricStorage();

  final BiometricStorage _backend;

  /// Single hardware-keyed file holding the JSON array of accounts.
  static const String _vaultName = 'agnosticotp_vault_v1';

  BiometricStorageFile? _file;

  static const PromptInfo _prompt = PromptInfo(
    androidPromptInfo: AndroidPromptInfo(
      title: 'Unlock AgnosticOTP',
      subtitle: 'Authenticate to access your codes',
      negativeButton: 'Cancel',
      confirmationRequired: false,
    ),
    iosPromptInfo: IosPromptInfo(
      saveTitle: 'Authenticate to save your codes',
      accessTitle: 'Authenticate to access your codes',
    ),
  );

  @override
  Future<VaultAvailability> availability() async {
    switch (await _backend.canAuthenticate()) {
      case CanAuthenticateResponse.success:
        return VaultAvailability.ready;
      case CanAuthenticateResponse.errorNoBiometricEnrolled:
        return VaultAvailability.noBiometricEnrolled;
      case CanAuthenticateResponse.errorNoHardware:
      case CanAuthenticateResponse.unsupported:
        return VaultAvailability.noHardware;
      case CanAuthenticateResponse.errorPasscodeNotSet:
        return VaultAvailability.passcodeNotSet;
      case CanAuthenticateResponse.errorHwUnavailable:
      case CanAuthenticateResponse.statusUnknown:
        return VaultAvailability.unavailable;
    }
  }

  Future<BiometricStorageFile> _storage() async {
    return _file ??= await _backend.getStorage(
      _vaultName,
      options: StorageFileInitOptions(
        authenticationRequired: true,
        androidBiometricOnly: true,
        darwinBiometricOnly: true,
        authenticationValidityDurationSeconds: -1,
      ),
      promptInfo: _prompt,
    );
  }

  /// Trigger biometric auth and return the decrypted accounts.
  ///
  /// Throws [VaultAuthCancelled] if the user dismisses/fails the prompt.
  @override
  Future<List<Account>> unlockAndLoad() async {
    final file = await _storage();
    final String? raw;
    try {
      raw = await file.read(promptInfo: _prompt);
    } on AuthException catch (e) {
      if (e.code == AuthExceptionCode.userCanceled ||
          e.code == AuthExceptionCode.canceled ||
          e.code == AuthExceptionCode.timeout) {
        throw const VaultAuthCancelled();
      }
      rethrow;
    }
    return _decode(raw);
  }

  /// Persist the full account list (read-modify-write of the single blob).
  /// Triggers a biometric prompt to access the key.
  @override
  Future<void> save(List<Account> accounts) async {
    final file = await _storage();
    final payload = jsonEncode(accounts.map((a) => a.toJson()).toList());
    try {
      await file.write(payload, promptInfo: _prompt);
    } on AuthException catch (e) {
      if (e.code == AuthExceptionCode.userCanceled ||
          e.code == AuthExceptionCode.canceled) {
        throw const VaultAuthCancelled();
      }
      rethrow;
    }
  }

  /// Wipe the vault (e.g. on user "remove all"). Irreversible.
  @override
  Future<void> wipe() async {
    final file = await _storage();
    await file.delete(promptInfo: _prompt);
  }

  List<Account> _decode(String? raw) {
    if (raw == null || raw.trim().isEmpty) return <Account>[];
    final decoded = jsonDecode(raw);
    if (decoded is! List) return <Account>[];
    final out = <Account>[];
    for (final item in decoded) {
      if (item is Map<String, dynamic>) {
        // A single corrupt entry must not nuke the whole vault.
        try {
          out.add(Account.fromJson(item));
        } on Object {
          continue;
        }
      }
    }
    return out;
  }
}
