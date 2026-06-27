<p align="center">
  <img src="assets/brand/AS_Logo_Primary.png" width="120" alt="Agnostic Security"/>
</p>

# AgnosticOTP

A privacy-first, offline TOTP authenticator for Android and iOS, built with Flutter.
**SHA-256 by default**, with SHA-1/SHA-512 supported for legacy services.

## Why

Most authenticator apps default to (and some only support) HMAC-SHA1. AgnosticOTP
defaults every new account to **HMAC-SHA256**, only dropping to SHA-1 when a service
explicitly asks for it — and shows you which accounts are on legacy crypto.

## Features

- **RFC 6238 TOTP** — SHA-256 (default), SHA-1 and SHA-512 (legacy/interop); 6–8 digits; configurable period. Verified against the RFC 6238 Appendix B known-answer vectors.
- **Biometric-bound storage** — secrets are encrypted with a hardware-backed key (Android Keystore / iOS Secure Enclave) that requires a biometric to unlock. Access is *cryptographically* tied to the biometric, not an app-level toggle.
- **Two enrolment paths** — scan a QR code (live camera or an image from your gallery), or type a base-32 secret manually.
- **Offline by design** — no network, no accounts, no cloud sync. The Android build ships **without the `INTERNET` permission**: secrets have no way off the device.
- **Hardened** — `FLAG_SECURE` (Android) + privacy blur (iOS) block screenshots and app-switcher capture; auto-lock on background; no device backups; clipboard auto-clears 30s after copying a code.

## Security

This app was threat-modelled (STRIDE + attack trees, OWASP MASVS) before the
security-critical code was written. The threat model and the per-finding dev
disposition live with the project's security artifacts. Highlights:

- Hardware Keystore key audited: AES-256-GCM, `setUserAuthenticationRequired(true)`, cipher bound to the biometric (`authenticationValidityDurationSeconds = -1`, a load-bearing invariant).
- Adding/changing a biometric invalidates the key (anti-coercion).
- Hostile-QR defence: every `otpauth://` field is bounds-checked; oversized URIs, HOTP, out-of-range `digits`/`period`, weak (<80-bit) and non-base32 secrets are rejected at enrolment.

## Project layout

```
lib/
  core/totp.dart          # RFC 6238 engine (SHA-256 default)
  core/otpauth_uri.dart   # otpauth:// parser — the enrolment trust boundary
  data/account.dart       # account model + base32 validation
  data/secure_store.dart  # biometric-bound vault (Vault interface + SecureVault)
  app_state.dart          # session state; in-memory secrets, dropped on lock
  ui/                     # lock screen, code list, QR scanner, manual entry, theme
test/                     # RFC vectors, parser/hostile-QR, headless full-flow
integration_test/         # on-device full-flow test
```

## Develop

Requires the Flutter SDK (stable).

```bash
flutter pub get
flutter test                                   # unit + headless flow tests
flutter run                                    # on a connected device
flutter test integration_test/app_test.dart    # full flow on a device
flutter build apk --debug                       # Android build
```

> Biometrics and the hardware Keystore exist only on real devices — the secure
> vault cannot be exercised on the Linux/web desktop targets.

## Brand

Uses the Agnostic Security palette (Agnostic Blue `#1F5F8E`, Agnostic Orange
`#EC6B2D`) and shield logo from the brand pack.
