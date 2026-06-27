# Scoping: FIPS 140-3 Level 1 (validated module) for AgnosticOTP

**Status:** roadmap / not pursued. **Date:** 2026-06-27.

> **DECISION (2026-06-27):** Keep **Argon2id as the default** KDF — it is more
> resistant to offline GPU/ASIC cracking than PBKDF2. We will **not** pursue a
> FIPS-Level-1 validated-module build that would force PBKDF2-only, *unless a
> regulated customer mandates it*. PBKDF2 stays as an explicit opt-in for anyone
> who needs FIPS-Approved algorithms; we do not weaken the default for a label.

## Goal
Let AgnosticOTP legitimately claim **"FIPS 140-3 Level 1 — cryptography performed
by a CMVP-validated module"** for federal / regulated deployments — without
overclaiming.

## Where we are today (honest baseline)
Crypto runs through **pure-Dart** packages: `crypto` (HMAC for TOTP) and
`cryptography` (AES-256-GCM, PBKDF2, Argon2id). These use **FIPS-Approved
algorithms**, but the implementations are **neither CMVP-validated (module) nor
CAVP-tested (algorithm)**. So today's only defensible claim is *"uses
FIPS-Approved algorithms (SP 800-132)."* Even **Level 1 requires a validated
module** — there is no "compliant but not validated" tier.

## What Level 1 actually requires
Crypto operations performed by a **CMVP-validated cryptographic module**,
operated in its **Approved mode** (Approved algorithms only), with the module's
**power-on self-tests + integrity check** run at startup. You do **not** need
your *own* CMVP certificate (that is $$$ + 12–18 month queue) — you **cite the
module's certificate** and operate it per its Security Policy.

## Options

### Option 1 — Bundle the OpenSSL 3.x FIPS provider via Dart FFI  *(recommended)*
The **OpenSSL FIPS provider is now FIPS 140-3 validated** (OpenSSL 3.1.2,
CMVP cert ~#4985, 2025; compatible with 3.0–3.5). Ship the validated `fips`
module per architecture (android arm64/x86_64, ios arm64), load via FFI, run its
self-tests at startup, and route AES-256-GCM, HMAC-SHA1/256/512, and PBKDF2
through it.
- **+** One validated module, **both platforms**, a single citable cert, full control.
- **−** Native build per arch; **~2–5 MB/arch** binary; FFI bindings + self-test
  handling; **must use the module "as validated"** (follow the validated build
  procedure / use vendor-supplied validated artifacts — an arbitrary rebuild
  voids the cert).

### Option 2 — Platform-native validated crypto (per-platform)
- **iOS:** Apple **corecrypto** carries CMVP validations — route via
  CryptoKit / CommonCrypto (PBKDF2 = `CCKeyDerivationPBKDF`, AES-GCM, HMAC).
- **Android:** Google **BoringCrypto** (BoringSSL FIPS) is CMVP-validated —
  via Conscrypt in FIPS mode, or Android Keystore (hardware-validated on many
  devices).
- **+** No bundled binary (smaller app), OS-maintained.
- **−** Per-platform Swift + Kotlin; Android FIPS-mode availability **varies by
  device/OEM**, so a uniform claim is fiddly; must confirm each module's cert
  covers the algorithms and that we run in Approved mode.

### Option 3 — Hybrid
iOS via corecrypto, Android via bundled OpenSSL-FIPS for a consistent claim.

## Architecture change (common to all)
1. A Dart `CryptoProvider` interface (HMAC, AES-GCM encrypt/decrypt, PBKDF2).
2. Two impls: current pure-Dart (**default / personal, non-FIPS**) and a
   **FIPS-backed** impl (FFI / platform channel to the validated module).
3. **TOTP HMAC must also route through the validated module** for a full claim
   (today it's the `crypto` package).
4. **KDF in FIPS mode = PBKDF2 only.** **Argon2id is NOT FIPS-Approved** — keep
   it as the explicit non-FIPS *personal* backup option (the work→PBKDF2 /
   personal→Argon2id split already aligns with this).
5. Run module self-tests at startup; **fail-closed** if they fail.
6. Record the module name + CMVP cert number in the security docs.

## Honesty guardrails
- The resulting claim is **"cryptography performed by <module>, CMVP cert #XXXX,
  FIPS 140-3 Level 1"** — accurate. **Not** "AgnosticOTP is FIPS 140-3 certified"
  (the *module* is; the app *uses* it).
- **Argon2id backups can never be called FIPS** — label them clearly as the
  non-FIPS personal option.
- Confirm exact cert numbers + current validation status at implementation time
  (CMVP listings change; OpenSSL 3.5.x was still in the validation queue as of
  late 2025).

## Effort (rough) & recommendation
- Crypto abstraction + wiring: ~1–2 weeks.
- Option 1 (bundle OpenSSL-FIPS, FFI, per-arch build, self-tests, KATs): ~3–6
  weeks + binary size.
- Option 2 (platform-native): ~2–4 weeks, lighter binary, fiddly Android claim.
- Plus FIPS known-answer tests, Security-Policy documentation, and a compliance
  review (Lu) of the deployment claim.

**Recommendation:** defer until a federal/regulated customer justifies the cost.
When triggered, take **Option 1** for one uniform, citable claim across both
platforms; keep the pure-Dart path as the non-FIPS default (with Argon2id), and
ship "FIPS mode" as an opt-in for regulated deployments.

Sources: OpenSSL 3.1.2 FIPS 140-3 validation (openssl-library.org, 2025-03-11);
NIST CMVP program (csrc.nist.gov).
