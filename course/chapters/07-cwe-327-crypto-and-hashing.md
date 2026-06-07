# Chapter 7 — CWE-327/916: Broken Cryptography and Weak Password Hashing

**Time budget:** ~65 min · **CWE:** CWE-327 / CWE-916 · **Files:** `src/Vulnerable/Shop.Api/Controllers/CryptoController.cs` ↔ `src/Fixed/Shop.Api/Controllers/CryptoController.cs` · test `tests/Shop.Tests/CryptoTests.cs`

## The weakness in one line

The application stores passwords with unsalted MD5 (crackable in milliseconds) and encrypts data with AES-ECB (identical plaintext blocks produce identical ciphertext blocks), both of which expose sensitive data even without the key or a network breach.

## Live demo script

**Demo A — Password Hashing**

1. Open the Vulnerable `CryptoController`. Read the `// CWE-916` comment aloud — note `MD5.HashData(Encoding.UTF8.GetBytes(req.Password))`. Point out there is no salt and no iteration count.
2. Hit `POST /crypto/hash` twice with `{"password":"hunter2"}` → both responses return the identical hex string, and you can verify it matches the plain MD5 of `hunter2` via any online lookup (the test does exactly this: it computes `MD5.HashData` independently and asserts equality). Rainbow tables make this trivially reversible.
3. Open the Fixed `CryptoController` side-by-side: `PasswordHasher<object>.HashPassword(...)` — one line, no explicit salt or iteration management needed. The result is a Base64 blob that embeds a per-hash random salt and a PBKDF2 work factor. Hit the same endpoint twice → hashes differ every call even for the same password.

**Demo B — Symmetric Encryption**

4. Back in the Vulnerable controller, read the `// CWE-327` comment — note `aes.Mode = CipherMode.ECB`. Send `POST /crypto/encrypt` with `{"plaintext":"YELLOW_SUBMARINEYELLOW_SUBMARINE"}` (32 bytes = exactly two 16-byte AES blocks). Decode the Base64 ciphertext; point out `bytes[0..15] == bytes[16..31]` — ECB encrypts each block independently, so identical plaintext → identical ciphertext. This is the famous "ECB penguin" leak.
5. Open the Fixed `CryptoController`: `IDataProtectionProvider.CreateProtector(...).Protect(plaintext)` — no key management, no mode selection. Call the endpoint twice with the same plaintext → ciphertext differs both times (Data Protection prepends a random IV/subkey per call).
6. Run `dotnet test --filter FullyQualifiedName~CryptoTests` → green.

## Why it's exploitable (the mechanism)

MD5 is a general-purpose hash designed to be fast; without a salt, two users with the same password produce the same hash, and precomputed rainbow tables can reverse billions of common passwords in seconds. ECB mode treats the plaintext as independent 16-byte blocks and encrypts each with the same key transformation, so repeated plaintext patterns survive into the ciphertext — an attacker can detect structure (e.g., identical credit card numbers in a database dump) without ever recovering the key. Both weaknesses are exploitable from ciphertext or hash alone, long after data is stolen.

## The fix (and why it's usually less code)

ASP.NET Core Identity's `PasswordHasher<T>` wraps PBKDF2-HMAC-SHA256 with a random 128-bit salt and 10,000 iterations (v3 format) behind a single method call — no algorithm choice, no salt generation, no iteration tuning required. The Data Protection API (`IDataProtectionProvider`) wraps authenticated encryption (AES-CBC + HMAC or AES-GCM depending on the platform) with automatic key rotation behind `Protect`/`Unprotect` — again a single-line replacement that eliminates the entire hand-rolled AES block. Both fixes are strictly less code than the vulnerable versions.

## The transferable principle

> **Never hand-roll crypto; use a real KDF for passwords.**

## "But what about…" — anticipated questions

- **Q:** MD5 and SHA-1 are fast — isn't fast better for hashing? **A:** For checksums yes; for passwords, speed is the enemy. An attacker with a GPU can compute billions of MD5 hashes per second. A KDF like PBKDF2 or bcrypt deliberately stretches computation to thousands of iterations, so brute-force attacks become economically infeasible. The fast hash is the vulnerability, not a feature.
- **Q:** What is the ECB penguin and why does it matter here? **A:** It refers to the famous demonstration where encrypting a bitmap of a penguin in ECB mode preserves the outline because each identically-coloured block encrypts to the same ciphertext. The same principle applies to structured data: if two rows in a database share the same field value (e.g., `Amount=0.00`), their ECB ciphertext blocks are identical — an attacker can detect patterns, reorder blocks, or confirm guesses without ever decrypting.
- **Q:** Why use the Data Protection API instead of just passing an IV with AES-CBC ourselves? **A:** Hand-rolling AES-CBC introduces new risks: forgetting the IV, reusing it, using a static key, or omitting an authentication tag (leading to padding-oracle attacks). The Data Protection API handles key generation, rotation, IV randomisation, and authentication in one abstraction. For general encryption of application data it is the correct .NET answer; for files or interop scenarios, `AesGcm` with a fresh random nonce is the next-best option.
