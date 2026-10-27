# Benchmark card: pqblocks-agility (offline)

generated_utc: 2026-09-14T02:57:31.873548+00:00
weights: [0.2, 0.25, 0.25, 0.15, 0.15] (sum=1.0)

- mini-4asset-spec-3.3: computed=47.5000 target=47.5 tol=1e-09 pass=True
- oqs-provider-v0.3.0: computed=43.5000 target=43.5 tol=1e-09 pass=True
- oqs-provider-v0.6.0: computed=64.5000 target=64.5 tol=1e-09 pass=True
- pkcs11-provider-0.5: computed=69.5000 target=67.3 tol=5.0 pass=True
- pkcs11js-2.3: computed=13.0000 target=13.0 tol=1e-09 pass=True

live_corpus attempted=43 replicated_offline=5 skipped_offline=40
(live entries require network + pinned commits; itemized as skipped)
