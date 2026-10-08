# Pinned Microsoft legacy TSA fixture

`catalog.cat` is the authentic native WinSxS catalog
`69622576702850c4b3303326bc717f27b8241086841ca022b8fffcf7b4307cab.cat`,
source-safe preserved from the disposable NetFx3 native oracle on 2026-10-06.
`member.manifest` is the native ApplyDeltaB expanded amd64 WCF GenericCommands
10.0.19041.1 manifest. Its SHA-256 equals the genuine COMPONENTS S256H value
`1aa9d7cd2c8ca9f110df999b7d9c030ccf2f1a755b3ac9b73e804a6eb56771ce`.

Native Windows Get-AuthenticodeSignature returned Valid for this catalog.
`tsa.der` is the actual Microsoft Time-Stamp Service leaf returned by that native
observation, SHA-256
`4540cd42e1fe2822157edfb1a7b6424f00f4a9020554a6780fe7c948f2b3c2e2`.
It has exactly one Time Stamping EKU, marked noncritical. The fixture policy
explicitly pins this leaf; omitting the compatibility field preserves strict
RFC3161 rejection. Microsoft root DER is copied unchanged from the existing
hash-pinned servicing source policy. Revocation is explicitly disabled in this
isolated offline fixture and no revocation freshness is claimed.

Full source metadata, native certificate DER/extensions and acquisition pins
remain in `/data/cache/servicing-engine/m6-m7-20261006/` under
`native-matched-catalog-files`, `native-catalog-trust-receipts`, and
`native-baseline-catalog-coverage-proof.json`.
