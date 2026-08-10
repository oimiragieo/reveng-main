# Sol verdict — Wave 5 stale-map fingerprint transfer

**Reviewed HEAD SHA:** TBD  
**Plan:** `docs/superpowers/plans/2026-08-09-wave5-stale-map-fingerprint.md`  
**Packet:** `docs/architecture/sol-wave5-stale-map-packet.md`

## Protocol note (L47)

- tip1: content under audit with stub `Reviewed HEAD SHA: TBD`.
- tip2: one commit that pins tip1’s SHA into **Reviewed HEAD SHA** above (pin only).
- Sol audits **tip2** SHA. Final PASS / PASS_WITH_NITS / FAIL lives in the **PR comment** (external receipt). This committed file is the tip pin + stub only — it must not claim to contain Sol’s verdict for tip2’s own SHA.
