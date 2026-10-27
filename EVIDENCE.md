# Evidence: pqblocks-agility

This file documents the primary specifications, research literature, and mathematical formulas implemented in `pqblocks-agility`, along with direct mappings to the codebase.

## Primary Sources

1. **CARS Framework & Readiness Score Model:**
   - A. D. B. Costa, *Quantum-Safe Cryptography: A Migration Framework for Legacy Systems Toward NIST PQC Standards with the Crypto-Agility Readiness Score*. IACR Cryptology ePrint Archive, Report 2026/1467. https://eprint.iacr.org/2026/1467
   - Defines the 5-dimension readiness score model:
     $$\text{CARS} = 100 \times \left(0.20\, d_1 + 0.25\, d_2 + 0.25\, d_3 + 0.15\, d_4 + 0.15\, d_5\right)$$
   - Weights and dimensions implemented in `pqblocks_agility.cars_scoring` and `pqblocks_agility.cli`.

2. **CycloneDX Bill of Materials Standard, version 1.6:**
   - OWASP Foundation, released April 2024.
   - Schema: `http://cyclonedx.org/schema/bom-1.6.schema.json`
   - Defines the `cryptographic-asset` component type and `cryptoProperties`.
   - Ingested and validated in `pqblocks_agility.cbom`.

3. **Static Analysis Results Interchange Format (SARIF) Version 2.1.0:**
   - OASIS Standard, 27 March 2020.
   - Schema: `https://json.schemastore.org/sarif-2.1.0.json`
   - Rules `CARS-D1` through `CARS-D5` emitted in `pqblocks_agility.sarif_export` and `pqblocks_agility.ci_gate`.

---

## Method to Code Map

| Specification Concept | Implementation in `pqblocks-agility` |
|---|---|
| CBOM Ingestion & Grade Derivation | `pqblocks_agility.cbom.parse_cbom_dict`: Parses CycloneDX 1.6 document; checks `specVersion == "1.6"`; extracts `properties` or derives A–F grades from algorithm names and NIST levels. |
| CARS Formula Evaluation | `pqblocks_agility.cars_scoring.score_cbom`: Computes weighted sum of $d_1..d_5$ using default weights $(0.20, 0.25, 0.25, 0.15, 0.15)$. |
| Profile Specialization | `pqblocks_agility.cli.get_profile_weights`: Provides weight profiles (`default`, `cloud-enterprise`, `embedded-iot`). |
| AST Decoupling Heuristics ($d_3$) | `pqblocks_agility.ast_decoupling.compute_d3`: Computes decoupling ratio from component call site locations and provider abstractions. |
| CI/CD Regression Gate | `pqblocks_agility.ci_gate.evaluate_gate`: Compares CARS against `min_cars` threshold; evaluates git diff for newly introduced quantum-vulnerable cryptography. |
| SARIF 2.1.0 Export | `pqblocks_agility.sarif_export.export_sarif`: Generates OASIS SARIF log with rules `CARS-D1` through `CARS-D5`. |
