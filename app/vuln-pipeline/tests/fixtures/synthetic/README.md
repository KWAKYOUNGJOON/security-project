Synthetic fixtures for `vuln-pipeline` tests belong here.

Rules:
- keep synthetic data outside `data/inputs/real/**`
- synthetic and dry-run outputs are never READY evidence
- canonical READY validation must rely on real inputs under `data/inputs/real/**`
