# Spikes

Raw research notes, captured payloads and measurements from Phase 0 (and later). Conclusions belong in an ADR.

Naming: `NN-topic.md`, e.g. `01-hook-payloads.md`, `02-lean-ctx-hook.md`, `03-dep-sizes.md`.

Rules:
- Captured hook payloads must be generated with canaries (`KEYGENT_CANARY_<random>`), never real values.
- Note the tool versions and the date at the top of each file.
- Throwaway spike code lives in `spikes/<name>/` (gitignored target dirs) and never in `src/`.
