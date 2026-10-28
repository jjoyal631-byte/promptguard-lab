# Changelog

## 1.0.0
- 40 scenarios (34 attacks, 9 attack types, 10 channels; 6 benign controls) with a recorded SHA-256.
- Deterministic detectors: canary leak, forbidden tool call, attacker marker (with a needs-review bucket).
- Runner for OpenAI-compatible endpoints: prompt styles, repeats, resume, retries, dry-run, HTTPS guard.
- Report: Markdown, HTML, JSON, CSV; Wilson intervals; per attack type and channel; simulated runs excluded by default.
- Simulated models for offline demos and tests.
- 44 tests, including a local mock API server and a self-consistency check that every attack is detectable from its own spec.
