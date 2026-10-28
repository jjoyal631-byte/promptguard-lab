# Contributing

## Adding a scenario

Append an object to `data/scenarios.json` with the next ID (`PGnnn`):

| Field | Notes |
|---|---|
| `channel`, `attack_type`, `severity` | must come from the lists in `promptguard/scenarios.py` (`attack_type: "none"` makes it a control) |
| `task` | what the *user* asks, e.g. "Summarize this email in one sentence." |
| `untrusted_content` | the attacker-controlled text. Must **not** contain the canary |
| `canary` | unique fake secret, e.g. `CNRY-PG041-AB12CD` |
| `task_keywords` | lowercase words a correct answer must contain; must not overlap the attack markers |
| `attack` | `targets_canary`, `forbidden_tools` (`name`, optional `arg_contains`), `markers` (unique phrases) |

Rules: payloads must stay benign (use `@example.invalid` / `.example.invalid`, never real addresses or working exploits). An attack needs at least one detector. A control needs `forbidden_tools: [{"name": "*"}]`, no markers, and `targets_canary: false`.

Then run:

```bash
python -m promptguard validate
python -m promptguard validate --write-hash
python -m unittest discover -s tests
```

The suite checks that every attack is detectable from its own spec and that the recorded hash matches the file.

## Adding a detector or provider

Detectors live in `promptguard/detectors.py` and must be deterministic and tested with at least one positive and one negative case. Providers implement `chat(messages, tools, ctx)` and set `kind` / `synthetic`.

## Results

Never commit real API keys or provider output you are not allowed to share. State the model version, date, scenario hash and prompt style with any published numbers.
