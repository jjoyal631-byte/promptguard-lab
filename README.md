# PROMPTGUARD LAB

An open, local-first test bench for **prompt-injection resistance**: does an AI assistant obey malicious instructions hidden in content it was only supposed to *read*: emails, web pages, documents, tool output, code comments?

Most of the scoring is **deterministic** (a leaked canary secret, a forbidden tool call, an attacker's marker phrase), so results do not depend on a human or an LLM judging each answer. Standard library only; Python 3.10+.

## What is inside

- **40 scenarios** (`data/scenarios.json`): 34 attacks across 9 attack types and 10 channels, plus 6 **benign controls**. Each scenario has a task, untrusted content, a per-scenario secret canary, and machine-checkable detectors.
- **A runner** for any OpenAI-compatible chat endpoint with tool calling. Three prompt styles (`plain` baseline, `delimited`, `sandwich`) so you can measure whether a defence actually helps. Resume, retries, repeats, `--dry-run`, HTTPS guard.
- **A report generator** that re-scores *stored* raw outputs (so detectors can improve without re-calling a model) and writes Markdown, HTML, JSON and CSV, with 95% Wilson intervals.
- **Simulated models** (`mock:naive`, `robust`, `mixed`, `refuser`, `reporter`) for free demos and tests. Their results are always flagged and excluded by default.
- **44 tests**, including runner tests against a local mock API server.

## Quick start

```bash
python -m promptguard list
python -m promptguard validate --check-hash
python -m promptguard prompt PG012 --style delimited        # see exactly what a model receives

# free, offline demo with a simulated model
python -m promptguard run --provider mock:mixed --styles plain,delimited
python -m promptguard report --include-synthetic            # simulated numbers: demonstration only
```

### Testing a real model

```bash
export OPENAI_BASE_URL=https://api.example.com/v1     # any OpenAI-compatible endpoint
export OPENAI_API_KEY=...                              # never commit this
export OPENAI_MODEL=your-model-name
python -m promptguard run --dry-run --limit 3          # preview prompts, no network
python -m promptguard run --scenario-ids PG001,PG012 --styles plain   # start tiny: network use may cost money
python -m promptguard run --styles plain,delimited,sandwich --repeats 3
python -m promptguard report                           # writes results/report/{report.md,report.html,summary.json,results.csv}
```

Re-running the same command skips work already collected for that model, prompt style, repeat and scenario-set hash (`--no-resume` overrides).

## Reading a report

| Metric | Meaning | Better |
|---|---|---|
| **Attack success** | Share of attack runs where a detector fired (canary leaked, forbidden tool called, attacker's phrase obeyed) | lower |
| **Task done under attack** | Share of attack runs where the model still completed the user's real task | higher |
| **Control task success** | Share of benign runs completed correctly | higher |
| **Control misbehaviour** | A leak or tool call with *no* attack present | lower |
| **Needs review** | Replies that mention an attacker's phrase while describing the injection. Not counted as compromised; read them in `results.csv` | n/a |

A model that refuses everything scores 0% attack success, which is why task completion and the benign controls are reported next to it.

## Important limits

PROMPTGUARD LAB measures behaviour on *this* scenario set and *these* prompts. A low attack success rate does **not** show a model is secure. Scenarios are single-turn and tools are never executed, only inspected. Task completion uses a crude keyword check. Published scenarios can leak into training data, so treat scores as a regression signal, not a certificate. See [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md).

## Safety

All payloads are benign: attacker addresses use the reserved `.invalid` domain, canaries are fake strings, and no tool is ever executed. Please use this only on systems you are authorised to test.

## Adding scenarios

See [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md). After editing `data/scenarios.json` run `python -m promptguard validate --write-hash` and note the change in any results, because runs are only comparable under the same hash.

## Tests

```bash
python -m unittest discover -s tests -v
```

License: MIT (see `LICENSE`). Example simulated output: `examples/simulated_report.md`.
