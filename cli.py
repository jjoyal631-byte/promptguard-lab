"""Command line interface: python -m promptguard <command>."""
import argparse
import os
import sys
from collections import Counter

from . import __version__
from .common import SCENARIOS_PATH, HASH_PATH, sha256_file
from .prompts import STYLES, build_messages
from .providers import MOCK_POLICIES, MockProvider, OpenAICompatible
from .report import write_report
from .runner import run_experiment
from .scenarios import check_hash, is_control, load_scenarios, validate


def _select(scenarios, ids, limit):
    if ids:
        wanted = [i.strip() for i in ids.split(",") if i.strip()]
        unknown = set(wanted) - {s["id"] for s in scenarios}
        if unknown:
            raise SystemExit(f"Unknown scenario IDs: {sorted(unknown)}")
        scenarios = [s for s in scenarios if s["id"] in wanted]
    return scenarios[:limit] if limit else scenarios


def cmd_list(a):
    rows = load_scenarios(a.scenarios)
    for s in rows:
        print(f"{s['id']}  {s['attack_type']:<22} {s['channel']:<16} {s['severity']:<7} {s['title']}")
    c = Counter(s["attack_type"] for s in rows)
    print(f"\n{len(rows)} scenarios ({sum(v for k, v in c.items() if k != 'none')} attacks, {c.get('none', 0)} controls)")


def cmd_validate(a):
    errs = validate(load_scenarios(a.scenarios))
    if errs:
        print("\n".join("ERROR " + e for e in errs))
        return 1
    if a.write_hash:
        HASH_PATH.write_text(f"SHA-256 data/scenarios.json: {sha256_file(a.scenarios)}\nRecompute after intentional scenario edits "
                             "(python -m promptguard validate --write-hash); never compare runs across different hashes without noting the change.\n",
                             encoding="utf-8")
        print("Recorded hash", sha256_file(a.scenarios))
        return 0
    if a.check_hash:
        errs = check_hash(a.scenarios)
        if errs:
            print("\n".join("ERROR " + e for e in errs))
            return 1
    print(f"Valid scenario set: {len(load_scenarios(a.scenarios))} scenarios")
    return 0


def cmd_prompt(a):
    sc = next((s for s in load_scenarios(a.scenarios) if s["id"] == a.scenario_id), None)
    if not sc:
        raise SystemExit(f"Unknown scenario {a.scenario_id}")
    for m in build_messages(sc, a.style):
        print(f"--- {m['role']} ---\n{m['content']}\n")


def cmd_run(a):
    scenarios = _select(load_scenarios(a.scenarios), a.scenario_ids, a.limit)
    styles = [s.strip() for s in a.styles.split(",")]
    bad = set(styles) - set(STYLES)
    if bad:
        raise SystemExit(f"Unknown prompt styles {sorted(bad)}; choose from {list(STYLES)}")
    if a.repeats < 1:
        raise SystemExit("--repeats must be >= 1")
    if a.dry_run:
        for sc in scenarios:
            for st in styles:
                print(f"=== {sc['id']} [{st}] ===")
                for m in build_messages(sc, st):
                    print(f"--- {m['role']} ---\n{m['content']}\n")
        print(f"Dry run: {len(scenarios)} scenarios x {len(styles)} styles x {a.repeats} repeats = "
              f"{len(scenarios) * len(styles) * a.repeats} requests. No network used.")
        return 0
    if a.provider.startswith("mock:"):
        provider = MockProvider(a.provider.split(":", 1)[1])
    elif a.provider == "openai":
        base, key, model = (os.environ.get(k, "") for k in ("OPENAI_BASE_URL", "OPENAI_API_KEY", "OPENAI_MODEL"))
        if not (base and key and model):
            raise SystemExit("Set OPENAI_BASE_URL, OPENAI_API_KEY and OPENAI_MODEL (check provider pricing first), "
                             "or use --provider mock:naive for a free simulated run, or --dry-run.")
        provider = OpenAICompatible(base, key, model, a.temperature, a.max_tokens, a.timeout, a.retries, a.backoff)
    else:
        raise SystemExit(f"--provider must be 'openai' or 'mock:<{'|'.join(MOCK_POLICIES)}>'")
    n = run_experiment(provider, scenarios, styles, a.repeats, a.out, a.scenarios, resume=not a.no_resume)
    print(f"Finished: {n['collected']} collected, {n['skipped']} skipped, {n['failed']} failed. Raw output in {a.out}.")
    if provider.synthetic:
        print("These are SIMULATED results; the report excludes them unless you pass --include-synthetic.")
    return 1 if n["failed"] else 0


def cmd_report(a):
    scenarios = load_scenarios(a.scenarios)
    rep = write_report(a.runs, a.scenarios, scenarios, a.out, a.include_synthetic)
    ex = rep["excluded"]
    print(f"Wrote {a.out}/report.md, report.html, summary.json, results.csv "
          f"({len(rep['groups'])} model/prompt groups; excluded {ex['synthetic']} simulated, {ex['errors']} errored)")
    if not rep["groups"] and ex["synthetic"]:
        print("All runs were simulated. Add --include-synthetic to demonstrate the report (never publish those numbers).")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="promptguard", description="Prompt-injection resistance test bench.")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--scenarios", default=str(SCENARIOS_PATH))
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list").set_defaults(fn=cmd_list)
    v = sub.add_parser("validate"); v.add_argument("--check-hash", action="store_true"); v.add_argument("--write-hash", action="store_true")
    v.set_defaults(fn=cmd_validate)
    pr = sub.add_parser("prompt"); pr.add_argument("scenario_id"); pr.add_argument("--style", default="plain", choices=STYLES)
    pr.set_defaults(fn=cmd_prompt)
    r = sub.add_parser("run", help="collect raw outputs from a model")
    r.add_argument("--provider", default="openai", help="'openai' (env-configured) or mock:<policy>")
    r.add_argument("--styles", default="plain,delimited", help="comma list from: " + ",".join(STYLES))
    r.add_argument("--repeats", type=int, default=1); r.add_argument("--limit", type=int, default=0, help="max scenarios (0 = all)")
    r.add_argument("--scenario-ids"); r.add_argument("--out", default="results/runs.jsonl")
    r.add_argument("--temperature", type=float, default=0.0); r.add_argument("--max-tokens", type=int)
    r.add_argument("--timeout", type=float, default=90); r.add_argument("--retries", type=int, default=3)
    r.add_argument("--backoff", type=float, default=2.0)
    r.add_argument("--no-resume", action="store_true"); r.add_argument("--dry-run", action="store_true")
    r.set_defaults(fn=cmd_run)
    rp = sub.add_parser("report", help="score stored runs and write a report")
    rp.add_argument("--runs", default="results/runs.jsonl"); rp.add_argument("--out", default="results/report")
    rp.add_argument("--include-synthetic", action="store_true"); rp.set_defaults(fn=cmd_report)
    a = p.parse_args(argv)
    return a.fn(a) or 0


if __name__ == "__main__":
    sys.exit(main())
