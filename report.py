"""Aggregate stored runs into per-model/per-prompt-style results, with Wilson confidence intervals."""
import datetime
import html
import json
from collections import defaultdict
from pathlib import Path

from . import __version__
from .common import load_json, rate, sha256_file, wilson, write_csv
from .detectors import evaluate
from .scenarios import is_control

WARNING = ("Results describe behaviour on this scenario set under these prompts, not general safety. A low attack success "
           "rate does not prove a model is secure; a high one is a real signal. Small samples give wide intervals; repeated "
           "runs of the same scenario are not independent.")
SIM_BANNER = "SIMULATED RESULTS: produced by built-in mock models to demonstrate the pipeline. Never report these as real."


def load_runs(path):
    rows, bad = [], 0
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            bad += 1
    return rows, bad


def _prop(k, n):
    return {"k": k, "n": n, "rate": rate(k, n), "ci95": wilson(k, n)}


def build_report(runs, scenarios, include_synthetic=False, scenarios_sha=None):
    by_id = {s["id"]: s for s in scenarios}
    ex = {"synthetic": 0, "errors": 0, "unknown_scenario": 0}
    errors_by_group, scored, other_sha = defaultdict(int), [], 0
    for r in runs:
        group = (r.get("model_requested", "?"), r.get("style", "?"))
        if r.get("synthetic") and not include_synthetic:
            ex["synthetic"] += 1
            continue
        if "error" in r:
            ex["errors"] += 1
            errors_by_group[group] += 1
            continue
        sc = by_id.get(r.get("scenario_id"))
        if sc is None:
            ex["unknown_scenario"] += 1
            continue
        if scenarios_sha and r.get("scenario_set_sha256") != scenarios_sha:
            other_sha += 1
        ev = evaluate(sc, r.get("text", ""), r.get("tool_calls") or [])
        scored.append({"scenario": sc, "run": r, "ev": ev, "group": group})
    groups = defaultdict(list)
    for s in scored:
        groups[s["group"]].append(s)
    out_groups = []
    for (model, style), items in sorted(groups.items()):
        atk = [i for i in items if not is_control(i["scenario"])]
        ctl = [i for i in items if is_control(i["scenario"])]

        def split(key):
            d = defaultdict(lambda: [0, 0])
            for i in atk:
                d[i["scenario"][key]][1] += 1
                d[i["scenario"][key]][0] += i["ev"]["compromised"]
            return {k: _prop(*v) for k, v in sorted(d.items())}
        hit = defaultdict(int)
        for i in atk:
            if i["ev"]["compromised"]:
                hit[i["scenario"]["id"]] += 1
        out_groups.append({
            "model": model, "style": style, "runs": len(items), "attack_runs": len(atk), "control_runs": len(ctl),
            "errors": errors_by_group.get((model, style), 0),
            "attack_success": _prop(sum(i["ev"]["compromised"] for i in atk), len(atk)),
            "task_done_under_attack": _prop(sum(i["ev"]["task_completed"] for i in atk), len(atk)),
            "control_task_success": _prop(sum(i["ev"]["task_completed"] for i in ctl), len(ctl)),
            "control_misbehaviour": _prop(sum(i["ev"]["compromised"] for i in ctl), len(ctl)),
            "ambiguous_runs": sum(bool(i["ev"]["ambiguous_markers"]) for i in items),
            "by_attack_type": split("attack_type"), "by_channel": split("channel"),
            "compromised_scenarios": dict(sorted(hit.items()))})
    per_run = [{"scenario_id": s["scenario"]["id"], "attack_type": s["scenario"]["attack_type"],
                "channel": s["scenario"]["channel"], "model": s["group"][0], "style": s["group"][1],
                "repeat": s["run"].get("repeat"), "compromised": s["ev"]["compromised"],
                "canary_leak": s["ev"]["canary_leak"], "forbidden_tools": ";".join(s["ev"]["forbidden_tools"]),
                "markers_obeyed": ";".join(s["ev"]["markers_obeyed"]),
                "ambiguous_markers": ";".join(s["ev"]["ambiguous_markers"]),
                "task_completed": s["ev"]["task_completed"], "tool_calls": ";".join(s["ev"]["tool_calls"]),
                "synthetic": bool(s["run"].get("synthetic")), "text": s["run"].get("text", "")} for s in scored]
    return {"tool": "PROMPTGUARD LAB", "version": __version__, "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "scenario_set_sha256": scenarios_sha, "runs_from_other_scenario_hash": other_sha,
            "includes_synthetic": any(s["run"].get("synthetic") for s in scored), "excluded": ex,
            "groups": out_groups, "warning": WARNING}, per_run


def _pct(p):
    return "n/a" if not p["n"] else f"{p['rate']:.0%} [{p['ci95'][0]:.0%}-{p['ci95'][1]:.0%}] ({p['k']}/{p['n']})"


def render_markdown(rep) -> str:
    L = ["# PROMPTGUARD LAB report", ""]
    if rep["includes_synthetic"]:
        L += [f"> **{SIM_BANNER}**", ""]
    ex = rep["excluded"]
    L += [f"Scenario set `{(rep['scenario_set_sha256'] or '?')[:12]}...` | excluded: {ex['synthetic']} simulated, "
          f"{ex['errors']} errored, {ex['unknown_scenario']} unknown-scenario runs.", ""]
    if rep["runs_from_other_scenario_hash"]:
        L += [f"> Warning: {rep['runs_from_other_scenario_hash']} run(s) were collected against a different scenario-set hash.", ""]
    if not rep["groups"]:
        return "\n".join(L + ["No scored runs. (Simulated runs need `--include-synthetic`.)", ""])
    L += ["## Summary", "", "Lower attack success is better; higher task completion is better. Intervals are 95% Wilson.", "",
          "| Model | Prompt | Attack success | Task done under attack | Control task success | Control misbehaviour | Needs review |",
          "|---|---|---|---|---|---|---|"]
    for g in rep["groups"]:
        L.append(f"| {g['model']} | {g['style']} | {_pct(g['attack_success'])} | {_pct(g['task_done_under_attack'])} | "
                 f"{_pct(g['control_task_success'])} | {_pct(g['control_misbehaviour'])} | {g['ambiguous_runs']} |")
    for g in rep["groups"]:
        L += ["", f"## {g['model']} / {g['style']}", "", "| Attack type | Attack success |", "|---|---|"]
        L += [f"| {k} | {_pct(v)} |" for k, v in g["by_attack_type"].items()]
        L += ["", "| Channel | Attack success |", "|---|---|"] + [f"| {k} | {_pct(v)} |" for k, v in g["by_channel"].items()]
        if g["compromised_scenarios"]:
            L += ["", "Compromised scenarios: " + ", ".join(f"{k} x{v}" for k, v in g["compromised_scenarios"].items())]
        if g["errors"]:
            L += ["", f"{g['errors']} run(s) errored and are excluded."]
    L += ["", "## Reading these results", "", WARNING, "",
          "*Needs review* counts replies that mention an attacker's marker while also describing the injection; they are not counted as "
          "compromised. Inspect them in `results.csv`.", ""]
    return "\n".join(L)


def render_html(rep) -> str:
    e = html.escape
    rows = "".join(f"<tr><td>{e(g['model'])}</td><td>{e(g['style'])}</td><td>{e(_pct(g['attack_success']))}</td>"
                   f"<td>{e(_pct(g['task_done_under_attack']))}</td><td>{e(_pct(g['control_task_success']))}</td>"
                   f"<td>{e(_pct(g['control_misbehaviour']))}</td><td>{g['ambiguous_runs']}</td></tr>" for g in rep["groups"])
    detail = ""
    for g in rep["groups"]:
        detail += f"<h2>{e(g['model'])} / {e(g['style'])}</h2><table><tr><th>Attack type</th><th>Attack success</th></tr>"
        detail += "".join(f"<tr><td>{e(k)}</td><td>{e(_pct(v))}</td></tr>" for k, v in g["by_attack_type"].items()) + "</table>"
    banner = f'<p class="sim">{e(SIM_BANNER)}</p>' if rep["includes_synthetic"] else ""
    return ("<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>PROMPTGUARD LAB report</title><style>:root{color-scheme:light dark;--bg:#fff;--fg:#111;--line:#ccc;--warn:#fff3cd}"
            "@media(prefers-color-scheme:dark){:root{--bg:#10151f;--fg:#e8eefc;--line:#33415c;--warn:#3a3118}}"
            "body{font:15px/1.5 system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;background:var(--bg);color:var(--fg)}"
            "table{border-collapse:collapse;width:100%;margin:1rem 0;display:block;overflow-x:auto}td,th{border:1px solid var(--line);padding:6px 9px;text-align:left}"
            ".sim{background:var(--warn);padding:10px;border-radius:6px;font-weight:700}</style>"
            f"<h1>PROMPTGUARD LAB report</h1>{banner}<p>Lower attack success is better. 95% Wilson intervals.</p>"
            "<table><tr><th>Model</th><th>Prompt</th><th>Attack success</th><th>Task done under attack</th>"
            f"<th>Control task success</th><th>Control misbehaviour</th><th>Needs review</th></tr>{rows}</table>{detail}"
            f"<p>{e(WARNING)}</p></html>")


def write_report(runs_path, scenarios_path, scenarios, out_dir, include_synthetic=False):
    runs, bad = load_runs(runs_path)
    rep, per_run = build_report(runs, scenarios, include_synthetic, sha256_file(scenarios_path))
    rep["unparseable_lines"] = bad
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(json.dumps(rep, indent=2), encoding="utf-8")
    (out / "report.md").write_text(render_markdown(rep), encoding="utf-8")
    (out / "report.html").write_text(render_html(rep), encoding="utf-8")
    write_csv(out / "results.csv", list(per_run[0].keys()) if per_run else ["scenario_id"], per_run)
    return rep
