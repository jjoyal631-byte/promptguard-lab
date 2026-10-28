"""Collect raw model outputs with full provenance. Scoring happens later, in the report step."""
import datetime
import json
from pathlib import Path

from .common import sha256_file, sha256_text
from .prompts import PROMPT_VERSION, TOOLS, build_messages
from .providers import OpenAICompatible, ProviderError


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def identity(rec) -> tuple:
    return (rec.get("scenario_id"), rec.get("style"), rec.get("repeat"), rec.get("model_requested"),
            rec.get("scenario_set_sha256"), rec.get("prompt_version"))


def done_identities(out: Path) -> set:
    keys = set()
    if out.exists():
        for line in out.read_text(encoding="utf-8").splitlines():
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "error" not in r:
                keys.add(identity(r))
    return keys


def run_experiment(provider, scenarios, styles, repeats, out, scenarios_path, resume=True, log=print):
    """Run every (scenario, style, repeat); append one JSON line per attempt. Returns counts."""
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    sha = sha256_file(scenarios_path)
    done = done_identities(out) if resume else set()
    n = {"collected": 0, "skipped": 0, "failed": 0}
    with out.open("a", encoding="utf-8") as f:
        for sc in scenarios:
            for style in styles:
                for rep in range(repeats):
                    base = {"scenario_id": sc["id"], "style": style, "repeat": rep, "provider_kind": provider.kind,
                            "model_requested": provider.model_requested, "synthetic": provider.synthetic,
                            "scenario_set_sha256": sha, "prompt_version": PROMPT_VERSION}
                    if identity(base) in done:
                        n["skipped"] += 1
                        continue
                    messages, start = build_messages(sc, style), utcnow()
                    try:
                        r = provider.chat(messages, TOOLS, {"scenario": sc, "style": style})
                        rec = {**base, "model_returned": r["model"], "started_at": start, "finished_at": utcnow(),
                               "attempts": r["attempts"], "temperature": getattr(provider, "temperature", None),
                               "prompt_sha256": sha256_text(json.dumps(messages, sort_keys=True)),
                               "messages": messages, "text": r["text"], "tool_calls": r["tool_calls"],
                               "usage": r["usage"], "response_id": r["response_id"]}
                        n["collected"] += 1
                    except (ProviderError, OSError, ValueError) as e:  # urllib errors subclass OSError
                        rec = {**base, "started_at": start, "error_type": type(e).__name__, "error": str(e)}
                        n["failed"] += 1
                        log(f"{sc['id']} [{style}#{rep}]: ERROR {type(e).__name__}: {e}")
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    f.flush()
    return n
