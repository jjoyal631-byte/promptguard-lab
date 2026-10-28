"""Scenario schema, loading and validation."""
import re

from .common import SCENARIOS_PATH, HASH_PATH, load_json, recorded_hash, sha256_file

CHANNELS = ("email", "web_page", "document", "pdf_text", "tool_output", "code_comment",
            "calendar_invite", "support_ticket", "user_review", "chat_message")
ATTACK_TYPES = ("instruction_override", "data_exfiltration", "tool_abuse", "role_hijack", "hidden_text",
                "encoding_obfuscation", "authority_impersonation", "delimiter_escape", "output_manipulation")
CONTROL = "none"
SEVERITIES = ("low", "medium", "high")
TOOL_NAMES = ("send_email", "http_post", "delete_file", "create_calendar_event")


def load_scenarios(path=SCENARIOS_PATH):
    return load_json(path)


def is_control(s) -> bool:
    return s.get("attack_type") == CONTROL


def validate(rows) -> list:
    errors = []
    if not isinstance(rows, list) or not rows:
        return ["top level must be a non-empty array"]
    ids, canaries = set(), set()
    for i, s in enumerate(rows):
        if not isinstance(s, dict):
            errors.append(f"row {i}: not an object")
            continue
        sid = s.get("id")
        tag = sid if isinstance(sid, str) else f"row {i}"
        if not isinstance(sid, str) or not re.fullmatch(r"PG\d{3}", sid):
            errors.append(f"{tag}: id must look like PG001")
        if sid in ids:
            errors.append(f"{tag}: duplicate id")
        ids.add(sid)
        for k in ("title", "task", "untrusted_content", "canary"):
            if not isinstance(s.get(k), str) or not s[k].strip():
                errors.append(f"{tag}: '{k}' must be a non-empty string")
        if s.get("channel") not in CHANNELS:
            errors.append(f"{tag}: channel must be one of {list(CHANNELS)}")
        if s.get("attack_type") not in ATTACK_TYPES + (CONTROL,):
            errors.append(f"{tag}: attack_type must be one of {list(ATTACK_TYPES) + [CONTROL]}")
        if s.get("severity") not in SEVERITIES:
            errors.append(f"{tag}: severity must be one of {list(SEVERITIES)}")
        c = s.get("canary")
        if isinstance(c, str):
            if c in canaries:
                errors.append(f"{tag}: canary reused")
            canaries.add(c)
            if c.lower() in str(s.get("untrusted_content", "")).lower():
                errors.append(f"{tag}: canary appears in the untrusted content (detection would be trivial)")
        kw = s.get("task_keywords")
        if not isinstance(kw, list) or not kw or any(not isinstance(k, str) or not k or k != k.lower() for k in kw):
            errors.append(f"{tag}: task_keywords must be a non-empty list of lowercase strings")
        a = s.get("attack")
        if not isinstance(a, dict):
            errors.append(f"{tag}: 'attack' must be an object")
            continue
        if not isinstance(a.get("targets_canary"), bool):
            errors.append(f"{tag}: attack.targets_canary must be boolean")
        tools, markers = a.get("forbidden_tools"), a.get("markers")
        if not isinstance(tools, list) or not isinstance(markers, list):
            errors.append(f"{tag}: attack.forbidden_tools and attack.markers must be arrays")
            continue
        for t in tools:
            if not isinstance(t, dict) or t.get("name") not in TOOL_NAMES + ("*",):
                errors.append(f"{tag}: forbidden tool must name one of {list(TOOL_NAMES)} or '*'")
        if any(not isinstance(m, str) or not m for m in markers):
            errors.append(f"{tag}: markers must be non-empty strings")
        if s.get("attack_type") == CONTROL:
            if a["targets_canary"] or markers or tools != [{"name": "*"}]:
                errors.append(f"{tag}: a control must have no markers, targets_canary false, and forbid any tool ('*')")
        elif not (a["targets_canary"] or tools or markers):
            errors.append(f"{tag}: an attack scenario needs at least one detector")
        else:
            for m in markers:  # the marker should not be what a good answer would naturally contain
                if any(m.lower() in k for k in kw):
                    errors.append(f"{tag}: marker overlaps with a task keyword")
    return errors


def check_hash(path=SCENARIOS_PATH):
    rec, act = recorded_hash(HASH_PATH), sha256_file(path)
    if rec is None:
        return [f"no SHA-256 found in {HASH_PATH}"]
    if rec != act:
        return [f"scenario SHA-256 changed: recorded {rec[:12]}..., actual {act[:12]}... "
                "(run `python -m promptguard validate --write-hash` if the edit was intentional)"]
    return []
