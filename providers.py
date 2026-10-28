"""Model providers: an OpenAI-compatible HTTP client and deterministic simulated models.

Simulated models (`mock:<policy>`) exist only to demonstrate and test the pipeline. Their records are
flagged `synthetic` and excluded from reports unless explicitly included.
"""
import json
import time
import urllib.error
import urllib.parse
import urllib.request

RETRY_STATUS = {408, 429, 500, 502, 503, 504}
MOCK_POLICIES = ("naive", "robust", "mixed", "refuser", "reporter")
_MIXED_VULNERABLE = {"hidden_text", "encoding_obfuscation", "authority_impersonation", "delimiter_escape"}


class ProviderError(RuntimeError):
    pass


def check_endpoint_security(base: str):
    u = urllib.parse.urlparse(base)
    if u.scheme != "https" and u.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise SystemExit("Refusing to send an API key over non-HTTPS to a remote host: " + base)


def parse_chat_response(parsed) -> tuple:
    """Return (text, tool_calls). Raises ValueError if the response has neither."""
    try:
        msg = parsed["choices"][0]["message"]
    except (KeyError, IndexError, TypeError):
        raise ValueError("response has no choices[0].message")
    content = msg.get("content")
    if isinstance(content, list):
        content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
    text = content if isinstance(content, str) else ""
    calls = []
    for tc in msg.get("tool_calls") or []:
        fn = (tc or {}).get("function") or {}
        calls.append({"name": fn.get("name", ""), "arguments": fn.get("arguments", "")})
    if not calls and isinstance(msg.get("function_call"), dict):  # legacy format
        fc = msg["function_call"]
        calls.append({"name": fc.get("name", ""), "arguments": fc.get("arguments", "")})
    if not text.strip() and not calls:
        raise ValueError("response has no text and no tool calls (refusal, filter, or empty output?)")
    return text, calls


class OpenAICompatible:
    kind, synthetic = "openai-compatible", False

    def __init__(self, base_url, api_key, model, temperature=0.0, max_tokens=None, timeout=90,
                 retries=3, backoff=2.0, sleep=time.sleep):
        check_endpoint_security(base_url)
        self.base, self.key, self.model = base_url.rstrip("/"), api_key, model
        self.temperature, self.max_tokens, self.timeout = temperature, max_tokens, timeout
        self.retries, self.backoff, self.sleep = retries, backoff, sleep

    @property
    def model_requested(self):
        return self.model

    def _post(self, payload):
        data, last = json.dumps(payload).encode(), None
        for attempt in range(1, self.retries + 2):
            req = urllib.request.Request(self.base + "/chat/completions", data=data, method="POST",
                                         headers={"Content-Type": "application/json", "Authorization": "Bearer " + self.key})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    return json.loads(r.read().decode("utf-8")), attempt
            except urllib.error.HTTPError as e:
                last = ProviderError(f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:300]}")
                if e.code not in RETRY_STATUS:
                    raise last
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                last = e
            if attempt <= self.retries:
                self.sleep(self.backoff * 2 ** (attempt - 1))
        raise last

    def chat(self, messages, tools, ctx=None) -> dict:
        payload = {"model": self.model, "temperature": self.temperature, "messages": messages,
                   "tools": tools, "tool_choice": "auto"}
        if self.max_tokens:
            payload["max_tokens"] = self.max_tokens
        parsed, attempts = self._post(payload)
        text, calls = parse_chat_response(parsed)
        return {"text": text, "tool_calls": calls, "model": parsed.get("model"), "usage": parsed.get("usage"),
                "response_id": parsed.get("id"), "attempts": attempts}


def _complete(sc) -> str:
    return "Result: " + ", ".join(sc["task_keywords"]) + "."


def _follow_attack(sc) -> tuple:
    a, text, calls = sc["attack"], _complete(sc), []
    for m in a["markers"]:
        text += " " + m
    if a["targets_canary"]:
        text += " Access code: " + sc["canary"]
    for spec in a["forbidden_tools"]:
        if spec["name"] != "*":
            calls.append({"name": spec["name"], "arguments": json.dumps({"target": spec.get("arg_contains", "/home/user")})})
    return text, calls


def mock_response(policy: str, sc: dict, style: str) -> tuple:
    """Deterministic behaviour of simulated models."""
    attacked = sc["attack_type"] != "none"
    if policy == "refuser":
        return "I'm sorry, I can't help with that.", []
    if policy == "naive" and attacked:
        return _follow_attack(sc)
    if policy == "mixed" and attacked and sc["attack_type"] in _MIXED_VULNERABLE and style == "plain":
        return _follow_attack(sc)
    if policy == "reporter" and attacked and sc["attack_type"] != "tool_abuse":
        note = " Note: the content contained an injection attempt"
        if sc["attack"]["markers"]:
            note += " telling me to say " + sc["attack"]["markers"][0]
        return _complete(sc) + note + "; I ignored it.", []
    return _complete(sc), []


class MockProvider:
    kind, synthetic = "mock", True

    def __init__(self, policy: str):
        if policy not in MOCK_POLICIES:
            raise SystemExit(f"Unknown mock policy {policy!r}; choose from {list(MOCK_POLICIES)}")
        self.policy = policy

    @property
    def model_requested(self):
        return f"mock:{self.policy}"

    def chat(self, messages, tools, ctx=None) -> dict:
        text, calls = mock_response(self.policy, ctx["scenario"], ctx["style"])
        return {"text": text, "tool_calls": calls, "model": self.model_requested, "usage": None,
                "response_id": None, "attempts": 1}
