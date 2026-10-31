"""LLM API destinations: their requests are recorded by structure, never by text.

What an agent sends to its LLM provider is the conversation itself (spec section 3.5: raw prompts
are not stored). For these destinations a record holds no text excerpt, only the structure of the
request: provider, ``model`` (the later lab rule needs it), the number of messages and their roles,
tool names, the stream flag, sizes and hashes. In full mode the bodies are in the body store only.

LLM destinations are the built-in hosts below, the ``llm_hosts`` setting and the configured local
inference endpoints (``local_endpoints``).
"""

from __future__ import annotations

import json
import re

from .store import decode_body

# host (or parent domain) -> provider
PROVIDERS = {
    "api.anthropic.com": "anthropic",
    "api.openai.com": "openai", "chatgpt.com": "openai", "openai.azure.com": "azure-openai",
    "generativelanguage.googleapis.com": "google", "aiplatform.googleapis.com": "google",
    "api.mistral.ai": "mistral", "codestral.mistral.ai": "mistral",
    "api.deepseek.com": "deepseek",
    "openrouter.ai": "openrouter",
    "dashscope.aliyuncs.com": "alibaba", "dashscope-intl.aliyuncs.com": "alibaba",
    "api.moonshot.ai": "moonshot", "api.moonshot.cn": "moonshot",
    "api.x.ai": "xai",
    "api.groq.com": "groq",
    "api.together.xyz": "together", "api.together.ai": "together",
    "api.fireworks.ai": "fireworks",
    "api.cohere.com": "cohere", "api.cohere.ai": "cohere",
    "api.perplexity.ai": "perplexity",
    "api.cerebras.ai": "cerebras",
    "api.z.ai": "zhipu", "open.bigmodel.cn": "zhipu",
    "api.minimax.io": "minimax", "api.minimaxi.com": "minimax",
    "router.huggingface.co": "huggingface", "api-inference.huggingface.co": "huggingface",
    "api.githubcopilot.com": "github-copilot",
}
BEDROCK = re.compile(r"bedrock-runtime(-fips)?\.[a-z0-9-]+\.amazonaws\.com")
KEEP_BYTES = 16 * 1024 * 1024      # request bodies up to this size are parsed for their structure
NAME_CHARS = 120


def provider(host: str | None, extra_hosts=()) -> str | None:
    host = (host or "").lower().rstrip(".")
    if not host:
        return None
    for name in (host, *[host.split(".", i)[-1] for i in range(1, host.count("."))]):
        if name in PROVIDERS:
            return PROVIDERS[name]
    if BEDROCK.fullmatch(host):
        return "aws-bedrock"
    if any(host == item or host.endswith("." + item) for item in extra_hosts):
        return "configured"
    return None


def _tool_names(tools) -> list[str]:
    names = []
    for tool in tools if isinstance(tools, list) else []:
        if not isinstance(tool, dict):
            continue
        for declaration in tool.get("functionDeclarations") or tool.get("function_declarations") or []:
            if isinstance(declaration, dict) and isinstance(declaration.get("name"), str):
                names.append(declaration["name"])
        name = tool.get("name") or (tool.get("function") or {}).get("name") or tool.get("type")
        if isinstance(name, str) and not (tool.get("functionDeclarations") or tool.get("function_declarations")):
            names.append(name)
    return [name[:NAME_CHARS] for name in names[:200]]


def structure(raw: bytes, *, complete: bool, encoding: str | None, path: str) -> dict:
    """Provider-neutral structure of an LLM API request body; never its text."""
    out: dict = {}
    data, _ = decode_body(raw, encoding) if complete else (raw, False)
    doc = None
    if complete:
        try:
            doc = json.loads(data)
        except (ValueError, UnicodeDecodeError, RecursionError):
            doc = None
    if isinstance(doc, dict):
        if isinstance(doc.get("model"), str):
            out["model"] = doc["model"][:NAME_CHARS]
        messages = doc.get("messages")
        if not isinstance(messages, list):
            messages = doc.get("contents") if isinstance(doc.get("contents"), list) else None   # Gemini
        if messages is None and isinstance(doc.get("input"), list):                          # Responses API
            messages = doc["input"]
        if messages is not None:
            roles: dict[str, int] = {}
            for message in messages:
                role = message.get("role") or message.get("type") if isinstance(message, dict) else None
                key = role[:40] if isinstance(role, str) else "?"
                roles[key] = roles.get(key, 0) + 1
            out["messages"] = len(messages)
            out["roles"] = roles
        if doc.get("system") or doc.get("instructions") or doc.get("systemInstruction"):
            out["system"] = True
        if "tools" in doc:
            names = _tool_names(doc["tools"])
            out["tools"] = names
        if isinstance(doc.get("stream"), bool):
            out["stream"] = doc["stream"]
    if "model" not in out:
        match = re.search(rb'"model"\s*:\s*"([^"\\]{1,120})"', bytes(data[:65536]))
        if match:
            out["model"] = match.group(1).decode("utf-8", "replace")
    if "model" not in out:
        match = re.search(r"/models/([^/:?]{1,120})", path or "")              # Gemini: /v1beta/models/<model>:...
        if match:
            out["model"] = match.group(1)
    out["parsed"] = doc is not None
    return out
