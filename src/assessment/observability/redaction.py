"""Agent Security v4.2 — 探针脱敏与哈希模块.

默认策略: raw_capture_enabled=false, 只保存 hash/摘要/长度/字段名。
敏感字段匹配 token|secret|password|key|credential|cookie|authorization|bearer|session。
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

# ── 敏感字段正则 ──────────────────────────────────────────────
SENSITIVE_FIELD_RE = re.compile(
    r"token|secret|password|key|credential|cookie|authorization|bearer|session",
    re.IGNORECASE,
)

MAX_SAMPLE_CHARS = 512
REDACTED_PLACEHOLDER = "[REDACTED]"


def is_sensitive_field(name: str) -> bool:
    """判断字段名是否疑似敏感字段."""
    return bool(SENSITIVE_FIELD_RE.search(name))


def redact_value(value: Any, max_sample: int = MAX_SAMPLE_CHARS) -> str:
    """脱敏任意值: 字符串直接脱敏, 其他类型 JSON 序列化后脱敏."""
    if isinstance(value, str):
        return _redact_string(value, max_sample)
    if isinstance(value, (bytes, bytearray)):
        return _redact_string(value.decode("utf-8", errors="replace"), max_sample)
    try:
        import json
        return _redact_string(json.dumps(value, ensure_ascii=False, default=str), max_sample)
    except Exception:
        return REDACTED_PLACEHOLDER


def _redact_string(text: str, max_sample: int = MAX_SAMPLE_CHARS) -> str:
    """对字符串脱敏: 截断 + 匹配敏感模式替换."""
    if not text:
        return ""
    # 替换常见 secret pattern
    redacted = re.sub(r"(sk-[a-zA-Z0-9]{20,})", REDACTED_PLACEHOLDER, text)
    redacted = re.sub(r"(Bearer\s+)[a-zA-Z0-9\-._~+/]+=*", r"\1" + REDACTED_PLACEHOLDER, redacted)
    redacted = re.sub(r"(password[\s\"'=:]+)[^\s\"',;}\]]{3,}", r"\1" + REDACTED_PLACEHOLDER, redacted, flags=re.IGNORECASE)
    redacted = re.sub(r"(secret[\s\"'=:]+)[^\s\"',;}\]]{3,}", r"\1" + REDACTED_PLACEHOLDER, redacted, flags=re.IGNORECASE)
    redacted = re.sub(r"(api[_-]?key[\s\"'=:]+)[^\s\"',;}\]]{3,}", r"\1" + REDACTED_PLACEHOLDER, redacted, flags=re.IGNORECASE)
    if len(redacted) > max_sample:
        redacted = redacted[:max_sample] + "...[TRUNCATED]"
    return redacted


def stable_hash(text: str) -> str:
    """SHA-256 稳定哈希."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def redact_payload(payload: dict[str, Any], depth: int = 0) -> dict[str, Any]:
    """递归脱敏 payload: 深度不超过 10 层, 敏感字段名自动替换值."""
    if depth > 10:
        return {"_redacted": "max_depth_exceeded"}
    result: dict[str, Any] = {}
    for key, value in payload.items():
        if is_sensitive_field(key):
            result[key] = REDACTED_PLACEHOLDER
        elif isinstance(value, dict):
            result[key] = redact_payload(value, depth + 1)
        elif isinstance(value, list):
            result[key] = [_redact_list_item(v, depth + 1) for v in value[:20]]
            if len(value) > 20:
                result[key].append({"_truncated": len(value) - 20})
        elif isinstance(value, str):
            result[key] = _redact_string(value)
        else:
            result[key] = value
    return result


def _redact_list_item(value: Any, depth: int) -> Any:
    if isinstance(value, dict):
        return redact_payload(value, depth)
    if isinstance(value, str):
        return _redact_string(value)
    return value


def summarize_text(text: str, max_chars: int = 200) -> str:
    """生成文本摘要: 取首尾各一半字符, 中间省略."""
    if not text or len(text) <= max_chars:
        return text
    half = max_chars // 2
    return text[:half] + "...[摘要省略 " + str(len(text) - max_chars) + " 字]..." + text[-half:]


def sample_preview(text: str, max_chars: int = 128) -> str:
    """取前 max_chars 字符作为预览, 用于 UI 展示."""
    if not text:
        return ""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "..."
