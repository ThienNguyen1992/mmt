"""Foreground process inspection and mapping to policy app groups."""

from __future__ import annotations

import os
import sys
from typing import Any


def get_foreground_process_name() -> str | None:
    """Return lowercase executable name of the foreground window (e.g. 'chrome.exe')."""
    if sys.platform != "win32":
        return None
    try:
        import psutil
        import win32gui
        import win32process

        hwnd = win32gui.GetForegroundWindow()
        if not hwnd:
            return None
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        if not pid or pid <= 0:
            return None
        proc = psutil.Process(pid)
        return proc.name().lower()
    except Exception:
        return None


def _extract_content(policy_or_enforcer: dict[str, Any] | Any) -> dict[str, Any]:
    if isinstance(policy_or_enforcer, dict):
        if isinstance(policy_or_enforcer.get("policy"), dict):
            return policy_or_enforcer["policy"]
        return policy_or_enforcer
    get_content_fn = getattr(policy_or_enforcer, "get_content", None)
    if callable(get_content_fn):
        return get_content_fn() or {}
    return {}


def get_foreground_app_group(
    policy_or_enforcer: dict[str, Any] | Any,
    override_process_name: str | None = None,
) -> tuple[str | None, str | None]:
    """Return ``(process_name, group)`` for the current foreground app."""
    proc_name = override_process_name or get_foreground_process_name()
    if not proc_name:
        return None, None

    proc_lower = proc_name.strip().lower()
    proc_base = os.path.basename(proc_lower)
    proc_stem = proc_base[:-4] if proc_base.endswith(".exe") else proc_base

    content = _extract_content(policy_or_enforcer)
    app_rules = content.get("app_rules") or {}
    rules = app_rules.get("rules") or []

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        match_type = str(rule.get("match_type", "name")).lower()
        val = str(rule.get("value", "")).strip().lower()
        if not val:
            continue
        val_stem = val[:-4] if val.endswith(".exe") else val

        matched = False
        if match_type == "name":
            matched = proc_base == val or proc_stem == val_stem
        elif match_type == "path":
            matched = val in proc_lower
        elif match_type == "hash":
            matched = proc_lower == val

        if matched:
            return proc_base, str(rule.get("group") or "other")

    return proc_base, "other"
