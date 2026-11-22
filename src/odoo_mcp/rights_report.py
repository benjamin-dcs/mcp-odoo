"""Opt-in log of the Odoo user's model rights, and model_acl's impact on them.

Enabled with ``ODOO_MCP_LOG_RIGHTS=1``. Once per instance, on the first
connection, the server logs two separate reports:

1. **Odoo rights**: what the connected Odoo user may do per model, exactly as
   Odoo grants it through ``ir.model.access`` rows for the user's groups
   (read / write / create / unlink). No model_acl interpretation.
2. **model_acl impact**: for the models the user has Odoo rights on, which of
   those operations model_acl blocks, plus the methods named in model_acl
   rules for that model.

Summaries go to INFO, per-model lines to DEBUG (``ODOO_MCP_LOG_LEVEL=DEBUG``).
Record rules (row-level filters) are not part of this report. A failure to
collect the data is logged as a warning and never affects the server.
"""

from __future__ import annotations

import fnmatch
import logging
import os
import threading
from typing import Any, Dict, List, Optional, Tuple

from .access_helpers import (
    _acl_row_applies,
    _available_user_read_fields,
    _field_names,
    _group_field_names,
    _m2m_ids,
    _m2o_id,
)
from .model_policy import METHOD_GROUPS, ModelPolicy, get_model_policy, metadata_scope

logger = logging.getLogger(__name__)

RIGHTS_ENV = "ODOO_MCP_LOG_RIGHTS"
OPERATIONS: Tuple[Tuple[str, str], ...] = (
    ("read", "perm_read"),
    ("write", "perm_write"),
    ("create", "perm_create"),
    ("unlink", "perm_unlink"),
)
_OTHER_METHOD_PROBE = "__odoo_mcp_any_other_method__"

_logged_instances: set[str] = set()
_logged_lock = threading.Lock()


def rights_logging_enabled() -> bool:
    return os.environ.get(RIGHTS_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# Pure computation
# ---------------------------------------------------------------------------


def odoo_model_rights(
    model_names: Dict[int, str],
    acl_rows: List[Dict[str, Any]],
    user_group_ids: Optional[set[int]],
) -> Dict[str, List[str]]:
    """Per model, the operations Odoo grants the user (union over applicable rows).

    A row applies when it has no group (global) or its group is one of the
    user's groups. Models without any granted operation are omitted.
    """
    granted: Dict[str, set[str]] = {}
    for row in acl_rows:
        if not isinstance(row, dict) or not row.get("active", True):
            continue
        if not _acl_row_applies(row, user_group_ids):
            continue
        model = model_names.get(_m2o_id(row.get("model_id")) or 0)
        if not model:
            continue
        ops = granted.setdefault(model, set())
        for op, perm in OPERATIONS:
            if row.get(perm):
                ops.add(op)
    return {
        model: [op for op, _ in OPERATIONS if op in ops]
        for model, ops in sorted(granted.items())
        if ops
    }


def model_acl_impact(
    policy: ModelPolicy, instance: str, rights: Dict[str, List[str]]
) -> Optional[Dict[str, Dict[str, Any]]]:
    """Per model with Odoo rights: operations kept/blocked by model_acl.

    Also lists the methods named in rules matching the model (exact names and
    globs, not groups or ``*``) and whether other, unnamed methods are allowed.
    Returns None when model_acl has no policy for this instance.
    """
    acl = policy.instance_acl(instance)
    if acl is None:
        return None
    impact: Dict[str, Dict[str, Any]] = {}
    for model, ops in rights.items():
        kept = [op for op in ops if policy.decide(instance, model, op).allowed]
        blocked = [op for op in ops if op not in kept]
        named: Dict[str, bool] = {}
        for rule in acl.rules:
            if rule.method in METHOD_GROUPS or rule.method == "*":
                continue
            if rule.method in dict(OPERATIONS):
                continue
            if fnmatch.fnmatchcase(model, rule.model_glob) and rule.method not in named:
                named[rule.method] = policy.decide(instance, model, rule.method).allowed
        impact[model] = {
            "kept": kept,
            "blocked": blocked,
            "methods": dict(sorted(named.items())),
            "other_methods": policy.decide(instance, model, _OTHER_METHOD_PROBE).allowed,
        }
    return impact


def format_odoo_rights(rights: Dict[str, List[str]]) -> List[str]:
    return [f"{model}: {' '.join(ops)}" for model, ops in rights.items()]


def format_acl_impact(impact: Dict[str, Dict[str, Any]]) -> List[str]:
    lines: List[str] = []
    for model, entry in impact.items():
        if not entry["kept"] and not any(entry["methods"].values()) and not entry["other_methods"]:
            lines.append(f"{model}: all blocked")
            continue
        parts = [" ".join(entry["kept"]) or "no CRUD"]
        if entry["blocked"]:
            parts.append(f"blocked: {' '.join(entry['blocked'])}")
        if entry["methods"]:
            parts.append(
                "methods: "
                + " ".join(
                    f"{name} {'allowed' if ok else 'blocked'}"
                    for name, ok in entry["methods"].items()
                )
            )
        parts.append(f"other methods {'allowed' if entry['other_methods'] else 'blocked'}")
        lines.append(f"{model}: " + " | ".join(parts))
    return lines


def _counts(rights: Dict[str, List[str]]) -> str:
    return ", ".join(
        f"{sum(1 for ops in rights.values() if op in ops)} {op}" for op, _ in OPERATIONS
    )


# ---------------------------------------------------------------------------
# Collection (Odoo metadata calls, exempt from model_acl like other lookups)
# ---------------------------------------------------------------------------


def collect_odoo_rights(client: Any) -> Tuple[Dict[str, Any], Dict[str, List[str]]]:
    """Query the user's groups, ir.model and ir.model.access; return (user, rights)."""
    with metadata_scope():
        context = client.get_user_context() if hasattr(client, "get_user_context") else {}
        uid = getattr(client, "uid", None)
        if uid is None and isinstance(context, dict):
            uid = context.get("uid")
        user: Dict[str, Any] = {"uid": uid, "login": getattr(client, "username", None)}
        group_ids: Optional[set[int]] = None
        if isinstance(uid, int) and uid > 0:
            user_fields = client.execute_method(
                "res.users", "fields_get", [], attributes=["type"]
            )
            rows = client.execute_method(
                "res.users",
                "read",
                [uid],
                fields=_available_user_read_fields(_field_names(user_fields)),
            )
            if rows:
                direct_field, all_field = _group_field_names(rows[0])
                all_ids = _m2m_ids(rows[0].get(all_field)) if all_field else set()
                direct_ids = _m2m_ids(rows[0].get(direct_field)) if direct_field else set()
                group_ids = all_ids or direct_ids
                user["name"] = rows[0].get("name")
        user["group_count"] = None if group_ids is None else len(group_ids)
        models = client.execute_method("ir.model", "search_read", [], fields=["id", "model"])
        model_names = {
            int(row["id"]): str(row["model"])
            for row in models or []
            if isinstance(row, dict) and row.get("id") and row.get("model")
        }
        acl_rows = client.execute_method(
            "ir.model.access",
            "search_read",
            [],
            fields=["model_id", "group_id", *(perm for _, perm in OPERATIONS)],
        )
    user["model_count"] = len(model_names)
    return user, odoo_model_rights(model_names, list(acl_rows or []), group_ids)


# ---------------------------------------------------------------------------
# Logging entry point
# ---------------------------------------------------------------------------


def log_rights_report(client: Any, instance: str) -> None:
    """Collect and log both reports for ``instance`` (no dedupe, no env check)."""
    user, rights = collect_odoo_rights(client)
    who = f"user {user.get('login') or user.get('name') or '?'} (uid {user.get('uid')})"
    if user.get("group_count") is None:
        logger.warning(
            "Odoo rights [%s]: could not read the groups of %s; only global "
            "ir.model.access rows are counted.",
            instance,
            who,
        )
    logger.info(
        "Odoo rights [%s] for %s: %d of %d models accessible (%s).",
        instance,
        who,
        len(rights),
        user["model_count"],
        _counts(rights),
    )
    if logger.isEnabledFor(logging.DEBUG):
        for line in format_odoo_rights(rights):
            logger.debug("Odoo rights [%s] %s", instance, line)

    impact = model_acl_impact(get_model_policy(), instance, rights)
    if impact is None:
        logger.info(
            "model_acl impact [%s]: no model_acl policy for this instance; Odoo "
            "rights apply unchanged.",
            instance,
        )
        return
    kept_rights = {model: entry["kept"] for model, entry in impact.items() if entry["kept"]}
    fully_blocked = sum(
        1
        for entry in impact.values()
        if not entry["kept"] and not any(entry["methods"].values()) and not entry["other_methods"]
    )
    logger.info(
        "model_acl impact [%s]: of %d models with Odoo rights, %d fully blocked; "
        "CRUD left on %d models (%s).",
        instance,
        len(impact),
        fully_blocked,
        len(kept_rights),
        _counts(kept_rights),
    )
    if logger.isEnabledFor(logging.DEBUG):
        for line in format_acl_impact(impact):
            logger.debug("model_acl impact [%s] %s", instance, line)


def maybe_log_rights(client: Any, instance: str) -> None:
    """Log the rights report once per instance when ODOO_MCP_LOG_RIGHTS is set."""
    if not rights_logging_enabled():
        return
    with _logged_lock:
        if instance in _logged_instances:
            return
        _logged_instances.add(instance)
    try:
        log_rights_report(client, instance)
    except Exception as exc:  # never let reporting break a connection
        logger.warning("Could not build the rights report for [%s]: %s", instance, exc)


def reset_rights_log() -> None:
    """Forget which instances were logged (tests)."""
    with _logged_lock:
        _logged_instances.clear()
