"""Opt-in log of the Odoo user's model rights, and model_acl's impact on them.

Enabled with ``ODOO_MCP_LOG_RIGHTS=1``. At startup, in a background thread
(the server never waits for it), the server connects to every configured
instance and logs two separate reports:

1. **Odoo rights**: what the connected Odoo user may do per model, as Odoo
   itself grants it (read / write / create / unlink). No model_acl
   interpretation.
2. **model_acl impact**: for the models the user has Odoo rights on, which of
   those operations model_acl blocks, plus the methods named in model_acl
   rules for that model.

How the Odoo rights are found:

- **Users who may read ``ir.model`` and ``ir.model.access``** (normally only
  administrators): one bulk read of every model and access rule, combined
  for the user's groups. Covers every installed model.
- **Everyone else**: Odoo is asked model by model whether this user has
  access (``has_access`` on Odoo 18+, ``check_access_rights`` before), which
  any user may do. Without the model list, a candidate list is checked: the
  models named in model_acl rules, common business models, and any listed in
  ``ODOO_MCP_LOG_RIGHTS_MODELS``. Models not installed are skipped.

Summaries go to INFO, per-model lines to DEBUG (``ODOO_MCP_LOG_LEVEL=DEBUG``).
Record rules (row-level filters) are not part of this report. A failure is
logged as a warning and never affects the server.
"""

from __future__ import annotations

import fnmatch
import logging
import os
import threading
from dataclasses import dataclass, field
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
from .odoo_client import quiet_requests

logger = logging.getLogger(__name__)

RIGHTS_ENV = "ODOO_MCP_LOG_RIGHTS"
RIGHTS_MODELS_ENV = "ODOO_MCP_LOG_RIGHTS_MODELS"
OPERATIONS: Tuple[Tuple[str, str], ...] = (
    ("read", "perm_read"),
    ("write", "perm_write"),
    ("create", "perm_create"),
    ("unlink", "perm_unlink"),
)
_OTHER_METHOD_PROBE = "__odoo_mcp_any_other_method__"

# Checked one by one when the user cannot read the model list.
COMMON_MODELS: Tuple[str, ...] = (
    "res.partner", "res.users", "res.company", "res.currency",
    "product.product", "product.template", "product.category",
    "crm.lead", "sale.order", "sale.order.line",
    "purchase.order", "purchase.order.line",
    "account.move", "account.move.line", "account.payment", "account.account",
    "account.journal", "account.analytic.account", "account.analytic.line",
    "stock.picking", "stock.move", "stock.quant", "stock.warehouse",
    "mrp.production",
    "project.project", "project.task", "project.milestone", "project.tags",
    "hr.employee", "hr.department", "hr.leave", "hr.expense", "hr.attendance",
    "calendar.event", "mail.message", "mail.activity", "ir.attachment",
    "helpdesk.ticket", "documents.document", "knowledge.article",
    "planning.slot", "sign.request",
)


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


@dataclass
class RightsResult:
    user: Dict[str, Any]
    rights: Dict[str, List[str]]
    source: str  # "ir.model.access" or "per-model check"
    models_checked: int
    not_installed: List[str] = field(default_factory=list)
    unchecked: Dict[str, str] = field(default_factory=dict)  # model -> reason
    fallback_reason: Optional[str] = None
    unmatched_globs: List[str] = field(default_factory=list)


def candidate_models(policy: ModelPolicy, instance: str) -> Tuple[List[str], List[str]]:
    """Models to check one by one, and model_acl globs that list can't expand.

    Candidates: common business models, exact model names from this
    instance's model_acl rules, and ``ODOO_MCP_LOG_RIGHTS_MODELS``.
    """
    names = set(COMMON_MODELS)
    names.update(
        item.strip()
        for item in os.environ.get(RIGHTS_MODELS_ENV, "").split(",")
        if item.strip()
    )
    globs: List[str] = []
    acl = policy.instance_acl(instance)
    for rule in acl.rules if acl else ():
        if any(ch in rule.model_glob for ch in "*?"):
            globs.append(rule.model_glob)
        else:
            names.add(rule.model_glob)
    unmatched = sorted(
        {glob for glob in globs if not any(fnmatch.fnmatchcase(n, glob) for n in names)}
    )
    return sorted(names), unmatched


def _first_line(exc: Exception) -> str:
    text = str(getattr(exc, "faultString", None) or exc).strip()
    return text.splitlines()[0] if text else type(exc).__name__


class ProbeUnavailable(RuntimeError):
    """Odoo offers no access-check method this probe can use."""


class AccessProbe:
    """Ask Odoo whether the current user may do ``operation`` on a model.

    Tries ``has_access`` (Odoo 18+) and then ``check_access_rights`` (older),
    remembering the first one the server accepts.
    """

    METHODS = ("has_access", "check_access_rights")

    def __init__(self, client: Any) -> None:
        self.client = client
        self.json2 = getattr(client, "transport", "xmlrpc") == "json2"
        self.method: Optional[str] = None

    def _call(self, method: str, model: str, operation: str) -> Any:
        if method == "has_access":
            if self.json2:
                return self.client.execute_method(model, method, ids=[], operation=operation)
            return self.client.execute_method(model, method, [], operation)
        if self.json2:
            return self.client.execute_method(
                model, method, operation=operation, raise_exception=False
            )
        return self.client.execute_method(model, method, operation, raise_exception=False)

    def check(self, model: str, operation: str) -> Optional[bool]:
        """True/False for access; None when the model is not installed."""
        methods = [self.method] if self.method else list(self.METHODS)
        last_error: Optional[Exception] = None
        for method in methods:
            try:
                result = self._call(method, model, operation)
            except Exception as exc:
                verdict = classify_probe_error(exc, model, method)
                if verdict == "model_missing":
                    return None
                if verdict == "method_unavailable":
                    last_error = exc
                    continue
                raise
            self.method = method
            return bool(result)
        raise ProbeUnavailable(
            "Odoo accepted neither has_access nor check_access_rights: "
            f"{_first_line(last_error) if last_error else 'no answer'}"
        )


def _odoo_message(exc: Exception) -> str:
    """Odoo's own error text: the JSON-2 message, else the full XML-RPC fault."""
    odoo_error = getattr(exc, "odoo_error", None)
    if isinstance(odoo_error, dict) and odoo_error.get("message"):
        return str(odoo_error["message"])
    return str(getattr(exc, "faultString", None) or exc)


def classify_probe_error(exc: Exception, model: str, method: str) -> str:
    """'model_missing', 'method_unavailable' or 'other', from Odoo's error.

    Odoo translates "model not installed" into the user's language ("Object
    hr.attendance bestaat niet"), so the English texts are only a first try.
    The language-independent signal is XML-RPC fault code 2 (Odoo's
    user-facing error) or JSON-2 HTTP 404, with the model named in the
    message. A missing method is an untranslated "The method
    '<model>.<method>' does not exist" (in an XML-RPC traceback); a private
    one "Private methods (such as '<model>.<method>') ...".
    """
    text = _odoo_message(exc)
    lowered = text.lower()
    if f"object {model} doesn't exist" in lowered or f"the model '{model}' does not exist" in lowered:
        return "model_missing"
    if f"'{model}.{method}'" in text:
        return "method_unavailable"
    code = getattr(exc, "faultCode", None)
    status = getattr(exc, "status_code", None)
    if (code == 2 or status == 404) and model in text:
        return "model_missing"
    return "other"


def _collect_bulk(client: Any) -> Tuple[Dict[str, Any], Dict[str, List[str]], int]:
    """Admin path: groups + ir.model + ir.model.access in a few reads."""
    context = client.get_user_context() if hasattr(client, "get_user_context") else {}
    uid = getattr(client, "uid", None)
    if uid is None and isinstance(context, dict):
        uid = context.get("uid")
    user: Dict[str, Any] = {"uid": uid, "login": getattr(client, "username", None)}
    group_ids: Optional[set[int]] = None
    if isinstance(uid, int) and uid > 0:
        user_fields = client.execute_method("res.users", "fields_get", [], attributes=["type"])
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
    if group_ids is None:
        raise PermissionError("could not read the user's groups")
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
    return user, odoo_model_rights(model_names, list(acl_rows or []), group_ids), len(
        model_names
    )


def _collect_by_probe(
    client: Any, models: List[str]
) -> Tuple[Dict[str, List[str]], List[str], Dict[str, str]]:
    """Any-user path: ask Odoo per model and operation.

    Returns (rights, not installed, could-not-check model -> reason). One
    model failing never stops the others; only a server that offers no
    usable access-check method does.
    """
    probe = AccessProbe(client)
    rights: Dict[str, List[str]] = {}
    not_installed: List[str] = []
    unchecked: Dict[str, str] = {}
    for model in models:
        granted: List[str] = []
        try:
            for op, _ in OPERATIONS:
                answer = probe.check(model, op)
                if answer is None:
                    not_installed.append(model)
                    break
                if answer:
                    granted.append(op)
        except ProbeUnavailable:
            raise
        except Exception as exc:
            unchecked[model] = _odoo_message(exc).strip().splitlines()[-1][:200]
            continue
        if granted:
            rights[model] = granted
    if unchecked and len(unchecked) + len(not_installed) == len(models):
        # Not a single model answered: report the failure, not "0 of 0".
        first_model, first_reason = next(iter(unchecked.items()))
        raise RuntimeError(f"no model could be checked ({first_model}: {first_reason})")
    return rights, not_installed, unchecked


def collect_odoo_rights(client: Any, instance: str = "default") -> RightsResult:
    """Bulk read when allowed (admins), otherwise check candidate models one by one."""
    with metadata_scope(), quiet_requests():
        try:
            user, rights, model_count = _collect_bulk(client)
            return RightsResult(user, rights, "ir.model.access", model_count)
        except Exception as exc:
            reason = _odoo_message(exc).strip().splitlines()[0]
        uid = getattr(client, "uid", None)
        if uid is None and hasattr(client, "get_user_context"):
            context = client.get_user_context()
            uid = context.get("uid") if isinstance(context, dict) else None
        user = {"uid": uid, "login": getattr(client, "username", None)}
        models, unmatched = candidate_models(get_model_policy(), instance)
        rights, not_installed, unchecked = _collect_by_probe(client, models)
    return RightsResult(
        user,
        rights,
        "per-model check",
        len(models) - len(not_installed) - len(unchecked),
        not_installed,
        unchecked,
        reason,
        unmatched,
    )


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def log_rights_report(client: Any, instance: str) -> None:
    """Collect and log both reports for ``instance``."""
    result = collect_odoo_rights(client, instance)
    rights = result.rights
    who = f"user {result.user.get('login') or '?'} (uid {result.user.get('uid')})"
    if result.source == "ir.model.access":
        scope = f"{len(rights)} of {result.models_checked} models accessible"
    else:
        logger.info(
            "Odoo rights [%s]: this user may not read the full model list (%s); "
            "checking %d candidate models one by one instead. Add models with %s.",
            instance,
            result.fallback_reason,
            result.models_checked + len(result.not_installed) + len(result.unchecked),
            RIGHTS_MODELS_ENV,
        )
        scope = (
            f"{len(rights)} of {result.models_checked} installed candidate models "
            "accessible"
        )
    logger.info(
        "Odoo rights [%s] for %s: %s (%s).", instance, who, scope, _counts(rights)
    )
    if result.unchecked:
        first_model, first_reason = next(iter(result.unchecked.items()))
        logger.warning(
            "Odoo rights [%s]: %d model(s) could not be checked (e.g. %s: %s); "
            "they are left out of the report.",
            instance,
            len(result.unchecked),
            first_model,
            first_reason,
        )
    if result.unmatched_globs:
        logger.info(
            "Odoo rights [%s]: no candidate model matches model_acl pattern(s) %s; "
            "list the models you care about in %s.",
            instance,
            ", ".join(result.unmatched_globs),
            RIGHTS_MODELS_ENV,
        )
    if logger.isEnabledFor(logging.DEBUG):
        for line in format_odoo_rights(rights):
            logger.debug("Odoo rights [%s] %s", instance, line)
        for model, reason in result.unchecked.items():
            logger.debug("Odoo rights [%s] could not check %s: %s", instance, model, reason)
        if result.not_installed:
            logger.debug(
                "Odoo rights [%s] not installed (skipped): %s",
                instance,
                " ".join(result.not_installed),
            )

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


def start_rights_report(transport: str) -> Optional[threading.Thread]:
    """When enabled, build the report for every instance in a background thread.

    The thread opens its own Odoo connection per instance, so it never shares
    a client with tool calls, and the server starts without waiting for it.
    """
    if not rights_logging_enabled():
        return None
    logger.info(
        "Rights report enabled (%s): connecting to each configured Odoo instance "
        "in the background to log it now.",
        RIGHTS_ENV,
    )
    thread = threading.Thread(
        target=_report_all_instances, name="odoo-mcp-rights-report", daemon=True
    )
    thread.start()
    return thread


def _report_all_instances() -> None:
    from . import odoo_client

    try:
        _, instances = odoo_client.load_instances_config()
    except Exception as exc:
        logger.warning("Rights report: could not load the Odoo configuration: %s", exc)
        return
    for name in instances:
        try:
            _, client = odoo_client.get_odoo_client_for(name)
        except Exception as exc:
            logger.warning("Rights report [%s]: could not connect to Odoo: %s", name, exc)
            continue
        try:
            log_rights_report(client, name)
        except Exception as exc:
            logger.warning(
                "Could not build the rights report for [%s]: %s", name, _first_line(exc)
            )
