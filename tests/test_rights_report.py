"""Opt-in rights logging: Odoo user rights and model_acl impact, reported separately."""

import json
import logging
import xmlrpc.client

import pytest

from odoo_mcp.model_policy import _parse_model_policy, reset_model_policy
from odoo_mcp.rights_report import (
    COMMON_MODELS,
    AccessProbe,
    candidate_models,
    collect_odoo_rights,
    format_acl_impact,
    format_odoo_rights,
    log_rights_report,
    model_acl_impact,
    odoo_model_rights,
    start_rights_report,
)

MODELS = {1: "project.project", 2: "project.task", 3: "res.partner", 4: "hr.employee"}
GROUP_USER, GROUP_MANAGER, GROUP_OTHER = 10, 11, 12

ACL_ROWS = [
    # global read on partners (Odoo sends False for "no group")
    {"model_id": [3, "Contact"], "group_id": False, "perm_read": True},
    # user group: read projects/tasks, write tasks
    {"model_id": [1, "Project"], "group_id": [GROUP_USER, "User"], "perm_read": True},
    {
        "model_id": [2, "Task"],
        "group_id": [GROUP_USER, "User"],
        "perm_read": True,
        "perm_write": True,
        "perm_create": True,
    },
    # manager group adds unlink on projects
    {
        "model_id": [1, "Project"],
        "group_id": [GROUP_MANAGER, "Manager"],
        "perm_read": True,
        "perm_write": True,
        "perm_unlink": True,
    },
    # a group the user is not in
    {"model_id": [4, "Employee"], "group_id": [GROUP_OTHER, "HR"], "perm_read": True},
]

# What a non-admin user may do, as Odoo answers has_access/check_access_rights.
PROBE_RIGHTS = {
    "project.project": {"read"},
    "project.task": {"read", "write", "create"},
    "res.partner": {"read"},
}
INSTALLED = set(COMMON_MODELS) - {"helpdesk.ticket", "mrp.production"}


# --------------------------------------------------------------------------
# Pure computation
# --------------------------------------------------------------------------


def test_odoo_rights_union_of_applicable_rows():
    rights = odoo_model_rights(MODELS, ACL_ROWS, {GROUP_USER, GROUP_MANAGER})
    assert rights == {
        "project.project": ["read", "write", "unlink"],
        "project.task": ["read", "write", "create"],
        "res.partner": ["read"],
    }


def test_odoo_rights_without_known_groups_counts_only_global_rows():
    assert odoo_model_rights(MODELS, ACL_ROWS, None) == {"res.partner": ["read"]}


def test_model_acl_impact_is_separate_and_per_method():
    rights = odoo_model_rights(MODELS, ACL_ROWS, {GROUP_USER, GROUP_MANAGER})
    policy = _parse_model_policy(
        {
            "model_acl": {
                "default": {
                    "default": "deny",
                    "rules": [
                        {"allow": "project.*:@read"},
                        {"allow": "project.task:@write"},
                        {"allow": "project.project:message_subscribe"},
                        {"deny": "project.project:unlink"},
                    ],
                }
            }
        }
    )
    impact = model_acl_impact(policy, "default", rights)
    assert impact["project.project"] == {
        "kept": ["read"],
        "blocked": ["write", "unlink"],
        "methods": {"message_subscribe": True},
        "other_methods": False,
    }
    assert impact["project.task"]["kept"] == ["read", "write", "create"]
    assert impact["res.partner"]["kept"] == []
    lines = format_acl_impact(impact)
    assert "res.partner: all blocked" in lines
    assert (
        "project.project: read | blocked: write unlink | methods: message_subscribe "
        "allowed | other methods blocked"
    ) in lines


def test_no_policy_for_instance_returns_none():
    policy = _parse_model_policy({"model_acl": {"other": {"default": "deny"}}})
    assert model_acl_impact(policy, "default", {"res.partner": ["read"]}) is None


def test_format_odoo_rights():
    assert format_odoo_rights({"res.partner": ["read", "write"]}) == [
        "res.partner: read write"
    ]


def test_candidate_models_include_rules_env_and_report_unmatched_globs(monkeypatch):
    monkeypatch.setenv("ODOO_MCP_LOG_RIGHTS_MODELS", "x_custom.model, quality.check")
    policy = _parse_model_policy(
        {
            "model_acl": {
                "default": {
                    "default": "deny",
                    "rules": [
                        {"allow": "fleet.vehicle:@read"},
                        {"allow": "project.*"},
                        {"allow": "website.*"},
                    ],
                }
            }
        }
    )
    models, unmatched = candidate_models(policy, "default")
    assert {"fleet.vehicle", "x_custom.model", "quality.check", "res.partner"} <= set(models)
    assert unmatched == ["website.*"]  # project.* matches common models


# --------------------------------------------------------------------------
# Fake Odoo clients
# --------------------------------------------------------------------------


def fault(message, code=4):
    return xmlrpc.client.Fault(code, message)


class AdminClient:
    """May read ir.model / ir.model.access (bulk path)."""

    uid = 7
    username = "admin@example.com"
    transport = "xmlrpc"

    def __init__(self):
        self.calls = []

    def get_user_context(self):
        return {"uid": 7}

    def execute_method(self, model, method, *args, **kwargs):
        self.calls.append((model, method))
        if (model, method) == ("res.users", "fields_get"):
            return {"name": {}, "group_ids": {}, "all_group_ids": {}}
        if (model, method) == ("res.users", "read"):
            return [{"id": 7, "group_ids": [GROUP_USER], "all_group_ids": [GROUP_USER, GROUP_MANAGER]}]
        if (model, method) == ("ir.model", "search_read"):
            return [{"id": key, "model": value} for key, value in MODELS.items()]
        if (model, method) == ("ir.model.access", "search_read"):
            return ACL_ROWS
        raise AssertionError((model, method))


class UserClient:
    """A normal user: no ir.model access; answers per-model access checks."""

    uid = 9
    username = "user@example.com"

    def __init__(self, methods=("has_access", "check_access_rights"), transport="xmlrpc"):
        self.methods = methods
        self.transport = transport
        self.calls = []

    def get_user_context(self):
        return {"uid": 9}

    def execute_method(self, model, method, *args, **kwargs):
        self.calls.append((model, method, args, kwargs))
        if model in {"ir.model", "ir.model.access"} or (model, method) == (
            "res.users",
            "fields_get",
        ):
            raise fault(
                "You are not allowed to access 'Models' (ir.model) records.\n\n"
                "This operation is allowed for the following groups:\n"
                "\t- Administration/Access Rights"
            )
        if method in {"has_access", "check_access_rights"}:
            if method not in self.methods:
                # real XML-RPC shape: the reason is on the traceback's last line
                raise fault(
                    "Traceback (most recent call last):\n  ...\n"
                    f"AttributeError: The method '{model}.{method}' does not exist"
                )
            if model not in INSTALLED:
                raise fault(f"Object {model} doesn't exist", code=2)
            operation = kwargs.get("operation") or (args[1] if method == "has_access" else args[0])
            return operation in PROBE_RIGHTS.get(model, set())
        raise AssertionError((model, method))


# --------------------------------------------------------------------------
# Collection
# --------------------------------------------------------------------------


def test_admin_uses_bulk_read():
    result = collect_odoo_rights(AdminClient())
    assert result.source == "ir.model.access"
    assert result.models_checked == 4
    assert result.rights["project.project"] == ["read", "write", "unlink"]


def test_normal_user_falls_back_to_per_model_check():
    client = UserClient()
    result = collect_odoo_rights(client)
    assert result.source == "per-model check"
    assert "not allowed to access 'Models'" in result.fallback_reason
    assert result.rights == {
        "project.project": ["read"],
        "project.task": ["read", "write", "create"],
        "res.partner": ["read"],
    }
    assert set(result.not_installed) == {"helpdesk.ticket", "mrp.production"}
    assert result.models_checked == len(COMMON_MODELS) - 2
    # positional XML-RPC form: ids, then operation
    call = next(c for c in client.calls if c[1] == "has_access")
    assert call[2] == ([], "read")


def test_older_odoo_without_has_access_uses_check_access_rights():
    client = UserClient(methods=("check_access_rights",))
    result = collect_odoo_rights(client)
    assert result.rights["project.task"] == ["read", "write", "create"]
    call = next(c for c in client.calls if c[1] == "check_access_rights")
    assert call[2] == ("read",) and call[3] == {"raise_exception": False}
    # once detected, has_access is not retried for every model
    assert sum(1 for c in client.calls if c[1] == "has_access") == 1


def test_json2_uses_keyword_arguments():
    client = UserClient(transport="json2")
    collect_odoo_rights(client)
    call = next(c for c in client.calls if c[1] == "has_access")
    assert call[2] == () and call[3] == {"ids": [], "operation": "read"}


def test_probe_raises_when_no_method_is_offered():
    probe = AccessProbe(UserClient(methods=()))
    with pytest.raises(RuntimeError, match="neither has_access nor check_access_rights"):
        probe.check("res.partner", "read")


# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------


def test_admin_report_info_and_debug(caplog, monkeypatch, tmp_path):
    pf = tmp_path / "policy.json"
    pf.write_text(
        json.dumps({"model_acl": {"default": {"default": "deny", "rules": [{"allow": "project.*"}]}}})
    )
    monkeypatch.setenv("ODOO_MCP_MODEL_POLICY_FILE", str(pf))
    reset_model_policy()
    with caplog.at_level(logging.DEBUG, logger="odoo_mcp.rights_report"):
        log_rights_report(AdminClient(), "default")
    text = caplog.text
    assert "Odoo rights [default] for user admin@example.com (uid 7): 3 of 4 models accessible" in text
    assert "Odoo rights [default] project.project: read write unlink" in text
    assert "model_acl impact [default]: of 3 models with Odoo rights, 1 fully blocked" in text
    assert "model_acl impact [default] res.partner: all blocked" in text


def test_user_report_explains_fallback(caplog):
    with caplog.at_level(logging.DEBUG, logger="odoo_mcp.rights_report"):
        log_rights_report(UserClient(), "default")
    text = caplog.text
    assert "may not read the full model list" in text
    assert "ODOO_MCP_LOG_RIGHTS_MODELS" in text
    assert "3 of 40 installed candidate models accessible" in text
    assert "not installed (skipped): helpdesk.ticket mrp.production" in text
    assert "no model_acl policy for this instance" in text


def test_info_level_has_no_per_model_lines(caplog):
    with caplog.at_level(logging.INFO, logger="odoo_mcp.rights_report"):
        log_rights_report(AdminClient(), "default")
    assert "project.project: read" not in caplog.text


# --------------------------------------------------------------------------
# Startup
# --------------------------------------------------------------------------


def test_start_is_noop_when_disabled(monkeypatch, caplog):
    monkeypatch.delenv("ODOO_MCP_LOG_RIGHTS", raising=False)
    with caplog.at_level(logging.INFO, logger="odoo_mcp.rights_report"):
        assert start_rights_report("streamable-http") is None
    assert caplog.text == ""


@pytest.mark.parametrize("transport", ["stdio", "streamable-http"])
def test_start_reports_every_instance_in_background(monkeypatch, caplog, transport):
    import odoo_mcp.odoo_client as oc

    monkeypatch.setenv("ODOO_MCP_LOG_RIGHTS", "1")
    monkeypatch.setattr(
        oc,
        "load_instances_config",
        lambda: ("main", {"main": {}, "user": {}, "broken": {}, "failing": {}}),
    )

    class Failing(UserClient):
        def execute_method(self, model, method, *args, **kwargs):
            raise RuntimeError("boom")

    clients = {"main": AdminClient(), "user": UserClient(), "failing": Failing()}

    def fake_client_for(name):
        if name == "broken":
            raise ConnectionError("unreachable")
        return name, clients[name]

    monkeypatch.setattr(oc, "get_odoo_client_for", fake_client_for)
    with caplog.at_level(logging.INFO, logger="odoo_mcp.rights_report"):
        thread = start_rights_report(transport)
        assert thread is not None
        thread.join(timeout=5)
    text = caplog.text
    assert "connecting to each configured Odoo instance" in text
    assert "Odoo rights [main] for user admin@example.com" in text
    assert "Odoo rights [user] for user user@example.com" in text
    assert "Rights report [broken]: could not connect to Odoo: unreachable" in text
    assert "Could not build the rights report for [failing]: no model could be checked" in text
    assert "boom" in text


class _Json2Error(Exception):
    def __init__(self, message):
        super().__init__(f"JSON-2 request x failed with HTTP 404: {message}")
        self.odoo_error = {"message": message}


@pytest.mark.parametrize(
    "exc, verdict",
    [
        # texts captured from Odoo 19 (XML-RPC and JSON-2)
        (fault("Object account.account doesn't exist"), "model_missing"),
        (_Json2Error("the model 'account.account' does not exist"), "model_missing"),
        (
            fault(
                "Traceback (most recent call last):\n...\nAttributeError: "
                "The method 'account.account.has_access' does not exist"
            ),
            "method_unavailable",
        ),
        (
            _Json2Error("The method 'account.account.has_access' does not exist"),
            "method_unavailable",
        ),
        (
            fault(
                "Private methods (such as 'account.account.has_access') cannot be "
                "called remotely."
            ),
            "method_unavailable",
        ),
        (fault("Access Denied"), "other"),
        # Dutch user on Odoo 17 (captured): translated text, fault code 2
        (fault("Object account.account bestaat niet", code=2), "model_missing"),
        # same code but about something else: not a missing model
        (fault("Ongeldige waarde", code=2), "other"),
    ],
)
def test_classify_probe_error_real_texts(exc, verdict):
    from odoo_mcp.rights_report import classify_probe_error

    assert classify_probe_error(exc, "account.account", "has_access") == verdict


def test_json2_missing_model_is_skipped_not_method_error():
    class Json2User(UserClient):
        def execute_method(self, model, method, *args, **kwargs):
            if method == "has_access" and model not in INSTALLED:
                raise _Json2Error(f"the model '{model}' does not exist")
            return super().execute_method(model, method, *args, **kwargs)

    client = Json2User(transport="json2")
    result = collect_odoo_rights(client)
    assert set(result.not_installed) == {"helpdesk.ticket", "mrp.production"}
    assert all(call[1] != "check_access_rights" for call in client.calls)


def test_dutch_user_missing_models_are_skipped():
    """Reproduces a colleague's log: Odoo 17, Dutch user, no has_access."""

    class DutchUser(UserClient):
        def execute_method(self, model, method, *args, **kwargs):
            if method == "check_access_rights" and model not in INSTALLED:
                raise fault(f"Object {model} bestaat niet", code=2)
            return super().execute_method(model, method, *args, **kwargs)

    result = collect_odoo_rights(DutchUser(methods=("check_access_rights",)))
    assert set(result.not_installed) == {"helpdesk.ticket", "mrp.production"}
    assert result.unchecked == {}
    assert result.rights["project.task"] == ["read", "write", "create"]


def test_one_failing_model_does_not_stop_the_report(caplog):
    class Flaky(UserClient):
        def execute_method(self, model, method, *args, **kwargs):
            if model == "sale.order" and method == "has_access":
                raise fault("Unexpected server error", code=1)
            return super().execute_method(model, method, *args, **kwargs)

    with caplog.at_level(logging.DEBUG, logger="odoo_mcp.rights_report"):
        log_rights_report(Flaky(), "default")
    text = caplog.text
    assert "1 model(s) could not be checked (e.g. sale.order: Unexpected server error)" in text
    assert "could not check sale.order: Unexpected server error" in text
    assert "Odoo rights [default] project.task: read write create" in text


def test_report_requests_are_quiet(capsys, monkeypatch):
    import odoo_mcp.odoo_client as oc

    def refuse(self, host, handler, request_body, verbose=False):
        raise fault("You are not allowed to access 'Models' (ir.model) records.")

    monkeypatch.setattr(xmlrpc.client.Transport, "request", refuse)
    transport = oc.RedirectTransport(timeout=1, use_https=False, verify_ssl=True)
    with oc.quiet_requests(), pytest.raises(xmlrpc.client.Fault):
        transport.request("odoo.example", "/xmlrpc/2/object", b"")
    assert capsys.readouterr().err == ""
    with pytest.raises(xmlrpc.client.Fault):
        transport.request("odoo.example", "/xmlrpc/2/object", b"")
    err = capsys.readouterr().err
    assert "Making request to odoo.example/xmlrpc/2/object" in err
    assert "Error during request" in err
