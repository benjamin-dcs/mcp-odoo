"""Opt-in rights logging: Odoo user rights and model_acl impact, reported separately."""

import json
import logging

import pytest

from odoo_mcp.model_policy import _parse_model_policy, reset_model_policy
from odoo_mcp.rights_report import (
    format_acl_impact,
    format_odoo_rights,
    log_rights_report,
    maybe_log_rights,
    model_acl_impact,
    odoo_model_rights,
    reset_rights_log,
)

MODELS = {1: "project.project", 2: "project.task", 3: "res.partner", 4: "hr.employee"}
GROUP_USER, GROUP_MANAGER, GROUP_OTHER = 10, 11, 12

ACL_ROWS = [
    # global read on partners
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


@pytest.fixture(autouse=True)
def _reset():
    reset_rights_log()
    yield
    reset_rights_log()


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


class FakeClient:
    uid = 7
    username = "agent@example.com"

    def __init__(self, fail=False):
        self.fail = fail
        self.calls = []

    def get_user_context(self):
        return {"uid": 7}

    def execute_method(self, model, method, *args, **kwargs):
        self.calls.append((model, method))
        if self.fail:
            raise RuntimeError("Access denied")
        if (model, method) == ("res.users", "fields_get"):
            return {"name": {}, "group_ids": {}, "all_group_ids": {}}
        if (model, method) == ("res.users", "read"):
            return [
                {
                    "id": 7,
                    "name": "Agent",
                    "group_ids": [GROUP_USER],
                    "all_group_ids": [GROUP_USER, GROUP_MANAGER],
                }
            ]
        if (model, method) == ("ir.model", "search_read"):
            return [{"id": key, "model": value} for key, value in MODELS.items()]
        if (model, method) == ("ir.model.access", "search_read"):
            return ACL_ROWS
        raise AssertionError((model, method))


def test_log_report_info_and_debug(caplog, monkeypatch, tmp_path):
    pf = tmp_path / "policy.json"
    pf.write_text(
        json.dumps({"model_acl": {"default": {"default": "deny", "rules": [{"allow": "project.*"}]}}})
    )
    monkeypatch.setenv("ODOO_MCP_MODEL_POLICY_FILE", str(pf))
    reset_model_policy()
    with caplog.at_level(logging.DEBUG, logger="odoo_mcp.rights_report"):
        log_rights_report(FakeClient(), "default")
    text = caplog.text
    assert "Odoo rights [default] for user agent@example.com (uid 7): 3 of 4 models" in text
    assert "Odoo rights [default] project.project: read write unlink" in text
    assert "model_acl impact [default]: of 3 models with Odoo rights, 1 fully blocked" in text
    assert "model_acl impact [default] res.partner: all blocked" in text


def test_info_level_has_no_per_model_lines(caplog):
    with caplog.at_level(logging.INFO, logger="odoo_mcp.rights_report"):
        log_rights_report(FakeClient(), "default")
    assert "project.project: read" not in caplog.text
    assert "no model_acl policy for this instance" in caplog.text


def test_maybe_log_is_opt_in_and_once_per_instance(monkeypatch, caplog):
    client = FakeClient()
    monkeypatch.delenv("ODOO_MCP_LOG_RIGHTS", raising=False)
    maybe_log_rights(client, "default")
    assert client.calls == []
    monkeypatch.setenv("ODOO_MCP_LOG_RIGHTS", "1")
    with caplog.at_level(logging.INFO, logger="odoo_mcp.rights_report"):
        maybe_log_rights(client, "default")
        first = len(client.calls)
        maybe_log_rights(client, "default")
    assert first > 0 and len(client.calls) == first


def test_maybe_log_never_raises(monkeypatch, caplog):
    monkeypatch.setenv("ODOO_MCP_LOG_RIGHTS", "1")
    with caplog.at_level(logging.WARNING, logger="odoo_mcp.rights_report"):
        maybe_log_rights(FakeClient(fail=True), "default")
    assert "Could not build the rights report" in caplog.text
