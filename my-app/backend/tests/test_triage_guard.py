"""The guard decides what an LLM reply is allowed to cause. These are the rules that
keep a manipulated or mistaken model from touching real systems."""

import json

import pytest

from app.services.triage_guard import (
    RecommendedAction,
    TriageParseError,
    extract_json_object,
    observed_entities,
    parse_triage_output,
    plan_action,
)

EVENTS = [
    {"source_ip": "185.220.101.42", "destination_ip": "10.0.1.15", "host": "web-01.contoso.com",
     "user_identity": "admin@contoso.com",
     "raw_data": {"Url": "http://evil.example/payload", "SHA256": "a" * 64, "Computer": "WEB-01.contoso.com"}},
]
AUTO_TYPES = ["block_ip", "block_url", "block_file_hash"]


def reply(**overrides) -> str:
    base = {
        "severity": "critical", "attack_type": "ransomware", "confidence_score": 0.97,
        "summary": "Ransomware on web-01.", "recommended_actions": [], "requires_human_review": False,
    }
    return json.dumps({**base, **overrides})


def plan(action, target, *, can_auto=True, confidence=0.97, review=False, allow_auto=True):
    rec = RecommendedAction(action=action, target=target, can_auto_execute=can_auto)
    return plan_action(rec, observed_entities(EVENTS), confidence, review, AUTO_TYPES, 0.95, allow_auto=allow_auto)


# ---- parsing -----------------------------------------------------------------

def test_parses_a_valid_reply():
    out = parse_triage_output(reply(mitre_techniques=["T1486"]))
    assert out.severity == "critical" and out.confidence_score == 0.97 and out.mitre_techniques == ["T1486"]


def test_parses_json_wrapped_in_a_code_fence_and_prose():
    assert parse_triage_output("Here you go:\n```json\n" + reply() + "\n```").attack_type == "ransomware"


@pytest.mark.parametrize("confidence", [95, 1.5, -0.1, "high", None])
def test_rejects_confidence_outside_zero_to_one(confidence):
    # 95 must not sail past a ">= 0.95" check as if it were 95%.
    with pytest.raises(TriageParseError):
        parse_triage_output(reply(confidence_score=confidence))


def test_rejects_unknown_severity_and_non_json():
    with pytest.raises(TriageParseError):
        parse_triage_output(reply(severity="apocalyptic"))
    with pytest.raises(TriageParseError):
        parse_triage_output("I could not analyse this.")
    with pytest.raises(TriageParseError):
        extract_json_object("[1, 2, 3]")


def test_missing_review_flag_fails_safe_to_human_review():
    data = json.loads(reply())
    del data["requires_human_review"]
    assert parse_triage_output(json.dumps(data)).requires_human_review is True


def test_malformed_action_entries_are_dropped_not_fatal():
    out = parse_triage_output(reply(recommended_actions=["block everything", {"target": "1.2.3.4"},
                                                         {"action": "Block_IP", "target": "185.220.101.42"}]))
    assert [a.action for a in out.recommended_actions] == ["block_ip"]


# ---- what may run ------------------------------------------------------------

def test_allow_listed_block_of_an_observed_ip_auto_executes():
    p = plan("block_ip", "185.220.101.42")
    assert p.disposition == "auto" and p.params == {"ip_address": "185.220.101.42"}


def test_target_must_appear_in_the_evidence():
    # The classic injection: a log line tells the model to block or disable something else.
    assert plan("block_ip", "8.8.8.8").disposition == "skip"
    assert plan("disable_account", "ceo@contoso.com").disposition == "skip"
    assert plan("isolate_host", "dc-01.contoso.com").disposition == "skip"


def test_never_blocks_private_or_invalid_addresses():
    assert plan("block_ip", "10.0.1.15").disposition == "skip"  # observed, but internal
    assert plan("block_ip", "not-an-ip").disposition == "skip"


def test_account_and_host_actions_always_wait_for_an_analyst():
    # Even when the model is certain and flags them auto-executable.
    for action, target in [("disable_account", "admin@contoso.com"), ("revoke_sessions", "ADMIN@contoso.com"),
                           ("isolate_host", "web-01.contoso.com")]:
        p = plan(action, target, can_auto=True, confidence=1.0)
        assert p.disposition == "queue", action


def test_reversal_and_free_form_actions_cannot_be_proposed_by_the_ai():
    for action in ["enable_account", "release_host", "run_kql_query", "format_all_disks", "quarantine_email"]:
        assert plan(action, "admin@contoso.com").disposition == "skip", action


def test_auto_execution_needs_every_condition():
    assert plan("block_ip", "185.220.101.42", can_auto=False).disposition == "queue"
    assert plan("block_ip", "185.220.101.42", confidence=0.94).disposition == "queue"
    assert plan("block_ip", "185.220.101.42", review=True).disposition == "queue"
    assert plan("block_ip", "185.220.101.42", allow_auto=False).disposition == "queue"


def test_observed_entities_cover_normalised_and_raw_fields():
    seen = observed_entities(EVENTS)
    assert "185.220.101.42" in seen["ips"] and "web-01.contoso.com" in seen["hosts"]
    assert "admin@contoso.com" in seen["users"] and "http://evil.example/payload" in seen["urls"]
    assert "a" * 64 in seen["file_hashes"]
    assert plan("block_url", "http://evil.example/payload").disposition == "auto"
    assert plan("block_file_hash", "A" * 64).disposition == "auto"
