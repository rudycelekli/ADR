import json
from pathlib import Path

from adr_desktop import threat_feed
from adr_desktop.detection.inline import feed
from adr_desktop.detection.inline.feed import api_v1
from adr_desktop.protection import evaluate_operation


def test_desktop_feed_adapter_only_selects_the_reviewed_baseline_that_ships_with_detection():
    assert threat_feed.__all__ == ["load_bundled_feed"]
    baseline = Path(feed.__file__).parent / "malicious_artifacts.json"
    assert threat_feed.load_bundled_feed() == api_v1.parse_feed_json(baseline.read_bytes())


def test_existing_baseline_and_serialized_policy_generation_keep_their_contract():
    baseline = threat_feed.load_bundled_feed()
    generation = api_v1.compose_generation(baseline)
    restored = json.loads(json.dumps(generation))
    assert api_v1.validate_generation(restored) == generation
    subject = {
        "kind": "package", "ecosystem": "npm", "registry": "https://registry.npmjs.org",
        "name": "postmark-mcp", "version": "1.0.16",
    }
    assert api_v1.compile_generation(restored).match(subject) == api_v1.match_subject(
        generation, subject,
    )


def test_host_still_owns_enforcement_and_unknown_results_do_not_grant_permissions(runtime):
    event = {"tool_name": "Read", "tool_input": {"file_path": "/synthetic/private"}, "cwd": "/"}
    runtime.change_policy(add={"path": "/synthetic/private", "kind": "file", "action": "block"})
    decision = evaluate_operation(event, "claude", runtime.policy, state_dir=runtime.state_dir)
    assert decision.decision == "deny"
    assert decision.reason_code == "protected_path"
