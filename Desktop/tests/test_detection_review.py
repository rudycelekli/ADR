"""Detection's review coordinator with fake ports: no Desktop runtime, store or native bridge."""

import time
import uuid

import pytest

from adr_desktop.detection.review.contracts import ReviewError
from adr_desktop.detection.review.coordinator import ReviewCoordinator
from adr_desktop.storage.database import Database

SETTINGS = {
    "provider": "claude",
    "model": "",
    "background": False,
    "mode": "budget",
    "max_tokens": 12000,
    "daily_tokens": 50000,
    "daily_jobs": 5,
    "max_seconds": 180,
    "max_cost_usd": 0.50,
    "daily_cost_usd": 2.0,
    "allow_paid": False,
    "reserve_percent": 35,
    "idle_minutes": 15,
    "reset_within_hours": 4,
    "projects": [],
    "consented": True,
    "revision": "synthetic-revision",
}


def captured(identifier, *, project="/workspace/sample", messages=None, title="Synthetic session"):
    history = messages or [
        {"role": "user", "content": "Summarize the notes"},
        {"role": "assistant", "content": "The notes describe a synthetic project."},
    ]
    return {
        "id": identifier,
        "project": project,
        "digest": "digest-" + identifier,
        "message_count": len(history),
        "source": "codex",
        "source_session_id": "source-" + identifier,
        "title": title,
        "partial": 0,
        "payload": {"chat_history": history},
    }


class Sessions:
    """Fake SessionSource: sessions in the order of their latest activity, newest first."""

    def __init__(self, *sessions):
        self.items = {session["id"]: session for session in sessions}
        self.activity = []  # (epoch seconds, session) for captured session activity
        self.hook_times = []  # epoch seconds of hook events

    def record(self, kind, at):
        if kind == "hook":
            self.hook_times.append(at)
        else:
            self.activity.append((at, {"source": "codex", "source_session_id": "source-active"}))

    def session(self, session_id):
        return self.items.get(session_id)

    def recent_sessions(self, projects):
        fields = ("id", "project", "digest", "message_count", "source", "source_session_id")
        return [
            {key: session[key] for key in fields}
            for session in self.items.values()
            if session["project"] in projects
        ]

    def active_sessions(self, since):
        return [session for at, session in self.activity if at > since]

    def hooks_active(self, since):
        return any(at > since for at in self.hook_times)

    def describe_sessions(self, session_ids):
        return {
            identifier: {key: self.items[identifier][key] for key in ("title", "source", "digest")}
            for identifier in session_ids
            if identifier in self.items
        }


class Device:
    """Fake device-idle port."""

    def __init__(self, seconds=3600):
        self.seconds = seconds

    def idle_seconds(self):
        if isinstance(self.seconds, Exception):
            raise self.seconds
        return self.seconds


class Driver:
    def __init__(self, *, report=None, fail=False):
        self.report = report or {"summary": "No supported finding in synthetic evidence.", "findings": []}
        self.fail = fail
        self.prompts = []

    def available(self):
        return {"claude": True, "codex": True}

    def probe(self, provider, cancel):
        return {"account": "synthetic-account", "subscription": True, "quota": None}

    def run(self, provider, prompt, schema, settings, cancel, progress):
        self.prompts.append(prompt)
        progress({"session_id": "review-run"})
        progress({"tokens": 200, "cost_usd": 0.01})
        if self.fail:
            raise ReviewError("cli_failed")
        return self.report


class Reviews(ReviewCoordinator):
    """Supplies what Desktop supplies: the owner's settings, the credential check and the activity log."""

    def __init__(self, state_dir, sessions, *, device=None, driver=None, **settings):
        self.settings = {**SETTINGS, **settings}
        self.audits = []
        super().__init__(Database(state_dir), sessions, device or Device(), driver or Driver())

    def preferences(self):
        return self.settings

    def withheld(self, text, provider):
        return False

    def audit(self, kind, summary, details=None):
        self.audits.append(kind)


@pytest.fixture
def make(tmp_path):
    made = []

    def build(*sessions, **options):
        reviews = Reviews(tmp_path, Sessions(*sessions), **options)
        made.append(reviews)
        return reviews

    yield build
    for reviews in made:
        reviews.close()
        reviews.store.close()


def finished(reviews):
    reviews.worker.join(timeout=5)
    assert not reviews.worker.is_alive()
    return reviews.status()["jobs"][0]


def test_review_reads_the_captured_session_through_the_session_source(make):
    reviews = make(captured("one"))
    reviews.start("one", str(uuid.uuid4()))
    job = finished(reviews)
    assert (job["state"], job["session_id"], job["digest"]) == ("completed", "one", "digest-one")
    assert "The notes describe a synthetic project." in reviews.driver.prompts[0]
    assert reviews.audits == ["security_review_finished"]
    with pytest.raises(ValueError, match="not found"):
        reviews.start("missing", str(uuid.uuid4()))


def test_review_list_names_each_session_and_flags_one_changed_or_gone_since_its_review(make):
    reviews = make(captured("one", title="Notes cleanup"))
    reviews.start("one", str(uuid.uuid4()))
    job = finished(reviews)
    assert (job["session_title"], job["session_source"], job["stale"]) == ("Notes cleanup", "codex", False)
    reviews.sessions.items["one"] = {**captured("one", title="Notes cleanup"), "digest": "digest-newer"}
    assert reviews.status()["jobs"][0]["stale"] is True
    del reviews.sessions.items["one"]
    gone = reviews.status()["jobs"][0]
    assert (gone["session_title"], gone["session_source"], gone["stale"]) == (None, None, True)


def test_failed_review_is_not_completed_and_keeps_no_report(make):
    reviews = make(captured("one"), driver=Driver(fail=True))
    reviews.start("one", str(uuid.uuid4()))
    job = finished(reviews)
    assert (job["state"], job["report"]) == ("failed", None)
    assert job["error"] == (
        "The agent CLI could not complete this review. Check its sign-in and configuration."
    )


def test_review_of_part_of_a_session_is_marked_partial(make):
    large = [
        {"role": "user", "content": "Large " * 30000},
        {"role": "assistant", "content": "Small synthetic evidence"},
    ]
    reviews = make(captured("one", messages=large), max_tokens=1000)
    reviews.start("one", str(uuid.uuid4()))
    job = finished(reviews)
    assert job["state"] == "completed"
    assert (job["coverage"]["partial"], job["coverage"]["message_indexes"]) == (True, [1])


def test_report_citing_evidence_that_was_not_sent_fails_the_review(make):
    finding = {
        "title": "Synthetic finding",
        "category": "prompt_injection",
        "severity": "low",
        "confidence": "low",
        "message_index": 0,
        "evidence": "Large",
        "explanation": "Synthetic only",
        "suggestion": "Review the evidence",
    }
    large = [
        {"role": "user", "content": "Large " * 30000},
        {"role": "assistant", "content": "Small synthetic evidence"},
    ]
    driver = Driver(report={"summary": "Synthetic", "findings": [finding]})
    reviews = make(captured("one", messages=large), driver=driver, max_tokens=1000)
    reviews.start("one", str(uuid.uuid4()))
    job = finished(reviews)
    assert (job["state"], job["report"]) == ("failed", None)
    assert job["error"] == "The agent did not return a valid, evidence-linked security report."


IDLE_REVIEWS = {"background": True, "projects": ["/workspace/sample"]}


@pytest.mark.parametrize(
    ("device", "reason"),
    [
        (Device(60), "Waiting for idle time"),
        (Device(RuntimeError()), "Device idle detection is unavailable; manual reviews still work"),
    ],
    ids=["not-idle-long-enough", "idle-time-unavailable"],
)
def test_idle_reviews_wait_for_the_device_to_be_idle_long_enough(make, device, reason):
    reviews = make(captured("one"), device=device, **IDLE_REVIEWS)
    reviews.tick()
    assert (reviews.active, reviews.driver.prompts, reviews.scheduler_reason) == (None, [], reason)


@pytest.mark.parametrize("kind", ["hook", "session"])
def test_agent_activity_within_the_idle_window_keeps_reviews_waiting(make, kind):
    reviews = make()
    reviews.sessions.record(kind, time.time() - 20 * 60)
    assert reviews.idle(15)
    reviews.sessions.record(kind, time.time() - 60)
    assert not reviews.idle(15)
    assert reviews.idle_reason == "Waiting for observed agent activity to settle"


def test_the_reviews_own_captured_run_is_not_agent_activity(make):
    reviews = make(captured("one"))
    reviews.start("one", str(uuid.uuid4()))
    finished(reviews)
    run = {"source": "claude", "source_session_id": "review-run"}
    reviews.sessions.activity.append((time.time() - 60, run))
    assert reviews.idle(15)


def test_idle_reviews_take_the_newest_unreviewed_session_in_the_chosen_projects(make):
    elsewhere = captured("elsewhere", project="/workspace/other")
    reviews = make(captured("newest"), elsewhere, captured("older"), **IDLE_REVIEWS)
    order = []
    for _ in range(2):
        reviews.tick()
        order.append(finished(reviews)["session_id"])
    reviews.tick()
    assert order == ["newest", "older"]
    assert reviews.scheduler_reason == "No new sessions in your selected projects"


def test_idle_reviews_skip_their_own_captured_run_and_review_a_changed_session_again(make):
    reviews = make(captured("one"), **IDLE_REVIEWS)
    reviews.tick()
    finished(reviews)
    run = {**captured("run"), "source": "claude", "source_session_id": "review-run"}
    reviews.sessions.items = {"run": run, "one": {**captured("one"), "digest": "digest-changed"}}
    reviews.tick()
    job = finished(reviews)
    assert (job["session_id"], job["digest"]) == ("one", "digest-changed")
