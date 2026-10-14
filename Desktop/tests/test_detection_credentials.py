"""Detection's credential check reaches the owner's saved values only through the SavedValueCheck port."""

import pytest

from adr_desktop.detection.inline.credentials import find_credentials

GITHUB_TOKEN = "ghp_" + "a" * 36


class SavedValues:
    """A fake SavedValueCheck that reports a fixed answer and records each question."""

    def __init__(self, *names, matched=None):
        self.names = list(names)
        self.matched = bool(names) if matched is None else matched
        self.calls = []

    def check(self, text, purpose):
        self.calls.append((text, purpose))
        return self.matched, self.names


def test_saved_value_is_a_finding_next_to_known_formats_and_its_names_come_back():
    text = f"Deploy with {GITHUB_TOKEN} and the database password"
    kinds, names = find_credentials(text, SavedValues("DB_PASSWORD"), prompt=True)
    assert kinds == ["GitHub token", "Saved credential"]
    assert names == ["DB_PASSWORD"]


def test_saved_value_without_a_variable_name_is_still_a_finding():
    # API-only credentials have no variable name.
    assert find_credentials("Synthetic text", SavedValues(matched=True), prompt=False) == (
        ["Saved credential"], [],
    )


def test_prompts_are_also_checked_for_password_assignments_and_outputs_only_for_known_formats():
    text = "My password is Correct-Horse-Synthetic"
    saved = SavedValues()
    assert find_credentials(text, saved, prompt=True) == (["Possible password or key"], [])
    assert find_credentials(text, saved, prompt=False) == ([], [])
    assert saved.calls == [(text, "prompt"), (text, "output")]


def test_text_whose_saved_values_cannot_be_checked_is_not_reported_clean():
    class Unavailable:
        def check(self, text, purpose):
            raise TimeoutError("The vault did not answer")

    with pytest.raises(TimeoutError):
        find_credentials("Synthetic text", Unavailable(), prompt=True)
