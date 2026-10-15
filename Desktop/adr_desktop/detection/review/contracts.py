"""Errors that cross the boundary between Desktop and detection's review part."""

ERRORS = {
    "cli_missing": "Install the selected agent CLI, then try again.",
    "cli_failed": "The agent CLI could not complete this review. Check its sign-in and configuration.",
    "cli_incompatible": "Update the agent CLI to a version supporting isolated, structured reviews.",
    "usage_unavailable": "The agent did not report usage. The review reservation is retained.",
    "rate_limited": "The agent reported a usage limit. No automatic retry will run.",
    "paid_not_allowed": "This CLI uses API or managed access. Allow paid access in review settings first.",
    "cancelled": "Review stopped. Usage already consumed still counts.",
    "timeout": "The review reached its time limit. Its budget reservation is retained.",
    "token_limit": "The review reached its token limit. An in-flight response can exceed the limit.",
    "cost_limit": "The review reached its reported cost limit. An in-flight response can exceed the limit.",
    "unsafe_tool": "The review attempted a tool operation and was stopped.",
    "output_limit": "The agent returned more output than this review can safely process.",
    "invalid_report": "The agent did not return a valid, evidence-linked security report.",
    "isolation_unavailable": (
        "This agent configuration cannot isolate a read-only review. No evidence was sent."
    ),
}


class ReviewError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(ERRORS.get(code, ERRORS["cli_failed"]))
