"""Run audit: which agent session a credential-backed run belongs to. Content-free."""

import re

NATIVE_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,511}")


def record_session(store, run_id, grant_id, harness, session_id):
    """A hook may associate only an existing run from its verified MCP grant."""
    if not NATIVE_SESSION_ID.fullmatch(session_id):
        return False
    with store.transaction() as connection:
        run = connection.execute(
            "SELECT id FROM environment_runs WHERE id=? AND grant_id=?", (run_id, grant_id)
        ).fetchone()
        if not run:
            return False
        connection.execute(
            """INSERT INTO environment_run_context(run_id,harness,session_id,ambiguous)
               VALUES (?,?,?,0)
               ON CONFLICT(run_id) DO UPDATE SET ambiguous=(
                   environment_run_context.ambiguous OR environment_run_context.harness<>excluded.harness
                   OR environment_run_context.session_id<>excluded.session_id)""",
            (run_id, harness, session_id),
        )
    return True
