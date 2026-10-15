"""Which files an agent operation touches: tool tables, path resolution and literal shell reads."""

import errno
import io
import shlex
import unicodedata
from pathlib import Path
from urllib.parse import unquote, urlsplit

DIRECT_TOOLS = {
    "read",
    "write",
    "edit",
    "multiedit",
    "notebookedit",
    "read_file",
    "write_file",
    "edit_file",
    "create_file",
    "view",
    "str_replace",
    "str_replace_editor",
}
SEARCH_TOOLS = {"glob", "grep", "list_dir", "list_directory", "find_files", "search_files"}
SAFE_TOOLS = {
    "todowrite",
    "askuserquestion",
    "enterplanmode",
    "exitplanmode",
    "taskcreate",
    "taskupdate",
    "tasklist",
    "taskget",
    "toolsearch",
    "collaboration.send_message",
    "collaborationsend_message",
    "collaboration.list_agents",
    "collaborationlist_agents",
    "collaboration.wait_agent",
    "collaborationwait_agent",
    "functions.get_goal",
    "functions.request_user_input",
}
PATH_KEYS = ("file_path", "filePath", "filepath", "path", "notebook_path")
SHELL_TOOLS = {"bash", "exec_command", "functions.exec_command", "shell", "shell_command"}


def printable(value: str) -> str:
    return "".join(
        f"\\u{ord(char):04x}" if unicodedata.category(char).startswith("C") else char for char in value
    )


def display(value, maximum=8192):
    return printable(str(value))[:maximum]


def resolve_path(value: str, cwd: str) -> Path:
    if not isinstance(value, str) or not value or len(value) > 8192 or "\x00" in value:
        raise ValueError("Invalid file path")
    if value.startswith("file:"):
        parsed = urlsplit(value)
        if parsed.netloc not in ("", "localhost") or parsed.query or parsed.fragment:
            raise ValueError("Unsupported file URL")
        value = unquote(parsed.path)
    elif "://" in value:
        raise ValueError("Not a local file path")
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = Path(cwd) / path
    resolved = path.resolve(strict=False)
    # Python 3.13 no longer raises for symlink loops in non-strict resolve().
    # Check both spellings so missing/.. or loop/.. cannot conceal a loop.
    # Preserve non-strict handling of missing/inaccessible metadata: the rule
    # still protects that spelling, and must not disable unrelated operations.
    for candidate in (path, resolved):
        try:
            candidate.stat()
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise
    return resolved


def project_path(value: str) -> str:
    return str(resolve_path(value, str(Path.home())))


def literal_shell_files(arguments: dict, cwd: str) -> list[Path]:
    """Recognize a small set of literal reads, without executing or expanding shell.

    This deliberately is not a shell interpreter. Pipelines, substitutions,
    redirects, compound commands, scripts, and other executables remain subject
    to the user's existing unclassified-execution setting.
    """
    command = arguments.get("command", arguments.get("cmd"))
    if not isinstance(command, str) or len(command) > 16384:
        return []
    def words_with_quoting(text):
        # Keep whether a leading tilde was quoted: "~/file" is relative to
        # cwd, while ~/file uses the shell's home expansion.
        text = text.strip()
        stream = io.StringIO(text)
        lexer = shlex.shlex(stream, posix=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        result = []
        try:
            while True:
                offset = stream.tell()
                if text[offset:].lstrip().startswith("#"):
                    break
                word = lexer.get_token()
                if word is None:
                    break
                raw = text[offset:stream.tell()]
                if any(character in raw for character in "\n\r;&|<>`$()*?[]{}"):
                    return []
                result.append((word, raw.lstrip().startswith("~")))
                if len(result) > 128:
                    return []
        except ValueError:
            return []
        return result

    words = words_with_quoting(command)
    if not words or len(words) > 128:
        return []
    executable = Path(words[0][0]).name
    if executable in {"sh", "bash", "zsh", "dash"}:
        if len(words) != 3 or words[1][0] not in {"-c", "-lc"}:
            return []
        # Codex may supply the canonical shell wrapper rather than just the
        # command text. Accept only one bounded wrapper, not nested scripts.
        words = words_with_quoting(words[2][0])
        if not words or len(words) > 128:
            return []
        executable = Path(words[0][0]).name
    if executable not in {"cat", "head", "tail"}:
        return []
    directory = arguments.get("workdir", arguments.get("cwd", cwd))
    directory = str(resolve_path(directory, cwd))
    files = []
    options = True
    skip_count = False
    for word, expand_tilde in words[1:]:
        if skip_count:
            # Counts are not paths. Anything not a literal count is outside
            # this bounded recognizer (including a missing option argument).
            if not word.lstrip("+-").isdigit():
                return []
            skip_count = False
            continue
        if options and word == "--":
            options = False
            continue
        if options and word.startswith("-") and word != "-":
            if executable == "cat":
                short = word.startswith("-") and not word.startswith("--") and set(word[1:]) <= set(
                    "AbeEnstTuv"
                )
                long = word in {
                    "--show-all", "--number-nonblank", "--show-ends", "--number",
                    "--squeeze-blank", "--show-tabs", "--show-nonprinting",
                }
                if not short and not long:
                    return []
            elif word in {"-n", "-c", "--lines", "--bytes"}:
                skip_count = True
            elif word in {"-q", "-v", "--quiet", "--silent", "--verbose"}:
                pass
            elif executable == "tail" and word in {"-f", "-F", "--follow", "--retry"}:
                pass
            elif word[1:].isdigit() or (
                word.startswith(("-n", "-c")) and word[2:].lstrip("+-").isdigit()
            ):
                pass
            elif word.startswith(("--lines=", "--bytes=")) and word.split("=", 1)[1].lstrip("+-").isdigit():
                pass
            else:
                return []
            continue
        # BSD tools stop option processing at the first operand. Treat later
        # option-looking words as possible filenames on every host, rather
        # than silently ignoring an actually accessed "-n" file on macOS.
        options = False
        if word != "-":
            if word.startswith("~") and not expand_tilde:
                word = str(Path(directory) / word)
            files.append(resolve_path(word, directory))
    return [] if skip_count else files
