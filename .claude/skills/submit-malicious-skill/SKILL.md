---
name: submit-malicious-skill
description: Report a malicious agent skill to the ADR maintainers as a GitHub issue that names its folder hash, then attach the skill's zip to that issue. Use when the user found a malicious skill (from a Discovery snapshot, a finding, or a detection result) and wants to report it.
allowed-tools: Bash, Read
---

# Report a malicious skill

You prepare one GitHub issue on the ADR repository. The skill's zip is
attached to the issue on GitHub after it is created.

## 1. Identify the skill
You need its folder hash (`skill_sha256`, 64 hex characters) and its zip.

- Take both from a Discovery snapshot: skill assets carry `skill_sha256`,
  `install_path`, `provenance` and, when the scan ran with
  `--archive-skills`, `archive.path`.
- No snapshot, or no archive? Scan with archiving on:
  `adr-discovery --output-dir OUT --archive-skills`
  (or `python -m adr_discovery.cli ...` from `Sensor/`), and read the
  skill from the newest `OUT/snapshot-*.json`.
- Check the zip is that skill. This must print the `skill_sha256`:
  ```
  python -c "import sys; from adr_discovery.archive import zip_content_sha256; print(zip_content_sha256(open(sys.argv[1], 'rb').read()))" <zip>
  ```

Ask the user in their own words why the skill is malicious, and for any
public links that back it up.

If `provenance` shows a private or local marketplace, ask whether the skill
belongs to their organisation. If it does, it should be reported there, not
here.

## 2. Prepare the issue
Title: `Malicious skill: <name> (<first 12 hex of skill_sha256>)`

Body:
~~~markdown
**Skill:** `<name>`
**Folder hash (`skill_sha256`):** `<skill_sha256>`
**Source:** <marketplace and plugin with version, and the marketplace repo, if public; otherwise "local or private">
**Seen at:** `~/<home-relative install path>`

**Why it is malicious**
<the user's reason>

**References**
- <https links, if any>

**Verify the attached zip**
`zip_content_sha256` of the zip must print the folder hash above:
`python -c "import sys; from adr_discovery.archive import zip_content_sha256; print(zip_content_sha256(open(sys.argv[1], 'rb').read()))" <skill_sha256>.zip`

**Proposed indicator**
```json
{"id": "skill-<name>-<first 12 hex>", "status": "active", "kind": "skill_sha256",
 "summary": "<one sentence: what the skill does>", "references": [...],
 "target": {"sha256": "<skill_sha256>"}}
```
~~~

Use home-relative paths only; no host names, user names or absolute paths.
Show the user the title and body in full and create the issue only after
they confirm, with `gh issue create --title ... --body-file ...` from a checkout of this repository.
Without `gh`, give them the text and the repository's new-issue link.

## 3. Attach the zip
After the issue exists, tell the user to:
1. Open it on GitHub.
2. Drag the zip into a comment (GitHub accepts `.zip` attachments) and post it.
   Its file name is the `skill_sha256`.

Never extract the zip into a skills directory or run anything from it.
