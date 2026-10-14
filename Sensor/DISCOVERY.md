# ADR Discovery

ADR Discovery inventories AI tooling on an endpoint, including AI binaries,
desktop applications, agents, MCP servers, skills, plugins, and related
programmable surfaces. It records the evidence behind each finding and reports
coverage gaps so an incomplete scan is not mistaken for a clean machine.

Discovery ships in the `adr-sensor` package as its own import package,
`adr_discovery`, with the `adr-discovery` command. It runs on Python 3.11+,
imports only the standard library, and never imports `adr_sensor`.
Programs that embed it import only `adr_discovery.api`.

## Quick start

Run a scan from `Sensor/` with [`uv`](https://docs.astral.sh/uv/):

```sh
uv run adr-discovery --dry-run --json
```

To see exactly what the collector would emit without writing a snapshot:

```sh
uv run adr-discovery --dry-run --explain
```

Use `--output-dir` to save scan output:

```sh
uv run adr-discovery --output-dir ./output
```

Run `uv run adr-discovery --help` for all options.

## Common workflows

Scan a fixture tree instead of the live endpoint:

```sh
uv run adr-discovery --root /path/to/fixture --dry-run --json
```

Compare the current scan with an earlier snapshot:

```sh
uv run adr-discovery --diff /path/to/snapshot.json --dry-run --json
```

Apply a tenant policy or last-used telemetry during a scan:

```sh
uv run adr-discovery \
  --policy /path/to/policy.json \
  --telemetry /path/to/telemetry.json \
  --dry-run --json
```

Discovery does not execute binaries that it finds. Machine access is bounded,
and risky text is redacted at collection time.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | The scan completed with full available coverage. |
| `2` | The scan completed, but one or more surfaces were unavailable, unreadable, or truncated. A snapshot is still produced. |
| Other | The command could not complete because of an error or invalid input. |

## Development

Install the development dependencies and run the checks:

```sh
uv sync --extra dev
uv run pytest -q tests/discovery
uv run ruff check adr_discovery tests/discovery
```

Ruff reads Discovery's own settings from `adr_discovery/ruff.toml`.
The test suite has two layers:

- `tests/discovery/unit/` verifies modules, contracts, security boundaries,
  the composed pipeline, and the public API.
- `tests/discovery/` is the black-box endpoint harness used to compare known installations
  with the collector's reported snapshot.

## Project layout

```text
adr_discovery/
  catalog/       known-tool catalog and validation
  contracts/     shared records, evidence, and snapshot types
  coverage/      coverage accounting
  enumerator/    endpoint source enumeration
  extractor/     declaration and surface extraction
  identifier/    evidence-based identification
  judge/         risk, sanction, and finding evaluation
  redact/        sensitive-data redaction
  reporter/      snapshots and deltas
  resolver/      observation merging and confidence
  world/         bounded, platform-specific machine access
  api.py         public interface for programs that embed Discovery
  cli.py         command-line interface
  pipeline.py    pipeline composition
tests/discovery/ black-box endpoint test harness
  unit/          module, pipeline and API tests
```

For the architecture, data model, security boundaries, current limitations,
and implementation details, see the [package documentation](adr_discovery/README.md).
For end-to-end validation and VM provisioning, see the
[test harness documentation](tests/discovery/README.md).

## License

Apache-2.0.
