# Releasing ADR Sensor

ADR Sensor releases publish the `adr-sensor` package, which contains both `adr_sensor` and `adr_discovery` and installs the `adr-sensor` and `adr-discovery` commands. Releases are built from GitHub Release tags and published to PyPI through OpenID Connect Trusted Publishing. The workflow does not use a long-lived PyPI token.

## One-time repository setup

Complete these steps before publishing the first release:

1. In the GitHub repository settings, create an environment named `pypi`.
2. Add required reviewers to the environment and restrict deployment tags to `sensor-v*`.
3. On PyPI, create a pending Trusted Publisher for the `adr-sensor` project with these values:

   - Owner: `uber`
   - Repository: `ADR`
   - Workflow: `release-sensor.yml`
   - Environment: `pypi`

PyPI can create the project during the first successful publication when a pending publisher is configured. See the [PyPI Trusted Publishing guide](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).

## Release process

1. Update `project.version` in `Sensor/pyproject.toml`.
2. From `Sensor/`, run `uv lock` and commit the updated lockfile.
3. Pin Desktop to the new version: set `adr-sensor==X.Y.Z` in `Desktop/pyproject.toml` and run `uv lock` from `Desktop/`. Desktop CI fails when the pin differs from `project.version`.
4. Update the release notes and open a pull request.
5. Verify that CI succeeds and merge the pull request to `main`.
6. In GitHub Releases, create a release targeting `main` with a tag named `sensor-vX.Y.Z`. The tag version must exactly match `project.version`.
7. Publish the GitHub Release.
8. Approve the `pypi` environment deployment when prompted.

The `Release ADR Sensor` workflow then performs these actions:

1. Checks out the exact release tag.
2. Confirms that the tag and package version match.
3. Runs the Sensor and Discovery test suites and builds the wheel and source distribution.
4. Publishes both distributions to PyPI using a short-lived OpenID Connect credential.
5. Attaches the distributions to the GitHub Release.

Package versions on PyPI are immutable. If publication succeeds, never move or reuse the release tag. Publish any correction as a new version.
