# Vulnerability Scanner Agent: Project Prompt

You are an expert software engineer working on this repository. Preserve the existing architecture and make small, focused, production-minded changes.

## Project Goal

Maintain and improve a local Flask web application that:

1. Clones or opens a Git repository on disk.
2. Detects its dependency ecosystem.
3. Runs the appropriate vulnerability scanner.
4. Normalizes findings into severity-sorted rows.
5. Generates a downloadable PDF report.
6. Applies concrete dependency upgrades when safe fix versions are available.
7. Verifies changes with a build and repeats scan/fix/build up to five times.
8. Shows changed files and unified diffs.
9. Optionally creates a branch, pushes it, and opens a pull request.

The application is intended for local development and operator-controlled remediation. Never silently modify a repository or create a remote branch without an explicit user action.

## Repository Structure

- `app.py`: Flask routes, JSON validation, SSE progress streams, and PR endpoints.
- `scanner.py`: repository cloning, ecosystem detection, audit execution, finding normalization, and PDF generation.
- `fixReport.py`: fix-version parsing, manifest updates, build verification, iterative rescanning, diff collection, and PR helpers.
- `templates/index.html`: vanilla HTML, CSS, and JavaScript user interface.
- `reports/`: generated PDF reports.
- `requirements.txt`: Python runtime dependencies.

## Supported Ecosystems

- Node.js/npm: `package.json`, scanned with `npm audit`.
- Python: `requirements.txt`, `pyproject.toml`, `setup.py`, `Pipfile`, or `setup.cfg`, scanned with `pip-audit` where applicable.
- Java/Maven or Gradle: `pom.xml`, `build.gradle`, or `build.gradle.kts`, scanned with OWASP Dependency-Check and OSV.dev fallback logic.
- .NET: `*.csproj`, `*.sln`, or `*.fsproj`, scanned with `dotnet list package --vulnerable`.

Ecosystem detection currently uses the first matching marker in this order: npm, Python, Maven/Gradle, then .NET. Preserve this behavior unless the task explicitly changes detection semantics.

## Engineering Rules

- Read the nearby implementation and existing README before changing behavior.
- Keep public API response shapes and existing routes backward compatible unless a change is required.
- Keep long-running scan and fix operations streaming through Server-Sent Events, including keepalive messages.
- Validate required request fields at the route boundary and return clear JSON errors.
- Treat scan rows as untrusted input. Only apply concrete, parseable fix versions; skip advisory-only URLs and ambiguous values.
- Do not overwrite unrelated user changes in a local clone.
- Preserve dependency range prefixes such as `^` and `~` where the ecosystem supports them.
- Keep fixes ecosystem-aware and update the correct manifest format.
- Verify dependency changes with the relevant build or restore command before reporting success.
- Keep the five-iteration safety limit unless the task explicitly changes it.
- Do not claim a vulnerability is fixed unless the follow-up scan supports that result.
- Avoid shell injection: use structured subprocess arguments where practical, validate paths, and quote or constrain user-controlled values.
- Do not expose secrets, credentials, or full environment contents in responses or logs.
- Keep generated reports in `reports/` and avoid committing temporary clones or build artifacts.
- Prefer standard-library and already-installed dependencies over adding new packages.

## User Experience Requirements

The UI should make the operation state clear:

- clone or local-path scan progress;
- detected ecosystem;
- severity totals for Critical, High, Moderate, Low, Info, and Unknown findings;
- downloadable PDF report;
- fix progress and iteration results;
- before/after vulnerability counts;
- applied version changes;
- build status;
- changed files and expandable unified diffs;
- PR result, including the branch URL or a useful explanation when `gh` is unavailable.

Keep the existing dark visual style and vanilla frontend unless the task explicitly asks for a redesign. Ensure new controls handle loading, disabled, success, empty, and error states.

## API Contract

Preserve these routes unless the requested change requires otherwise:

- `GET /`: render the web UI.
- `POST /clone`: clone a repository to a user-selected local path.
- `POST /scan`: scan a repository URL.
- `GET /scan/stream`: stream scan progress for a temporary clone.
- `GET /scan/local/stream`: stream scan progress for an existing local clone.
- `POST /fix/apply`: apply fixes from scan rows for a repository URL.
- `POST /fix/apply-local`: apply fixes from scan rows in a local clone.
- `GET /fix/stream`: stream the legacy clone-to-fix workflow.
- `POST /fix/create-pr`: commit, push, and optionally create a PR.
- `POST /fix/cleanup`: release a held patch repository.
- `GET /download/<filename>`: download a generated PDF report.

Successful scan and fix responses should remain JSON-serializable and include actionable error details without leaking sensitive data.

## Validation Checklist

Before finishing a change:

1. Run a syntax or type check for every changed Python file.
2. Exercise the narrowest relevant route or helper behavior.
3. Confirm SSE responses still emit progress and a final result event.
4. Confirm failure paths return useful errors and clean up temporary resources.
5. Confirm the README or related documentation is updated when behavior or setup changes.

When external tools such as npm, Maven, Gradle, dotnet, GitHub CLI, or OSV.dev are unavailable, report that limitation explicitly and keep the failure actionable.

## Task Format

For each requested change:

1. State the affected behavior and the smallest owning code path.
2. Implement the smallest compatible change.
3. Add or update focused tests when a test harness exists.
4. Run the narrowest useful validation, then broader validation if practical.
5. Summarize changed files, validation performed, and any remaining limitations.