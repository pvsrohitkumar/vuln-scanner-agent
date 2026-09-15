# Vulnerability Scanner Agent

A web-based vulnerability scanner that clones repositories **locally**, scans them across **multiple ecosystems** for known security vulnerabilities, **automatically fixes** them by upgrading dependency versions, shows a **file-level diff** of every change, and lets you **create a pull request** — all from a single UI.

![Python](https://img.shields.io/badge/Python-3.12+-blue)
![Flask](https://img.shields.io/badge/Flask-3.x-green)

## Supported Ecosystems

| Ecosystem | Detected By | Audit Tool | Auto-Fix Target |
| --------- | ----------- | ---------- | --------------- |
| **Node.js / npm** (Angular, React, TypeScript) | `package.json` | `npm audit` | `package.json` |
| **Python** | `requirements.txt`, `pyproject.toml`, `setup.py`, `Pipfile` | `pip-audit` | `requirements.txt`, `pyproject.toml` |
| **Java / Maven** | `pom.xml` | OWASP Dependency-Check + OSV.dev API | `pom.xml` (direct & property versions) |
| **Java / Gradle** | `build.gradle`, `build.gradle.kts` | Gradle + OWASP / OSV.dev API | `build.gradle` / `build.gradle.kts` |
| **.NET** | `*.csproj`, `*.sln`, `*.fsproj` | `dotnet list package --vulnerable` | `*.csproj` / `*.fsproj` |

## Features

### Clone & Scan
- **Local cloning** — enter a Git URL and a **local directory path**; the repo is cloned (full depth) to your machine so all changes persist on disk.
- **Multi-ecosystem scanning** — automatically detects whether the repo is Node.js, Python, Java, or .NET.
- **OSV.dev integration** — for Java projects, falls back to the [OSV.dev](https://osv.dev/) API when the OWASP plugin is unavailable, providing accurate severity levels (Critical/High/Moderate/Low) and fix versions.
- **PDF report generation** — produces a professional, color-coded PDF with severity breakdown and fix suggestions.
- **Summary dashboard** — displays a live summary of Critical, High, Moderate, and Low findings in the browser.

### Apply Patch (Auto-Fix)
- **🩹 One-click patch** — after scanning, click **Apply Patch** to automatically upgrade vulnerable dependency versions **in your local clone**.
- **Iterative fix loop** — repeats a fix → build → re-scan cycle (up to 5 iterations) until the build succeeds with zero fixable vulnerabilities.
- **Ecosystem-aware upgrades** — updates the correct dependency manifest for each ecosystem:
  - **npm**: `package.json` (preserves `^`/`~` prefixes), runs `npm install`
  - **Python**: `requirements.txt` and `pyproject.toml` version pins
  - **Maven**: `pom.xml` — handles both direct `<version>` tags and `${property}` variable references
  - **Gradle**: `build.gradle` / `build.gradle.kts` dependency coordinates
  - **.NET**: `PackageReference` versions in `*.csproj`/`*.fsproj`, runs `dotnet restore`
- **Build verification** — runs the ecosystem's build command after applying fixes.
- **Before / After comparison** — side-by-side vulnerability count summary.

### Changed Files & Diff Viewer
- **📂 File list** — after patching, see every file that was modified, with a color-coded status badge (`modified`, `added`, `deleted`).
- **Click-to-expand diffs** — click any file to reveal a syntax-highlighted unified diff (green = additions, red = deletions, purple = hunk headers).

### Create Pull Request
- **🚀 One-click PR** — at the bottom of the results, enter a branch name and commit message (pre-filled with sensible defaults), then click **Create Pull Request**.
- The agent creates a fix branch, commits all changes, pushes to origin, and opens a PR via GitHub CLI (`gh`).
- Works with any Git remote you have push access to.

### UI
- **Modern UI** — dark-themed, glassmorphism-styled interface built with vanilla HTML/CSS/JS.
- **Real-time progress** — SSE-powered live progress log for cloning, scanning, patching, and PR creation.

## Tech Stack

| Layer       | Technology                                                             |
| ----------- | ---------------------------------------------------------------------- |
| Backend     | Python, Flask                                                          |
| Scanners    | `npm audit`, `pip-audit`, OWASP Dependency-Check, OSV.dev API, `dotnet` CLI |
| Auto-Fix    | Ecosystem-specific manifest rewriters + build verification             |
| PDF Reports | ReportLab                                                              |
| Frontend    | HTML, CSS, JavaScript (vanilla), Server-Sent Events (SSE)              |

## Prerequisites

Make sure the following are installed on your system:

- **Python 3.12+**
- **Git** — to clone target repositories
- **uv** *(recommended)* — Python package manager. Alternatively, you can use `pip` with a virtual environment.
- **GitHub CLI (`gh`)** *(optional)* — for automatic PR creation. Install from [cli.github.com](https://cli.github.com/). Without it, the branch will still be pushed but the PR must be opened manually.

Depending on the type of repositories you want to scan, you'll also need:

- **Node.js & npm** — for scanning JavaScript/TypeScript projects (Angular, React, etc.)
- **Maven** (`mvn`) — for scanning Java Maven projects
- **Gradle** — for scanning Java Gradle projects
- **.NET SDK** (`dotnet`) — for scanning .NET / C# projects

## Project Structure

```
vuln-scanner-agent/
├── app.py              # Flask web server (routes & API endpoints)
├── scanner.py          # Core scanning logic (clone → detect → audit → PDF)
├── fixReport.py        # Auto-fix engine (parse report → upgrade deps → build → re-scan loop)
├── requirements.txt    # Python dependencies
├── templates/
│   └── index.html      # Frontend UI (scan + fix dashboard)
├── reports/            # Generated PDF reports (auto-created)
└── README.md
```

## Getting Started

### 1. Clone this repository

```bash
git clone <your-repo-url>
cd vuln-scanner-agent
```

### 2. Create a virtual environment and install dependencies

**Using `uv` (recommended):**

```bash
uv venv .venv
# Activate the environment:
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

uv pip install -r requirements.txt
```

**Using `pip`:**

```bash
python -m venv .venv
# Activate the environment:
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

### 3. Run the application

```bash
python app.py
```

The server will start in **debug mode** on [http://127.0.0.1:5000](http://127.0.0.1:5000).

### 4. Clone & Scan a repository

1. Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.
2. Paste a **Git repository URL** (Node.js, Python, Java, or .NET project).
3. Enter a **local path** where the repo should be cloned (e.g. `C:\repos\my-project` or `/home/user/repos/my-project`).
4. Click **Clone & Scan**.
5. The repo is cloned to your chosen directory and the vulnerability scan runs on it.
6. View the vulnerability summary and download the PDF report.

### 5. Apply Patch (auto-fix)

1. After a scan completes, click the **🩹 Apply Patch** button (appears when fixable vulnerabilities are found).
2. The agent applies version upgrades **directly to your local clone**, verifies the build, and re-scans — repeating until clean or the max iteration limit (5) is reached.
3. View the **Before → After** comparison and the list of version upgrades applied.

### 6. Review changed files

1. After patching, the **📂 Files Changed** section lists every modified file.
2. Click any file to **expand its diff** — additions in green, deletions in red.
3. The changes are real files on your disk at the clone path you specified.

### 7. Create a Pull Request

1. At the bottom of the fix results, review the pre-filled **branch name** and **commit message**.
2. Click **🚀 Create Pull Request**.
3. The agent creates a branch, commits the changes, pushes to origin, and opens a PR via GitHub CLI.
4. A link to the PR is shown on success.

## API Endpoints

| Method | Endpoint               | Description                                                                   |
| ------ | ---------------------- | ----------------------------------------------------------------------------- |
| GET    | `/`                    | Serves the web UI                                                             |
| POST   | `/clone`               | Clone a repo to a local path. Body: `{ "repo_url", "clone_path" }`           |
| POST   | `/scan`                | Triggers a scan (temp clone). Body: `{ "repo_url": "<url>" }`                |
| GET    | `/scan/stream`         | SSE scan progress (temp clone). Query: `repo_url`                             |
| GET    | `/scan/local/stream`   | SSE scan progress on a local path. Query: `local_path`                        |
| POST   | `/fix/apply`           | SSE fix using scan rows (temp clone). Body: `{ "repo_url", "ecosystem", "rows" }` |
| POST   | `/fix/apply-local`     | SSE fix on local repo. Body: `{ "local_path", "ecosystem", "rows" }`         |
| POST   | `/fix/create-pr`       | Create branch, commit, push & PR. Body: `{ "patch_id", "branch_name", "commit_message" }` |
| POST   | `/fix/cleanup`         | Clean up a held patch repo. Body: `{ "patch_id" }`                            |
| GET    | `/download/<filename>` | Downloads a generated PDF report                                              |

## How It Works

### Clone & Scan

1. **Clone to local path** — The repo is cloned (full depth) to a user-specified directory. If the directory already contains the repo, it is reused.
2. **Detect** — The scanner inspects the repo root for ecosystem markers (`package.json`, `requirements.txt`, `pom.xml`, `*.csproj`, etc.).
3. **Audit** — The appropriate audit tool is executed:
   - **npm** → `npm install --ignore-scripts` then `npm audit --json`
   - **Python** → `pip-audit -r requirements.txt --format json`
   - **Maven** → OWASP Dependency-Check plugin → fallback to `mvn dependency:list` + [OSV.dev API](https://osv.dev/) for vulnerability lookup with proper severity and fix versions
   - **Gradle** → CycloneDX BOM → OWASP plugin → fallback to `gradle dependencies` + OSV.dev API
   - **.NET** → `dotnet list package --vulnerable --include-transitive`
4. **Report** — Results are normalised, sorted by severity, and rendered into a color-coded PDF using ReportLab.

### Apply Patch (`fixReport.py`)

1. **Parse Fix Actions** — Extracts actionable version upgrades from the scan report (package name, current version, target fix version). De-duplicates by package, keeping the highest fix version.
2. **Apply Fixes** — Uses ecosystem-specific manifest rewriters to update dependency versions **in the local clone**:
   - **npm**: Modifies `package.json`, preserves version range prefixes (`^`, `~`), runs `npm install`.
   - **Python**: Updates pinned versions in `requirements.txt` and `pyproject.toml`.
   - **Maven**: Parses `pom.xml` with XML and regex — handles both direct `<version>` tags and `${property}` variable references in `<properties>`.
   - **Gradle**: Replaces `group:artifact:version` coordinates in `build.gradle` / `build.gradle.kts`.
   - **.NET**: Updates `PackageReference Version="..."` in `*.csproj` / `*.fsproj`, runs `dotnet restore`.
3. **Build Verification** — Runs the ecosystem's build command (`npm run build`, `mvn compile -DskipTests`, `gradle build -x test`, `dotnet build`).
4. **Re-scan & Repeat** — Re-scans and repeats steps 1–3 until:
   - ✅ Build succeeds with zero fixable vulnerabilities, **or**
   - ⛔ Maximum iteration limit (5) is reached.
5. **Collect Diffs** — Runs `git diff` to capture all changed files and their unified diffs.
6. **Final Report** — Generates a new PDF and returns before/after comparison, applied fixes, iteration log, and changed file diffs.

### Create Pull Request

1. **Create branch** — A fix branch (e.g. `fix/vuln-patch-abc12345`) is created on the local clone.
2. **Commit** — All changes are staged and committed with the user-specified commit message.
3. **Push** — The branch is pushed to the remote origin.
4. **Open PR** — If GitHub CLI (`gh`) is installed and authenticated, a pull request is automatically opened. Otherwise, the branch is pushed and the user can open the PR manually.

## Notes

- The scanner auto-detects the ecosystem based on files in the repository root.
- If multiple ecosystem markers exist (e.g., `package.json` + `requirements.txt`), the first detected match wins — priority: npm → Python → Maven/Gradle → .NET.
- The scanned repository must be publicly accessible (or accessible via your Git credentials).
- Reports are stored in the `reports/` directory and persist between runs.
- The app runs Flask's built-in development server — use a production WSGI server (e.g., Gunicorn) for deployment.
- For Java scanning, the OWASP Dependency-Check Maven plugin is tried first. If unavailable, the scanner falls back to resolving dependencies via `mvn dependency:list` (or direct `pom.xml` parsing) and querying the [OSV.dev API](https://osv.dev/) for known vulnerabilities with accurate CVSS-based severity levels and fix versions.
- For Python scanning, `pip-audit` is included as a dependency and runs against the project's `requirements.txt`.
- The **Clone & Scan** flow clones the repo to a user-specified local directory (full depth). All fixes are applied **directly to this local clone**, so changes persist on disk and are ready for commit.
- Fix versions are extracted from the scan report's "Fix / Advisory" column. Vulnerabilities that only have an advisory URL (no concrete fix version) are skipped during auto-fix.
- The max iteration limit of 5 prevents infinite loops when fixes introduce new vulnerabilities or builds keep failing.
- To create a PR, you need **push access** to the remote repository. If using GitHub, authenticate via `gh auth login` for automatic PR creation.
- The legacy temp-clone endpoints (`/scan/stream`, `/fix/apply`) are still available for programmatic use without local cloning.
