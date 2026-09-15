# Vulnerability Scanner Agent

A web-based vulnerability scanner that analyzes repositories across **multiple ecosystems** for known security vulnerabilities. It auto-detects the project type, runs the appropriate audit tool, generates a detailed **PDF report** with color-coded severity levels, and can **automatically fix vulnerabilities** by upgrading dependency versions in a scan → fix → build → re-scan loop.

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

### Scanning
- **Multi-ecosystem scanning** — automatically detects whether the repo is Node.js, Python, Java, or .NET.
- **One-click scanning** — paste a Git repository URL and get a full vulnerability report.
- **OSV.dev integration** — for Java projects, falls back to the [OSV.dev](https://osv.dev/) API when the OWASP plugin is unavailable, providing accurate severity levels (Critical/High/Moderate/Low) and fix versions.
- **Automated pipeline** — clones the repo, detects the ecosystem, runs the appropriate audit, and collects results.
- **PDF report generation** — produces a professional, color-coded PDF with severity breakdown and fix suggestions.
- **Downloadable reports** — reports are saved to the `reports/` directory and can be downloaded directly from the UI.
- **Summary dashboard** — displays a live summary of Critical, High, Moderate, and Low findings in the browser.

### Auto-Fix (new)
- **🔧 One-click fix** — after scanning, click **Fix Vulnerabilities** to automatically apply version upgrades.
- **Iterative fix loop** — the agent repeats a scan → fix → build → re-scan cycle (up to 5 iterations) until the build succeeds with zero fixable vulnerabilities.
- **Ecosystem-aware upgrades** — updates the correct dependency manifest for each ecosystem:
  - **npm**: `package.json` (preserves `^`/`~` prefixes), runs `npm install`
  - **Python**: `requirements.txt` and `pyproject.toml` version pins
  - **Maven**: `pom.xml` — handles both direct `<version>` tags and `${property}` variable references
  - **Gradle**: `build.gradle` / `build.gradle.kts` dependency coordinates
  - **.NET**: `PackageReference` versions in `*.csproj`/`*.fsproj`, runs `dotnet restore`
- **Build verification** — after applying fixes, runs the ecosystem's build command to verify the project still compiles.
- **Before / After comparison** — shows a side-by-side summary of vulnerability counts before and after the fix.
- **Iteration log** — displays a per-iteration breakdown of fixes applied, build status, and remaining vulnerabilities.
- **Fixed report PDF** — generates a new PDF report reflecting the post-fix state of the project.

### UI
- **Modern UI** — dark-themed, glassmorphism-styled interface built with vanilla HTML/CSS/JS.
- **Real-time progress** — SSE-powered live progress log for both scanning and fixing.

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

### 4. Scan a repository

1. Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.
2. Paste a public Git repository URL (Node.js, Python, Java, or .NET project).
3. Click **Scan** and wait for the analysis to complete.
4. View the vulnerability summary in the dashboard and download the PDF report.

### 5. Auto-fix vulnerabilities

1. After a scan completes, click the **🔧 Fix Vulnerabilities** button (appears when fixable vulnerabilities are found).
2. The agent will:
   - Clone the repo again
   - Run a fresh scan to identify vulnerabilities with known fix versions
   - Upgrade dependency versions in the project's manifest files
   - Run the project's build command to verify the fix compiles
   - Re-scan to check for remaining vulnerabilities
   - Repeat the cycle until the build succeeds or the max iteration limit (5) is reached
3. View the **Before → After** comparison, the list of version upgrades applied, and the iteration log.
4. Download the **Fixed Report PDF** reflecting the post-fix state.

## API Endpoints

| Method | Endpoint              | Description                                              |
| ------ | --------------------- | -------------------------------------------------------- |
| GET    | `/`                   | Serves the web UI                                        |
| POST   | `/scan`               | Triggers a scan. Body: `{ "repo_url": "<url>" }`        |
| GET    | `/scan/stream`        | SSE stream for real-time scan progress. Query: `repo_url` |
| GET    | `/fix/stream`         | SSE stream for the auto-fix loop. Query: `repo_url`      |
| GET    | `/download/<filename>`| Downloads a generated PDF report                         |

## How It Works

### Scanning

1. **Clone** — The target repository is shallow-cloned (`--depth 1`) into a temporary directory.
2. **Detect** — The scanner inspects the repo root for ecosystem markers (`package.json`, `requirements.txt`, `pom.xml`, `*.csproj`, etc.).
3. **Audit** — The appropriate audit tool is executed:
   - **npm** → `npm install --ignore-scripts` then `npm audit --json`
   - **Python** → `pip-audit -r requirements.txt --format json`
   - **Maven** → OWASP Dependency-Check plugin → fallback to `mvn dependency:list` + [OSV.dev API](https://osv.dev/) for vulnerability lookup with proper severity and fix versions
   - **Gradle** → CycloneDX BOM → OWASP plugin → fallback to `gradle dependencies` + OSV.dev API
   - **.NET** → `dotnet list package --vulnerable --include-transitive`
4. **Report** — Results are normalised, sorted by severity, and rendered into a color-coded PDF using ReportLab.
5. **Cleanup** — The temporary clone is deleted after the scan completes.

### Auto-Fix (`fixReport.py`)

1. **Clone & Scan** — Clones the repo and runs the full vulnerability scan to get the report.
2. **Parse Fix Actions** — Extracts actionable version upgrades from each vulnerability row (package name, current version, target fix version). De-duplicates by package, keeping the highest fix version.
3. **Apply Fixes** — Uses ecosystem-specific manifest rewriters to update dependency versions:
   - **npm**: Modifies `package.json`, preserves version range prefixes (`^`, `~`), runs `npm install`.
   - **Python**: Updates pinned versions in `requirements.txt` and `pyproject.toml`.
   - **Maven**: Parses `pom.xml` with XML and regex — handles both direct `<version>` tags and `${property}` variable references in `<properties>`.
   - **Gradle**: Replaces `group:artifact:version` coordinates in `build.gradle` / `build.gradle.kts`.
   - **.NET**: Updates `PackageReference Version="..."` in `*.csproj` / `*.fsproj`, runs `dotnet restore`.
4. **Build Verification** — Runs the ecosystem's build command (`npm run build`, `mvn compile -DskipTests`, `gradle build -x test`, `dotnet build`) to verify the project still compiles.
5. **Re-scan & Repeat** — Re-scans for remaining vulnerabilities and repeats steps 2–4 until:
   - ✅ The build succeeds with zero fixable vulnerabilities, **or**
   - ⛔ The maximum iteration limit (5) is reached.
6. **Final Report** — Generates a new PDF report reflecting the post-fix state and returns a structured result with before/after comparison, applied fixes, and iteration log.

## Notes

- The scanner auto-detects the ecosystem based on files in the repository root.
- If multiple ecosystem markers exist (e.g., `package.json` + `requirements.txt`), the first detected match wins — priority: npm → Python → Maven/Gradle → .NET.
- The scanned repository must be publicly accessible (or accessible via your Git credentials).
- Reports are stored in the `reports/` directory and persist between runs.
- The app runs Flask's built-in development server — use a production WSGI server (e.g., Gunicorn) for deployment.
- For Java scanning, the OWASP Dependency-Check Maven plugin is tried first. If unavailable, the scanner falls back to resolving dependencies via `mvn dependency:list` (or direct `pom.xml` parsing) and querying the [OSV.dev API](https://osv.dev/) for known vulnerabilities with accurate CVSS-based severity levels and fix versions.
- For Python scanning, `pip-audit` is included as a dependency and runs against the project's `requirements.txt`.
- The auto-fix engine modifies dependency manifests **in the cloned temp directory only** — your original repository is never modified.
- Fix versions are extracted from the scan report's "Fix / Advisory" column. Vulnerabilities that only have an advisory URL (no concrete fix version) are skipped during auto-fix.
- The max iteration limit of 5 prevents infinite loops when fixes introduce new vulnerabilities or builds keep failing.
