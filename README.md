# Vulnerability Scanner Agent

A web-based vulnerability scanner that analyzes repositories across **multiple ecosystems** for known security vulnerabilities. It auto-detects the project type, runs the appropriate audit tool, and generates a detailed **PDF report** with color-coded severity levels.

![Python](https://img.shields.io/badge/Python-3.12+-blue)
![Flask](https://img.shields.io/badge/Flask-3.x-green)

## Supported Ecosystems

| Ecosystem | Detected By | Audit Tool |
| --------- | ----------- | ---------- |
| **Node.js / npm** (Angular, React, TypeScript) | `package.json` | `npm audit` |
| **Python** | `requirements.txt`, `pyproject.toml`, `setup.py`, `Pipfile` | `pip-audit` |
| **Java / Maven** | `pom.xml` | OWASP Dependency-Check Maven Plugin |
| **Java / Gradle** | `build.gradle`, `build.gradle.kts` | Gradle + OWASP Plugin |
| **.NET** | `*.csproj`, `*.sln`, `*.fsproj` | `dotnet list package --vulnerable` |

## Features

- **Multi-ecosystem scanning** — automatically detects whether the repo is Node.js, Python, Java, or .NET.
- **One-click scanning** — paste a Git repository URL and get a full vulnerability report.
- **Automated pipeline** — clones the repo, detects the ecosystem, runs the appropriate audit, and collects results.
- **PDF report generation** — produces a professional, color-coded PDF with severity breakdown and fix suggestions.
- **Downloadable reports** — reports are saved to the `reports/` directory and can be downloaded directly from the UI.
- **Summary dashboard** — displays a live summary of Critical, High, Moderate, and Low findings in the browser.
- **Modern UI** — dark-themed, glassmorphism-styled interface built with vanilla HTML/CSS/JS.

## Tech Stack

| Layer       | Technology                                                  |
| ----------- | ----------------------------------------------------------- |
| Backend     | Python, Flask                                               |
| Scanners    | `npm audit`, `pip-audit`, OWASP Dependency-Check, `dotnet` CLI |
| PDF Reports | ReportLab                                                   |
| Frontend    | HTML, CSS, JavaScript (vanilla)                             |

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
├── scanner.py          # Core scanning logic (clone → install → audit → PDF)
├── requirements.txt    # Python dependencies
├── templates/
│   └── index.html      # Frontend UI
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
2. Paste a public Git repository URL containing a `package.json` (e.g., a Node.js project).
3. Click **Scan** and wait for the analysis to complete.
4. View the vulnerability summary in the dashboard and download the PDF report.

## API Endpoints

| Method | Endpoint              | Description                        |
| ------ | --------------------- | ---------------------------------- |
| GET    | `/`                   | Serves the web UI                  |
| POST   | `/scan`               | Triggers a scan. Body: `{ "repo_url": "<url>" }` |
| GET    | `/download/<filename>`| Downloads a generated PDF report   |

## How It Works

1. **Clone** — The target repository is shallow-cloned (`--depth 1`) into a temporary directory.
2. **Detect** — The scanner inspects the repo root for ecosystem markers (`package.json`, `requirements.txt`, `pom.xml`, `*.csproj`, etc.).
3. **Audit** — The appropriate audit tool is executed:
   - **npm** → `npm install --ignore-scripts` then `npm audit --json`
   - **Python** → `pip-audit -r requirements.txt --format json`
   - **Maven** → `mvn org.owasp:dependency-check-maven:check -Dformat=JSON`
   - **Gradle** → `gradle dependencies` (OWASP plugin if configured)
   - **.NET** → `dotnet list package --vulnerable --include-transitive`
4. **Report** — Results are normalised, sorted by severity, and rendered into a color-coded PDF using ReportLab.
5. **Cleanup** — The temporary clone is deleted after the scan completes.

## Notes

- The scanner auto-detects the ecosystem based on files in the repository root.
- If multiple ecosystem markers exist (e.g., `package.json` + `requirements.txt`), the first detected match wins — priority: npm → Python → Maven/Gradle → .NET.
- The scanned repository must be publicly accessible (or accessible via your Git credentials).
- Reports are stored in the `reports/` directory and persist between runs.
- The app runs Flask's built-in development server — use a production WSGI server (e.g., Gunicorn) for deployment.
- For Java scanning, the OWASP Dependency-Check Maven plugin runs automatically (no pom.xml modification needed).
- For Python scanning, `pip-audit` is included as a dependency and runs against the project's `requirements.txt`.
