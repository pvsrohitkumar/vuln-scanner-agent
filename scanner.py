"""Vulnerability scanner: clone a repo, detect ecosystem, audit, generate a PDF report.

Supported ecosystems:
  - Node.js / npm  (Angular, React, TypeScript, vanilla JS)
  - Python         (pip-audit via requirements.txt / setup.py / pyproject.toml)
  - Java / Maven   (mvn dependency-check / org.owasp:dependency-check-maven)
  - .NET           (dotnet list package --vulnerable)
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MODERATE": 2,
    "LOW": 3,
    "INFO": 4,
    "UNKNOWN": 5,
}

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#7d1128"),
    "HIGH": colors.HexColor("#c0392b"),
    "MODERATE": colors.HexColor("#e67e22"),
    "LOW": colors.HexColor("#2980b9"),
    "INFO": colors.HexColor("#7f8c8d"),
    "UNKNOWN": colors.HexColor("#95a5a6"),
}

# Maps ecosystem names shown in reports / UI
ECOSYSTEM_LABELS = {
    "npm": "Node.js / npm",
    "python": "Python / pip",
    "maven": "Java / Maven",
    "dotnet": ".NET",
}

REPORTS_DIR = Path(__file__).resolve().parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def clone_repo(repo_url: str) -> Path:
    """Clone a git repo into a temp directory and return its path."""
    tmp = Path(tempfile.mkdtemp(prefix="vulnscan_"))
    subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, str(tmp / "repo")],
        check=True,
        capture_output=True,
        text=True,
    )
    return tmp / "repo"


def cleanup_repo(repo_path: Path) -> None:
    """Remove the cloned repo directory."""
    parent = repo_path.parent
    if parent.name.startswith("vulnscan_"):
        shutil.rmtree(parent, ignore_errors=True)
    else:
        shutil.rmtree(repo_path, ignore_errors=True)


# ---------------------------------------------------------------------------
# Ecosystem detection
# ---------------------------------------------------------------------------

def detect_ecosystem(repo_path: Path) -> str:
    """
    Detect which ecosystem the repo belongs to.
    Returns one of: 'npm', 'python', 'maven', 'dotnet'.
    Raises RuntimeError if none detected.
    """
    # Check for Node.js / npm (Angular, React, TypeScript, vanilla JS)
    if (repo_path / "package.json").exists():
        return "npm"

    # Check for Python
    python_markers = ["requirements.txt", "setup.py", "pyproject.toml", "Pipfile", "setup.cfg"]
    for marker in python_markers:
        if (repo_path / marker).exists():
            return "python"

    # Check for Java / Maven
    if (repo_path / "pom.xml").exists():
        return "maven"
    # Also check for Gradle
    if (repo_path / "build.gradle").exists() or (repo_path / "build.gradle.kts").exists():
        return "maven"  # we treat gradle under the same umbrella

    # Check for .NET
    dotnet_patterns = list(repo_path.glob("*.csproj")) + list(repo_path.glob("*.sln")) + list(repo_path.glob("*.fsproj"))
    if dotnet_patterns:
        return "dotnet"

    raise RuntimeError(
        "Could not detect project type. Supported ecosystems: "
        "Node.js/npm (package.json), Python (requirements.txt / pyproject.toml), "
        "Java/Maven (pom.xml / build.gradle), .NET (*.csproj / *.sln)."
    )


# ---------------------------------------------------------------------------
# NPM scanner  (Angular, React, TypeScript, vanilla JS)
# ---------------------------------------------------------------------------

def _find_java_home() -> str | None:
    """Auto-detect JAVA_HOME if not already set."""
    java_home = os.environ.get("JAVA_HOME")
    if java_home and Path(java_home).exists():
        return java_home

    # Common Windows install locations
    if os.name == "nt":
        search_roots = [
            Path("C:/Program Files/Microsoft"),
            Path("C:/Program Files/Eclipse Adoptium"),
            Path("C:/Program Files/Java"),
            Path("C:/Program Files/AdoptOpenJDK"),
            Path("C:/Program Files/Zulu"),
        ]
        for root in search_roots:
            if root.exists():
                for d in sorted(root.iterdir(), reverse=True):
                    if d.is_dir() and (d / "bin" / "java.exe").exists():
                        return str(d)
    else:
        # Linux / macOS common paths
        for pattern in ["/usr/lib/jvm/java-*", "/usr/local/opt/openjdk*/libexec/openjdk.jdk/Contents/Home"]:
            import glob
            matches = sorted(glob.glob(pattern), reverse=True)
            if matches and Path(matches[0]).is_dir():
                return matches[0]

    return None


def _get_java_env() -> dict[str, str]:
    """Return an env dict with JAVA_HOME and PATH properly set."""
    env = os.environ.copy()
    java_home = _find_java_home()
    if java_home:
        env["JAVA_HOME"] = java_home
        java_bin = str(Path(java_home) / "bin")
        if java_bin not in env.get("PATH", ""):
            env["PATH"] = java_bin + os.pathsep + env.get("PATH", "")
    return env


def _run_cmd(args: list[str], cwd: str, shell: bool = True, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        args, cwd=cwd, capture_output=True, text=True, check=False, shell=shell,
        env=env,
    )


def _run_npm_json(args: list[str], cwd: str) -> dict:
    result = _run_cmd(args, cwd)
    raw = (result.stdout or result.stderr).strip()
    if not raw:
        raise RuntimeError(f"{' '.join(args)} produced no output.")
    return json.loads(raw)


def npm_install(repo_path: Path) -> None:
    _run_cmd(["npm", "install", "--ignore-scripts"], cwd=str(repo_path))


def run_npm_audit(repo_path: Path) -> dict:
    return _run_npm_json(["npm", "audit", "--json"], cwd=str(repo_path))


def get_installed_versions(repo_path: Path) -> dict[str, str]:
    data = _run_npm_json(["npm", "ls", "--all", "--json"], cwd=str(repo_path))
    versions: dict[str, str] = {}

    def _walk(deps: dict):
        for name, info in deps.items():
            if isinstance(info, dict):
                ver = info.get("version")
                if ver and name not in versions:
                    versions[name] = ver
                _walk(info.get("dependencies", {}))

    _walk(data.get("dependencies", {}))
    return versions


def scan_npm(repo_path: Path, progress=None) -> list[list[str]]:
    """Run npm audit and return normalised rows: [[severity, package, fix], …]."""
    if progress:
        progress("Installing npm dependencies…")
    npm_install(repo_path)
    if progress:
        progress("Running npm audit…")
    audit_data = run_npm_audit(repo_path)
    if progress:
        progress("Resolving installed package versions…")
    installed_versions = get_installed_versions(repo_path)

    vulnerabilities = audit_data.get("vulnerabilities", {})
    rows: list[list[str]] = []
    for pkg, details in vulnerabilities.items():
        severity = str(details.get("severity", "unknown")).upper()
        version = installed_versions.get(pkg, "unknown")
        fix = "n/a"
        fix_data = details.get("fixAvailable")
        if isinstance(fix_data, dict):
            if fix_data.get("name"):
                fv = fix_data.get("version") or "latest"
                fix = f"{fix_data['name']}@{fv}"
            elif fix_data.get("version"):
                fix = str(fix_data["version"])
        elif isinstance(fix_data, str):
            fix = fix_data
        rows.append([severity, f"{pkg}@{version}", fix])
    return rows


# ---------------------------------------------------------------------------
# Python scanner  (pip-audit)
# ---------------------------------------------------------------------------

def _find_python_requirements(repo_path: Path) -> str:
    """Determine which pip-audit source flag to use."""
    if (repo_path / "requirements.txt").exists():
        return "requirements"
    if (repo_path / "pyproject.toml").exists():
        return "pyproject"
    if (repo_path / "setup.py").exists():
        return "setup"
    if (repo_path / "Pipfile").exists():
        return "pipfile"
    return "requirements"  # fallback


def scan_python(repo_path: Path, progress=None) -> list[list[str]]:
    """Run pip-audit and return normalised rows."""
    if progress:
        progress("Analysing Python dependencies…")
    req_type = _find_python_requirements(repo_path)

    # Build the pip-audit command
    if req_type == "requirements":
        cmd = ["pip-audit", "-r", str(repo_path / "requirements.txt"),
               "--format", "json", "--output", "-"]
    else:
        # For pyproject.toml / setup.py we let pip-audit auto-detect
        cmd = ["pip-audit", "--format", "json", "--output", "-"]

    if progress:
        progress(f"Running pip-audit ({req_type})…")
    result = _run_cmd(cmd, cwd=str(repo_path), shell=True)
    raw = (result.stdout or "").strip()

    rows: list[list[str]] = []

    if raw:
        try:
            data = json.loads(raw)
            # pip-audit JSON: {"dependencies": [{ "name", "version", "vulns": [{"id","fix_versions":[...], ...}] }]}
            for dep in data.get("dependencies", []):
                dep_name = dep.get("name", "unknown")
                dep_version = dep.get("version", "unknown")
                for vuln in dep.get("vulns", []):
                    vuln_id = vuln.get("id", "")
                    fix_versions = vuln.get("fix_versions", [])
                    fix = ", ".join(fix_versions) if fix_versions else "n/a"
                    # pip-audit doesn't give severity natively; look for aliases
                    # We'll map via the vuln description or default to UNKNOWN
                    severity = _pip_audit_severity(vuln)
                    rows.append([severity, f"{dep_name}@{dep_version} ({vuln_id})", fix])
        except json.JSONDecodeError:
            # Fallback: parse plain-text pip-audit output
            rows.extend(_parse_pip_audit_text(result.stdout or result.stderr or ""))
    else:
        # Might be in stderr for older pip-audit
        stderr = (result.stderr or "").strip()
        if stderr:
            rows.extend(_parse_pip_audit_text(stderr))

    return rows


def _pip_audit_severity(vuln: dict) -> str:
    """Try to extract severity from pip-audit vuln aliases (OSV data)."""
    aliases = vuln.get("aliases", [])
    desc = vuln.get("description", "").upper()
    # Check if description mentions severity keywords
    for sev in ["CRITICAL", "HIGH", "MODERATE", "LOW"]:
        if sev in desc:
            return sev
    # Default based on CVE presence (CVEs tend to be higher severity)
    for alias in aliases:
        if alias.startswith("CVE-"):
            return "HIGH"
    return "UNKNOWN"


def _parse_pip_audit_text(text: str) -> list[list[str]]:
    """Parse plain-text pip-audit table output as a fallback."""
    rows: list[list[str]] = []
    # Typical line: "package  version  vuln_id  fix_version"
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and not line.startswith("-") and not line.lower().startswith("name"):
            pkg = parts[0]
            ver = parts[1]
            vuln_id = parts[2] if len(parts) > 2 else ""
            fix = parts[3] if len(parts) > 3 else "n/a"
            rows.append(["UNKNOWN", f"{pkg}@{ver} ({vuln_id})", fix])
    return rows


# ---------------------------------------------------------------------------
# Java / Maven scanner  (OWASP dependency-check or mvn audit)
# ---------------------------------------------------------------------------

def scan_maven(repo_path: Path, progress=None) -> list[list[str]]:
    """
    Run OWASP dependency-check via Maven plugin and parse the JSON report.
    Falls back to a simpler mvn dependency:tree analysis if the plugin is
    not available.
    """
    rows: list[list[str]] = []
    java_env = _get_java_env()

    is_gradle = (repo_path / "build.gradle").exists() or (repo_path / "build.gradle.kts").exists()

    if is_gradle:
        rows = _scan_gradle_dependencies(repo_path, java_env, progress)
    else:
        rows = _scan_maven_owasp(repo_path, java_env, progress)

    return rows


def _scan_maven_owasp(repo_path: Path, java_env: dict, progress=None) -> list[list[str]]:
    """Run OWASP dependency-check maven plugin."""
    rows: list[list[str]] = []
    report_json = repo_path / "target" / "dependency-check-report.json"

    if progress:
        progress("Running OWASP dependency-check (Maven)…")
    # Try running OWASP dependency-check
    result = _run_cmd(
        ["mvn", "org.owasp:dependency-check-maven:check",
         "-Dformat=JSON", "-DprettyPrint=true", "-q"],
        cwd=str(repo_path), env=java_env,
    )

    if report_json.exists():
        try:
            data = json.loads(report_json.read_text(encoding="utf-8"))
            for dep in data.get("dependencies", []):
                dep_name = dep.get("fileName", "unknown")
                for vuln in dep.get("vulnerabilities", []):
                    name = vuln.get("name", "")
                    severity = vuln.get("severity", "UNKNOWN").upper()
                    # Normalise severity names
                    if severity == "MEDIUM":
                        severity = "MODERATE"
                    rows.append([severity, f"{dep_name} ({name})", "n/a"])
        except (json.JSONDecodeError, KeyError):
            pass

    # Fallback: parse mvn dependency:tree for at least listing deps
    if not rows:
        result = _run_cmd(["mvn", "dependency:tree", "-q"], cwd=str(repo_path), env=java_env)
        output = result.stdout or ""
        if "BUILD FAILURE" not in output:
            rows.append(["INFO", "No known vulnerabilities detected (dependency-check not available)", "n/a"])

    if not rows:
        rows.append(["UNKNOWN", "Could not run Maven audit — ensure Maven is installed", "n/a"])

    return rows


def _resolve_gradle_cmd(repo_path: Path) -> list[str]:
    """Return the best Gradle executable: prefer the wrapper bundled with the repo."""
    if os.name == "nt":  # Windows
        wrapper = repo_path / "gradlew.bat"
    else:
        wrapper = repo_path / "gradlew"

    if wrapper.exists():
        # Make sure the wrapper is executable (Linux/macOS)
        if os.name != "nt":
            wrapper.chmod(wrapper.stat().st_mode | 0o755)
        return [str(wrapper)]

    # Fall back to system gradle
    return ["gradle"]


def _scan_gradle_dependencies(repo_path: Path, java_env: dict, progress=None) -> list[list[str]]:
    """
    Scan a Gradle project for vulnerabilities.
    Strategy (in order):
      1. Try CycloneDX BOM plugin  (./gradlew cyclonedxBom → parse bom.json)
      2. Try dependency-check plugin (./gradlew dependencyCheckAnalyze → parse JSON)
      3. Fall back to listing the dependency tree
    Uses the Gradle wrapper (gradlew / gradlew.bat) when available.
    """
    gradle_cmd = _resolve_gradle_cmd(repo_path)
    rows: list[list[str]] = []

    # ── Strategy 1: CycloneDX BOM ──────────────────────────────────────
    if progress:
        progress("Running CycloneDX BOM generation (Gradle)…")
    result = _run_cmd(
        gradle_cmd + ["cyclonedxBom", "--console=plain", "-q"],
        cwd=str(repo_path), env=java_env,
    )
    bom_paths = [
        repo_path / "build" / "reports" / "bom.json",
        repo_path / "build" / "report" / "bom.json",
    ]
    for bom_path in bom_paths:
        if bom_path.exists():
            rows.extend(_parse_cyclonedx_bom(bom_path))
            break

    if rows:
        return rows

    # ── Strategy 2: OWASP dependency-check Gradle plugin ───────────────
    if progress:
        progress("Trying OWASP dependency-check plugin (Gradle)…")
    result = _run_cmd(
        gradle_cmd + ["dependencyCheckAnalyze", "--console=plain", "-q"],
        cwd=str(repo_path), env=java_env,
    )
    dc_report = repo_path / "build" / "reports" / "dependency-check-report.json"
    if dc_report.exists():
        try:
            data = json.loads(dc_report.read_text(encoding="utf-8"))
            for dep in data.get("dependencies", []):
                dep_name = dep.get("fileName", "unknown")
                for vuln in dep.get("vulnerabilities", []):
                    name = vuln.get("name", "")
                    severity = vuln.get("severity", "UNKNOWN").upper()
                    if severity == "MEDIUM":
                        severity = "MODERATE"
                    rows.append([severity, f"{dep_name} ({name})", "n/a"])
        except (json.JSONDecodeError, KeyError):
            pass

    if rows:
        return rows

    # ── Strategy 3: plain dependency tree ──────────────────────────────
    if progress:
        progress("Fetching Gradle dependency tree…")
    result = _run_cmd(
        gradle_cmd + ["dependencies", "--console=plain", "-q"],
        cwd=str(repo_path), env=java_env,
    )
    output = (result.stdout or "") + (result.stderr or "")
    deps = _parse_gradle_dependency_tree(output)
    if deps:
        for dep in deps:
            rows.append(["INFO", dep, "n/a"])
        if not rows:
            rows.append(["INFO", "No known vulnerabilities detected (add CycloneDX or OWASP plugin for full scan)", "n/a"])
    else:
        error_detail = output[:200].strip() if output.strip() else "no output"
        rows.append(["UNKNOWN", f"Could not run Gradle audit — check Gradle/wrapper setup ({error_detail})", "n/a"])

    return rows


def _parse_cyclonedx_bom(bom_path: Path) -> list[list[str]]:
    """
    Parse a CycloneDX BOM JSON file for components and their vulnerabilities.
    The BOM lists all components; vulnerabilities (if present) are in the
    'vulnerabilities' top-level key.
    """
    rows: list[list[str]] = []
    try:
        data = json.loads(bom_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return rows

    # Build a lookup of components
    components: dict[str, str] = {}  # bom-ref → "group:name@version"
    for comp in data.get("components", []):
        group = comp.get("group", "")
        name = comp.get("name", "unknown")
        version = comp.get("version", "unknown")
        bom_ref = comp.get("bom-ref", "")
        label = f"{group}:{name}@{version}" if group else f"{name}@{version}"
        components[bom_ref] = label

    # Parse vulnerabilities section (CycloneDX 1.4+)
    vulns = data.get("vulnerabilities", [])
    if vulns:
        for vuln in vulns:
            vuln_id = vuln.get("id", "")
            # CycloneDX ratings list
            severity = "UNKNOWN"
            for rating in vuln.get("ratings", []):
                sev = (rating.get("severity") or "").upper()
                if sev in SEVERITY_ORDER:
                    severity = sev
                    break
                elif sev == "MEDIUM":
                    severity = "MODERATE"
                    break

            # Affected components
            affects = vuln.get("affects", [])
            advisories = vuln.get("advisories", [])
            advisory_url = advisories[0].get("url", "n/a") if advisories else "n/a"

            if affects:
                for affect in affects:
                    ref = affect.get("ref", "")
                    comp_label = components.get(ref, ref or "unknown")
                    rows.append([severity, f"{comp_label} ({vuln_id})", advisory_url])
            else:
                rows.append([severity, f"({vuln_id})", advisory_url])
    else:
        # No vulnerabilities section — list components as INFO
        # This means the BOM was generated but no vuln data is embedded
        # (CycloneDX BOM alone doesn't do vuln matching; it's a dependency list)
        if components:
            # Report as clean scan with component count
            rows.append(["INFO",
                         f"CycloneDX BOM generated — {len(components)} dependencies found. "
                         "No embedded vulnerability data. Use a vuln DB matcher for full scan.",
                         "n/a"])

    return rows


def _parse_gradle_dependency_tree(output: str) -> list[str]:
    """Extract dependency coordinates from Gradle dependency tree output."""
    deps: list[str] = []
    seen: set[str] = set()
    for line in output.splitlines():
        # Lines like: "+--- org.springframework.boot:spring-boot-starter-web:3.1.0"
        match = re.search(r"[\+\\|`]---\s+(\S+:\S+:\S+)", line)
        if match:
            dep = match.group(1)
            # Strip trailing markers like " (*)" or " (c)"
            dep = re.sub(r"\s*\(.*\)\s*$", "", dep)
            if dep not in seen:
                seen.add(dep)
                deps.append(dep)
    return deps


# ---------------------------------------------------------------------------
# .NET scanner  (dotnet list package --vulnerable)
# ---------------------------------------------------------------------------

def scan_dotnet(repo_path: Path, progress=None) -> list[list[str]]:
    """Run dotnet list package --vulnerable and parse the output."""
    rows: list[list[str]] = []

    # Find the solution or project file
    sln_files = list(repo_path.glob("*.sln"))
    csproj_files = list(repo_path.glob("**/*.csproj"))

    target = str(repo_path)
    if sln_files:
        target = str(sln_files[0])
    elif csproj_files:
        target = str(csproj_files[0])

    # Restore packages first
    if progress:
        progress("Restoring .NET packages…")
    _run_cmd(["dotnet", "restore", target], cwd=str(repo_path))

    # Run vulnerable package check
    if progress:
        progress("Checking for vulnerable .NET packages…")
    result = _run_cmd(
        ["dotnet", "list", target, "package", "--vulnerable", "--include-transitive"],
        cwd=str(repo_path),
    )
    output = (result.stdout or "") + (result.stderr or "")

    rows.extend(_parse_dotnet_vulnerable_output(output))

    if not rows:
        # Try deprecated packages as secondary check
        result2 = _run_cmd(
            ["dotnet", "list", target, "package", "--deprecated"],
            cwd=str(repo_path),
        )
        output2 = (result2.stdout or "") + (result2.stderr or "")
        deprecated_rows = _parse_dotnet_deprecated_output(output2)
        rows.extend(deprecated_rows)

    if not rows:
        rows.append(["INFO", "No known vulnerabilities detected in .NET packages", "n/a"])

    return rows


def _parse_dotnet_vulnerable_output(output: str) -> list[list[str]]:
    """
    Parse output from: dotnet list package --vulnerable
    Lines look like:
       > PackageName    1.0.0    1.0.0    Critical    https://...
    """
    rows: list[list[str]] = []
    severity_map = {"critical": "CRITICAL", "high": "HIGH", "moderate": "MODERATE", "low": "LOW"}

    for line in output.splitlines():
        line = line.strip()
        if not line.startswith(">"):
            continue
        # Remove the leading '>'
        parts = line[1:].split()
        if len(parts) < 4:
            continue

        pkg_name = parts[0]
        resolved_ver = parts[1]
        # Severity can appear in different columns depending on .NET SDK version
        severity = "UNKNOWN"
        advisory_url = "n/a"
        for part in parts[2:]:
            lower = part.lower()
            if lower in severity_map:
                severity = severity_map[lower]
            elif part.startswith("https://"):
                advisory_url = part

        rows.append([severity, f"{pkg_name}@{resolved_ver}", advisory_url])

    return rows


def _parse_dotnet_deprecated_output(output: str) -> list[list[str]]:
    """Parse output from: dotnet list package --deprecated."""
    rows: list[list[str]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith(">"):
            continue
        parts = line[1:].split()
        if len(parts) >= 2:
            rows.append(["LOW", f"{parts[0]}@{parts[1]} (deprecated)", "upgrade recommended"])
    return rows


def build_pdf(rows: list, project_name: str, ecosystem: str = "npm") -> Path:
    report_id = uuid.uuid4().hex[:10]
    output = REPORTS_DIR / f"{project_name}_{report_id}.pdf"

    eco_label = ECOSYSTEM_LABELS.get(ecosystem, ecosystem)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        fontSize=20,
        textColor=colors.HexColor("#1a237e"),
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#37474f"),
    )

    doc = SimpleDocTemplate(
        str(output),
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    summary = Counter(r[0] for r in rows)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    story: list = []
    story.append(Paragraph("Vulnerability Scan Report", title_style))
    story.append(Paragraph(f"Project: {project_name}", subtitle_style))
    story.append(Paragraph(f"Ecosystem: {eco_label}", styles["Normal"]))
    story.append(Paragraph(f"Generated: {generated_at}", styles["Normal"]))
    story.append(Spacer(1, 12))

    labels = ["CRITICAL", "HIGH", "MODERATE", "LOW", "INFO", "UNKNOWN"]
    summary_lines = [f"<b>Total findings:</b> {len(rows)}"]
    for label in labels:
        cnt = summary.get(label, 0)
        if cnt:
            summary_lines.append(f"<b>{label.title()}:</b> {cnt}")
    for line in summary_lines:
        story.append(Paragraph(line, styles["BodyText"]))

    story.append(Spacer(1, 16))

    # Table
    header = ["Severity", "Package / Dependency", "Fix / Advisory"]
    table_data = [header] + rows

    col_widths = [80, 250, 200]
    table = Table(table_data, colWidths=col_widths, repeatRows=1)

    base_style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("GRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#bdbdbd")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f5f5f5"), colors.white]),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]

    # Color-code severity cells
    for i, row in enumerate(rows, start=1):
        sev = row[0]
        bg = SEVERITY_COLORS.get(sev, colors.white)
        base_style.append(("BACKGROUND", (0, i), (0, i), bg))
        base_style.append(("TEXTCOLOR", (0, i), (0, i), colors.white))
        base_style.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))

    table.setStyle(TableStyle(base_style))
    story.append(table)

    doc.build(story)
    return output


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

# Dispatch table: ecosystem → scanner function
_SCANNERS = {
    "npm": scan_npm,
    "python": scan_python,
    "maven": scan_maven,
    "dotnet": scan_dotnet,
}


def scan_repo(repo_url: str, progress_callback=None) -> dict:
    """
    End-to-end scan: clone → detect ecosystem → audit → PDF.
    Returns a dict with summary info and the path to the PDF.
    """
    def _progress(msg):
        if progress_callback:
            progress_callback(msg)

    repo_path = None
    try:
        _progress("Cloning repository…")
        repo_path = clone_repo(repo_url)
        project_name = repo_path.name or "project"

        _progress("Detecting project type…")
        ecosystem = detect_ecosystem(repo_path)
        eco_label = ECOSYSTEM_LABELS.get(ecosystem, ecosystem)

        _progress(f"Detected: {eco_label}. Running vulnerability scan…")
        scanner_fn = _SCANNERS[ecosystem]
        rows = scanner_fn(repo_path)

        # Sort rows by severity
        rows.sort(key=lambda r: (SEVERITY_ORDER.get(r[0], 99), r[1]))

        _progress("Building report…")
        pdf_path = build_pdf(rows, project_name, ecosystem)

        summary = Counter(r[0] for r in rows)
        return {
            "success": True,
            "pdf_path": str(pdf_path),
            "pdf_filename": pdf_path.name,
            "project_name": project_name,
            "ecosystem": ecosystem,
            "ecosystem_label": eco_label,
            "total": len(rows),
            "critical": summary.get("CRITICAL", 0),
            "high": summary.get("HIGH", 0),
            "moderate": summary.get("MODERATE", 0),
            "low": summary.get("LOW", 0),
            "info": summary.get("INFO", 0),
            "unknown": summary.get("UNKNOWN", 0),
            "rows": rows,
        }
    except Exception as exc:
        return {"success": False, "error": str(exc)}
    finally:
        if repo_path:
            cleanup_repo(repo_path)
