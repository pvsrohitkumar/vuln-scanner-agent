"""Auto-fix vulnerabilities reported by the scanner.

Workflow (per ecosystem):
  1. Clone the repo (or reuse the already-cloned path).
  2. Run the vulnerability scan to obtain rows: [[severity, package_label, fix]].
  3. Parse fix/advisory versions from each row.
  4. Apply version upgrades to the project's dependency manifest
     (package.json, requirements.txt, pom.xml, *.csproj, build.gradle, etc.).
  5. Run the project's build command to verify the fix compiles.
  6. Re-scan to check remaining vulnerabilities.
  7. Repeat steps 3-6 until the build succeeds with zero fixable vulnerabilities
     or a maximum iteration count is reached.

Returns a structured result with iteration logs, before/after summaries, and
the path to the fixed repo (if successful).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from scanner import (
    ECOSYSTEM_LABELS,
    REPORTS_DIR,
    SEVERITY_ORDER,
    _get_java_env,
    _run_cmd,
    _SCANNERS,
    build_pdf,
    clone_repo,
    cleanup_repo,
    detect_ecosystem,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_FIX_ITERATIONS = 5          # safety limit
FIXABLE_SEVERITIES = {"CRITICAL", "HIGH", "MODERATE", "LOW"}

# Holds the repo path temporarily so it can be used for PR creation
# keyed by a patch_id returned to the frontend
_ACTIVE_PATCHES: dict[str, Path] = {}


# ---------------------------------------------------------------------------
# Git diff / PR helpers
# ---------------------------------------------------------------------------

def _get_changed_files(repo_path: Path) -> list[dict]:
    """
    Run `git diff` on the cloned repo to get all changed files with their diffs.
    Returns a list of { filename, status, diff } dicts.
    """
    result = _run_cmd(
        ["git", "diff", "--name-status"],
        cwd=str(repo_path), shell=True,
    )
    files: list[dict] = []
    seen: set[str] = set()

    for line in (result.stdout or "").strip().splitlines():
        parts = line.split("\t", 1)
        if len(parts) >= 2:
            status_code, filename = parts[0].strip(), parts[1].strip()
            if filename in seen:
                continue
            seen.add(filename)
            status_map = {"M": "modified", "A": "added", "D": "deleted", "R": "renamed"}
            status = status_map.get(status_code[0], "modified")

            # Get the unified diff for this file
            diff_result = _run_cmd(
                ["git", "diff", "--", filename],
                cwd=str(repo_path), shell=True,
            )
            diff_text = (diff_result.stdout or "").strip()

            files.append({
                "filename": filename,
                "status": status,
                "diff": diff_text,
            })

    return files


def _create_pr_branch_and_push(
    repo_path: Path,
    branch_name: str,
    commit_message: str,
    progress: ProgressFn = None,
) -> dict:
    """
    Create a fix branch, commit all changes, and push.
    Then attempt to create a PR via GitHub CLI (`gh pr create`).
    Returns { success, branch, pr_url, error }.
    """
    env = os.environ.copy()

    # Create and checkout fix branch
    if progress:
        progress(f"Creating branch: {branch_name}…")
    result = _run_cmd(
        ["git", "checkout", "-b", branch_name],
        cwd=str(repo_path), shell=True, env=env,
    )
    if result.returncode != 0:
        return {"success": False, "error": f"Failed to create branch: {result.stderr}"}

    # Stage all changes
    if progress:
        progress("Staging changes…")
    _run_cmd(["git", "add", "-A"], cwd=str(repo_path), shell=True, env=env)

    # Commit
    if progress:
        progress("Committing changes…")
    result = _run_cmd(
        ["git", "commit", "-m", commit_message],
        cwd=str(repo_path), shell=True, env=env,
    )
    if result.returncode != 0:
        stderr = result.stderr or ""
        if "nothing to commit" in stderr.lower() or "nothing to commit" in (result.stdout or "").lower():
            return {"success": False, "error": "No changes to commit."}
        return {"success": False, "error": f"Commit failed: {stderr}"}

    # Push
    if progress:
        progress(f"Pushing branch {branch_name} to origin…")
    result = _run_cmd(
        ["git", "push", "-u", "origin", branch_name],
        cwd=str(repo_path), shell=True, env=env,
    )
    if result.returncode != 0:
        return {
            "success": False,
            "branch": branch_name,
            "error": f"Push failed (you may need write access): {(result.stderr or '')[:500]}",
        }

    # Try creating a PR using GitHub CLI
    pr_url = ""
    if progress:
        progress("Creating pull request…")
    pr_result = _run_cmd(
        ["gh", "pr", "create",
         "--title", commit_message,
         "--body", "Automated vulnerability fix — dependency versions upgraded to patched releases.",
         "--head", branch_name],
        cwd=str(repo_path), shell=True, env=env,
    )
    if pr_result.returncode == 0:
        pr_url = (pr_result.stdout or "").strip()
    else:
        # gh CLI may not be installed or user may not have permissions
        # Return success for the push at least
        return {
            "success": True,
            "branch": branch_name,
            "pr_url": "",
            "error": f"Branch pushed but PR creation failed (install `gh` CLI for auto-PR): {(pr_result.stderr or '')[:300]}",
        }

    return {
        "success": True,
        "branch": branch_name,
        "pr_url": pr_url,
        "error": "",
    }


def cleanup_patch(patch_id: str) -> None:
    """Clean up a held patch repo by its ID."""
    repo_path = _ACTIVE_PATCHES.pop(patch_id, None)
    if repo_path:
        cleanup_repo(repo_path)

ProgressFn = Callable[[str], None] | None


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class FixAction:
    """One concrete version bump to apply."""
    package: str        # e.g. "express" or "com.fasterxml.jackson.core:jackson-databind"
    current_version: str
    target_version: str
    vuln_id: str        # e.g. "GHSA-xxx" or "CVE-2023-xxx"
    severity: str


@dataclass
class IterationResult:
    """Captures what happened in a single fix-scan-build cycle."""
    iteration: int
    fixes_applied: list[FixAction] = field(default_factory=list)
    build_success: bool = False
    build_output: str = ""
    remaining_vulns: int = 0
    remaining_rows: list[list[str]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Row parsing helpers
# ---------------------------------------------------------------------------

def _parse_package_and_version(label: str) -> tuple[str, str]:
    """
    Extract (package_name, version) from a scan row label.
    Formats seen:
      "express@4.17.1"
      "com.thoughtworks.xstream:xstream@1.4.5 (GHSA-xxx)"
      "lodash@4.17.19 (CVE-2021-23337)"
      "Newtonsoft.Json@12.0.1"
    """
    # Strip trailing (vuln_id) parenthetical
    clean = re.sub(r"\s*\(.*\)\s*$", "", label).strip()
    if "@" in clean:
        # Split on last '@' in case package name contains '@' (scoped npm)
        idx = clean.rfind("@")
        return clean[:idx], clean[idx + 1:]
    return clean, ""


def _parse_vuln_id(label: str) -> str:
    """Extract vulnerability ID from parenthetical, e.g. '(GHSA-xxx)' → 'GHSA-xxx'."""
    m = re.search(r"\(([A-Z][\w-]+)\)", label)
    return m.group(1) if m else ""


def _parse_fix_version(fix_field: str) -> str:
    """
    Extract the best (highest) fix version from the fix/advisory column.
    Handles:
      "1.4.18"
      "1.4.11, 1.4.7"      → picks "1.4.18" (highest)
      "express@4.18.2"      → "4.18.2"
      "https://..."         → "" (advisory URL, not a version)
      "n/a"                 → ""
    """
    if not fix_field or fix_field.lower() == "n/a":
        return ""
    # If it's a URL, not a version
    if fix_field.startswith("http://") or fix_field.startswith("https://"):
        return ""
    # If it looks like "package@version"
    if "@" in fix_field:
        return fix_field.split("@")[-1].strip()
    # Comma-separated list → pick last (usually highest)
    parts = [p.strip() for p in fix_field.split(",") if p.strip()]
    versions = [p for p in parts if re.match(r"^\d+[\d.]*", p)]
    if versions:
        # Sort semantically and return the highest
        versions.sort(key=lambda v: list(map(int, re.findall(r"\d+", v))), reverse=True)
        return versions[0]
    return fix_field.strip() if fix_field.strip() != "n/a" else ""


def extract_fix_actions(rows: list[list[str]]) -> list[FixAction]:
    """
    Given scan rows [[severity, label, fix], …], extract concrete FixActions
    (only for rows that have an actionable fix version).
    De-duplicates by package: keeps the action with the highest target version.
    """
    actions: dict[str, FixAction] = {}
    for severity, label, fix_field in rows:
        if severity not in FIXABLE_SEVERITIES:
            continue
        pkg, current_ver = _parse_package_and_version(label)
        target_ver = _parse_fix_version(fix_field)
        if not pkg or not target_ver:
            continue
        vuln_id = _parse_vuln_id(label)

        key = pkg
        if key in actions:
            # Keep the higher target version
            existing = actions[key].target_version
            try:
                existing_nums = list(map(int, re.findall(r"\d+", existing)))
                new_nums = list(map(int, re.findall(r"\d+", target_ver)))
                if new_nums > existing_nums:
                    actions[key] = FixAction(pkg, current_ver, target_ver, vuln_id, severity)
            except (ValueError, TypeError):
                pass
        else:
            actions[key] = FixAction(pkg, current_ver, target_ver, vuln_id, severity)

    return list(actions.values())


# ---------------------------------------------------------------------------
# Ecosystem-specific fix appliers
# ---------------------------------------------------------------------------

def _apply_npm_fixes(repo_path: Path, fixes: list[FixAction], progress: ProgressFn = None) -> list[FixAction]:
    """Update package.json versions and run npm install."""
    applied: list[FixAction] = []
    pkg_json_path = repo_path / "package.json"
    if not pkg_json_path.exists():
        return applied

    pkg_data = json.loads(pkg_json_path.read_text(encoding="utf-8"))
    dep_sections = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]

    for fix in fixes:
        for section in dep_sections:
            deps = pkg_data.get(section, {})
            if fix.package in deps:
                old = deps[fix.package]
                # Preserve prefix (^, ~, >=, etc.)
                prefix = ""
                for p in ("^", "~", ">=", "<=", ">", "<", "="):
                    if old.startswith(p):
                        prefix = p
                        break
                deps[fix.package] = f"{prefix}{fix.target_version}"
                if progress:
                    progress(f"  npm: {fix.package} {old} → {prefix}{fix.target_version}")
                applied.append(fix)
                break

    if applied:
        pkg_json_path.write_text(json.dumps(pkg_data, indent=2) + "\n", encoding="utf-8")
        # Re-install to update lock file
        if progress:
            progress("Running npm install…")
        _run_cmd(["npm", "install", "--ignore-scripts"], cwd=str(repo_path))

    return applied


def _apply_python_fixes(repo_path: Path, fixes: list[FixAction], progress: ProgressFn = None) -> list[FixAction]:
    """Update requirements.txt / pyproject.toml versions."""
    applied: list[FixAction] = []

    # --- requirements.txt ---
    req_file = repo_path / "requirements.txt"
    if req_file.exists():
        lines = req_file.read_text(encoding="utf-8").splitlines()
        new_lines: list[str] = []
        for line in lines:
            updated = False
            for fix in fixes:
                # Match "package==version", "package>=version", "package~=version", etc.
                pattern = re.compile(
                    rf"^(\s*){re.escape(fix.package)}(\s*)(==|>=|~=|<=|!=|>|<)(\s*)[\d][\d.]*(.*)$",
                    re.IGNORECASE,
                )
                m = pattern.match(line)
                if m:
                    pre_ws, mid_ws, op, post_ws, tail = m.groups()
                    new_line = f"{pre_ws}{fix.package}{mid_ws}{op}{post_ws}{fix.target_version}{tail}"
                    new_lines.append(new_line)
                    if progress:
                        progress(f"  pip: {fix.package} → {fix.target_version}")
                    applied.append(fix)
                    updated = True
                    break
            if not updated:
                new_lines.append(line)
        req_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

    # --- pyproject.toml (basic regex approach) ---
    pyproject = repo_path / "pyproject.toml"
    if pyproject.exists():
        content = pyproject.read_text(encoding="utf-8")
        for fix in fixes:
            if fix in applied:
                continue
            # Match '"package>=x.y.z"' or '"package==x.y.z"' in dependencies list
            pattern = re.compile(
                rf'("{re.escape(fix.package)})((?:>=|==|~=|<=|!=|>|<)\s*)[\d][\d.]*(")',
                re.IGNORECASE,
            )
            new_content, count = pattern.subn(
                rf"\g<1>\g<2>{fix.target_version}\3", content
            )
            if count > 0:
                content = new_content
                if progress:
                    progress(f"  pyproject: {fix.package} → {fix.target_version}")
                applied.append(fix)
        pyproject.write_text(content, encoding="utf-8")

    return applied


def _apply_maven_fixes(repo_path: Path, fixes: list[FixAction], progress: ProgressFn = None) -> list[FixAction]:
    """
    Update pom.xml dependency versions (Maven) or build.gradle(.kts) (Gradle).
    """
    is_gradle = (repo_path / "build.gradle").exists() or (repo_path / "build.gradle.kts").exists()
    if is_gradle:
        return _apply_gradle_fixes(repo_path, fixes, progress)
    return _apply_pom_fixes(repo_path, fixes, progress)


def _apply_pom_fixes(repo_path: Path, fixes: list[FixAction], progress: ProgressFn = None) -> list[FixAction]:
    """Update <version> tags in pom.xml for matching dependencies."""
    applied: list[FixAction] = []
    pom_path = repo_path / "pom.xml"
    if not pom_path.exists():
        return applied

    # Read raw text so we can do precise edits (preserving formatting)
    content = pom_path.read_text(encoding="utf-8")

    # Also parse with ElementTree for structural matching
    try:
        tree = ET.parse(str(pom_path))
        root = tree.getroot()
    except ET.ParseError:
        return applied

    ns = ""
    m = re.match(r"\{(.+?)}", root.tag)
    if m:
        ns = m.group(1)
    nsmap = {"m": ns} if ns else {}

    def _find(parent, tag):
        return parent.findall(f"m:{tag}", nsmap) if ns else parent.findall(tag)

    # Collect properties for variable resolution
    props: dict[str, str] = {}
    for props_el in _find(root, "properties"):
        for child in props_el:
            tag_name = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            if child.text:
                props[tag_name] = child.text.strip()

    for fix in fixes:
        # Parse "group:artifact" from fix.package
        parts = fix.package.split(":")
        group_id = parts[0] if len(parts) >= 2 else ""
        artifact_id = parts[-1]

        # Search for matching <dependency> blocks
        all_dep_sections = _find(root, "dependencies")
        for dm in _find(root, "dependencyManagement"):
            all_dep_sections.extend(_find(dm, "dependencies"))

        for deps_section in all_dep_sections:
            for dep_el in _find(deps_section, "dependency"):
                g_els = _find(dep_el, "groupId")
                a_els = _find(dep_el, "artifactId")
                v_els = _find(dep_el, "version")

                g_text = g_els[0].text.strip() if g_els and g_els[0].text else ""
                a_text = a_els[0].text.strip() if a_els and a_els[0].text else ""

                if a_text != artifact_id:
                    continue
                if group_id and g_text != group_id:
                    continue
                if not v_els or not v_els[0].text:
                    continue

                old_ver = v_els[0].text.strip()

                # If version is a property reference like ${some.version}, update the property
                prop_match = re.match(r"\$\{(.+?)}", old_ver)
                if prop_match:
                    prop_name = prop_match.group(1)
                    prop_tag = f"<{prop_name}>" if not ns else f"<{prop_name}>"
                    # Find and replace in raw content
                    old_prop_val = props.get(prop_name, "")
                    if old_prop_val:
                        # Replace <propName>old_value</propName>
                        pattern = re.compile(
                            rf"(<{re.escape(prop_name)}>)\s*{re.escape(old_prop_val)}\s*(</{re.escape(prop_name)}>)"
                        )
                        new_content, count = pattern.subn(
                            rf"\g<1>{fix.target_version}\g<2>", content
                        )
                        if count > 0:
                            content = new_content
                            props[prop_name] = fix.target_version
                            if progress:
                                progress(f"  pom.xml: ${{{prop_name}}} {old_prop_val} → {fix.target_version}")
                            applied.append(fix)
                else:
                    # Direct version: replace in <version> tag
                    # Build a regex that matches this specific dependency block
                    esc_g = re.escape(g_text)
                    esc_a = re.escape(a_text)
                    esc_v = re.escape(old_ver)
                    pattern = re.compile(
                        rf"(<groupId>\s*{esc_g}\s*</groupId>.*?"
                        rf"<artifactId>\s*{esc_a}\s*</artifactId>.*?"
                        rf"<version>)\s*{esc_v}\s*(</version>)",
                        re.DOTALL,
                    )
                    new_content, count = pattern.subn(
                        rf"\g<1>{fix.target_version}\g<2>", content, count=1
                    )
                    if count > 0:
                        content = new_content
                        if progress:
                            progress(f"  pom.xml: {fix.package} {old_ver} → {fix.target_version}")
                        applied.append(fix)

    if applied:
        pom_path.write_text(content, encoding="utf-8")

    return applied


def _apply_gradle_fixes(repo_path: Path, fixes: list[FixAction], progress: ProgressFn = None) -> list[FixAction]:
    """Update dependency versions in build.gradle or build.gradle.kts."""
    applied: list[FixAction] = []

    for gradle_file_name in ["build.gradle", "build.gradle.kts"]:
        gradle_path = repo_path / gradle_file_name
        if not gradle_path.exists():
            continue

        content = gradle_path.read_text(encoding="utf-8")

        for fix in fixes:
            parts = fix.package.split(":")
            group = parts[0] if len(parts) >= 2 else ""
            artifact = parts[-1]
            esc_v = re.escape(fix.current_version)

            if group:
                # Match patterns like: "group:artifact:version"
                # or implementation("group:artifact:version")
                esc_g = re.escape(group)
                esc_a = re.escape(artifact)
                pattern = re.compile(
                    rf"({esc_g}:{esc_a}:){esc_v}"
                )
                new_content, count = pattern.subn(
                    rf"\g<1>{fix.target_version}", content
                )
                if count > 0:
                    content = new_content
                    if progress:
                        progress(f"  gradle: {fix.package} {fix.current_version} → {fix.target_version}")
                    applied.append(fix)

        if applied:
            gradle_path.write_text(content, encoding="utf-8")
            break  # Only edit one gradle file

    return applied


def _apply_dotnet_fixes(repo_path: Path, fixes: list[FixAction], progress: ProgressFn = None) -> list[FixAction]:
    """
    Update PackageReference versions in *.csproj / *.fsproj files,
    then run dotnet restore.
    """
    applied: list[FixAction] = []
    proj_files = list(repo_path.glob("**/*.csproj")) + list(repo_path.glob("**/*.fsproj"))

    for proj_file in proj_files:
        content = proj_file.read_text(encoding="utf-8")
        file_changed = False

        for fix in fixes:
            # Match <PackageReference Include="Package" Version="x.y.z" />
            # or <PackageReference Include="Package" Version="x.y.z"> ... </PackageReference>
            pattern = re.compile(
                rf'(<PackageReference\s+Include="{re.escape(fix.package)}"\s+Version=")[\d][\d.]*(")',
                re.IGNORECASE,
            )
            new_content, count = pattern.subn(
                rf"\g<1>{fix.target_version}\g<2>", content
            )
            if count > 0:
                content = new_content
                file_changed = True
                if progress:
                    progress(f"  csproj: {fix.package} → {fix.target_version} in {proj_file.name}")
                applied.append(fix)

        if file_changed:
            proj_file.write_text(content, encoding="utf-8")

    if applied:
        if progress:
            progress("Running dotnet restore…")
        _run_cmd(["dotnet", "restore"], cwd=str(repo_path))

    return applied


# Fix-applier dispatch
_FIX_APPLIERS = {
    "npm": _apply_npm_fixes,
    "python": _apply_python_fixes,
    "maven": _apply_maven_fixes,
    "dotnet": _apply_dotnet_fixes,
}


# ---------------------------------------------------------------------------
# Build verification per ecosystem
# ---------------------------------------------------------------------------

def _build_npm(repo_path: Path, progress: ProgressFn = None) -> tuple[bool, str]:
    """Run npm install + npm run build (if build script exists)."""
    if progress:
        progress("Verifying build: npm install…")
    result = _run_cmd(["npm", "install"], cwd=str(repo_path))
    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0:
        return False, output

    # Check if there's a build script
    pkg_json = repo_path / "package.json"
    if pkg_json.exists():
        data = json.loads(pkg_json.read_text(encoding="utf-8"))
        if "build" in data.get("scripts", {}):
            if progress:
                progress("Verifying build: npm run build…")
            result = _run_cmd(["npm", "run", "build"], cwd=str(repo_path))
            output += "\n" + (result.stdout or "") + (result.stderr or "")
            return result.returncode == 0, output

    return True, output


def _build_python(repo_path: Path, progress: ProgressFn = None) -> tuple[bool, str]:
    """Run pip install (dry-run check) or python -m py_compile on main files."""
    if progress:
        progress("Verifying build: checking Python dependencies…")

    req_file = repo_path / "requirements.txt"
    if req_file.exists():
        result = _run_cmd(
            ["pip", "install", "--dry-run", "-r", str(req_file)],
            cwd=str(repo_path), shell=True,
        )
        output = (result.stdout or "") + (result.stderr or "")
        if result.returncode != 0:
            return False, output
        return True, output

    # For pyproject.toml projects
    pyproject = repo_path / "pyproject.toml"
    if pyproject.exists():
        result = _run_cmd(
            ["pip", "install", "--dry-run", "."],
            cwd=str(repo_path), shell=True,
        )
        output = (result.stdout or "") + (result.stderr or "")
        return result.returncode == 0, output

    return True, "No requirements file found — skipping build verification."


def _build_maven(repo_path: Path, progress: ProgressFn = None) -> tuple[bool, str]:
    """Run mvn compile or gradle build."""
    java_env = _get_java_env()
    is_gradle = (repo_path / "build.gradle").exists() or (repo_path / "build.gradle.kts").exists()

    if is_gradle:
        gradle_cmd = _resolve_gradle_cmd(repo_path)
        if progress:
            progress("Verifying build: gradle build…")
        result = _run_cmd(
            gradle_cmd + ["build", "-x", "test", "--console=plain"],
            cwd=str(repo_path), env=java_env,
        )
    else:
        if progress:
            progress("Verifying build: mvn compile…")
        result = _run_cmd(
            ["mvn", "compile", "-q", "-DskipTests"],
            cwd=str(repo_path), env=java_env,
        )

    output = (result.stdout or "") + (result.stderr or "")
    return result.returncode == 0, output


def _resolve_gradle_cmd(repo_path: Path) -> list[str]:
    """Return the best Gradle executable: prefer the wrapper bundled with the repo."""
    if os.name == "nt":
        wrapper = repo_path / "gradlew.bat"
    else:
        wrapper = repo_path / "gradlew"
    if wrapper.exists():
        if os.name != "nt":
            wrapper.chmod(wrapper.stat().st_mode | 0o755)
        return [str(wrapper)]
    return ["gradle"]


def _build_dotnet(repo_path: Path, progress: ProgressFn = None) -> tuple[bool, str]:
    """Run dotnet build."""
    if progress:
        progress("Verifying build: dotnet build…")
    result = _run_cmd(["dotnet", "build", "--no-restore"], cwd=str(repo_path))
    output = (result.stdout or "") + (result.stderr or "")
    return result.returncode == 0, output


_BUILDERS = {
    "npm": _build_npm,
    "python": _build_python,
    "maven": _build_maven,
    "dotnet": _build_dotnet,
}


# ---------------------------------------------------------------------------
# Main fix loop
# ---------------------------------------------------------------------------

def fix_repo(
    repo_url: str,
    progress_callback: ProgressFn = None,
    max_iterations: int = MAX_FIX_ITERATIONS,
) -> dict:
    """
    End-to-end fix workflow:
      1. Clone repo
      2. Scan for vulnerabilities
      3. Parse fix versions from report
      4. Apply fixes to dependency manifests
      5. Build to verify
      6. Re-scan — repeat until clean or max iterations
    Returns a structured result dict.
    """
    def _progress(msg: str):
        if progress_callback:
            progress_callback(msg)

    repo_path = None
    try:
        # ── Step 1: Clone ──────────────────────────────────────────────
        _progress("Cloning repository…")
        repo_path = clone_repo(repo_url)
        project_name = repo_path.name or "project"

        _progress("Detecting project type…")
        ecosystem = detect_ecosystem(repo_path)
        eco_label = ECOSYSTEM_LABELS.get(ecosystem, ecosystem)
        _progress(f"Detected: {eco_label}")

        scanner_fn = _SCANNERS[ecosystem]
        fix_applier = _FIX_APPLIERS.get(ecosystem)
        builder = _BUILDERS.get(ecosystem)

        if not fix_applier:
            return {"success": False, "error": f"No fix applier for ecosystem: {ecosystem}"}

        iterations: list[dict] = []
        all_fixes_applied: list[dict] = []
        initial_rows: list[list[str]] | None = None

        for iteration in range(1, max_iterations + 1):
            _progress(f"━━━ Iteration {iteration}/{max_iterations} ━━━")

            # ── Scan ───────────────────────────────────────────────
            _progress(f"[Iteration {iteration}] Scanning for vulnerabilities…")
            rows = scanner_fn(repo_path, progress=_progress)
            rows.sort(key=lambda r: (SEVERITY_ORDER.get(r[0], 99), r[1]))

            if initial_rows is None:
                initial_rows = deepcopy(rows)

            summary = Counter(r[0] for r in rows)
            fixable_count = sum(
                1 for r in rows
                if r[0] in FIXABLE_SEVERITIES and _parse_fix_version(r[2])
            )

            _progress(
                f"[Iteration {iteration}] Found {len(rows)} vulnerabilities "
                f"({fixable_count} fixable)"
            )

            # If nothing to fix, we're done
            if fixable_count == 0:
                _progress(f"[Iteration {iteration}] No more fixable vulnerabilities — done!")
                iter_result = {
                    "iteration": iteration,
                    "fixes_applied": [],
                    "build_success": True,
                    "build_output": "",
                    "remaining_vulns": len(rows),
                    "remaining_fixable": 0,
                    "summary": dict(summary),
                }
                iterations.append(iter_result)
                break

            # ── Extract & apply fixes ──────────────────────────────
            fix_actions = extract_fix_actions(rows)
            _progress(f"[Iteration {iteration}] Applying {len(fix_actions)} version upgrades…")

            applied = fix_applier(repo_path, fix_actions, progress=_progress)

            applied_dicts = [
                {
                    "package": fa.package,
                    "from": fa.current_version,
                    "to": fa.target_version,
                    "vuln_id": fa.vuln_id,
                    "severity": fa.severity,
                }
                for fa in applied
            ]
            all_fixes_applied.extend(applied_dicts)

            if not applied:
                _progress(
                    f"[Iteration {iteration}] Could not apply any fixes "
                    "(versions may already be at the fix level or fix format unsupported)"
                )
                iter_result = {
                    "iteration": iteration,
                    "fixes_applied": applied_dicts,
                    "build_success": False,
                    "build_output": "No fixes could be applied.",
                    "remaining_vulns": len(rows),
                    "remaining_fixable": fixable_count,
                    "summary": dict(summary),
                }
                iterations.append(iter_result)
                break

            _progress(f"[Iteration {iteration}] Applied {len(applied)} fixes")

            # ── Build verification ─────────────────────────────────
            build_ok = True
            build_output = ""
            if builder:
                _progress(f"[Iteration {iteration}] Running build verification…")
                build_ok, build_output = builder(repo_path, progress=_progress)
                if build_ok:
                    _progress(f"[Iteration {iteration}] ✅ Build succeeded!")
                else:
                    _progress(f"[Iteration {iteration}] ⚠️ Build failed — will re-scan anyway")

            iter_result = {
                "iteration": iteration,
                "fixes_applied": applied_dicts,
                "build_success": build_ok,
                "build_output": build_output[-2000:] if build_output else "",
                "remaining_vulns": 0,    # will update after final re-scan
                "remaining_fixable": 0,
                "summary": {},
            }
            iterations.append(iter_result)

        # ── Final re-scan ──────────────────────────────────────────
        _progress("Running final vulnerability scan…")
        final_rows = scanner_fn(repo_path, progress=_progress)
        final_rows.sort(key=lambda r: (SEVERITY_ORDER.get(r[0], 99), r[1]))
        final_summary = Counter(r[0] for r in final_rows)
        final_fixable = sum(
            1 for r in final_rows
            if r[0] in FIXABLE_SEVERITIES and _parse_fix_version(r[2])
        )

        # Update last iteration with final numbers
        if iterations:
            iterations[-1]["remaining_vulns"] = len(final_rows)
            iterations[-1]["remaining_fixable"] = final_fixable
            iterations[-1]["summary"] = dict(final_summary)

        # ── Build the final PDF report ─────────────────────────────
        _progress("Building final report…")
        pdf_path = build_pdf(final_rows, f"{project_name}_fixed", ecosystem)

        # ── Compose result ─────────────────────────────────────────
        initial_summary = Counter(r[0] for r in (initial_rows or []))
        result = {
            "success": True,
            "project_name": project_name,
            "ecosystem": ecosystem,
            "ecosystem_label": eco_label,
            "iterations": iterations,
            "total_iterations": len(iterations),
            "fixes_applied": all_fixes_applied,
            "total_fixes": len(all_fixes_applied),
            # Before
            "before": {
                "total": len(initial_rows or []),
                "critical": initial_summary.get("CRITICAL", 0),
                "high": initial_summary.get("HIGH", 0),
                "moderate": initial_summary.get("MODERATE", 0),
                "low": initial_summary.get("LOW", 0),
                "rows": initial_rows or [],
            },
            # After
            "after": {
                "total": len(final_rows),
                "critical": final_summary.get("CRITICAL", 0),
                "high": final_summary.get("HIGH", 0),
                "moderate": final_summary.get("MODERATE", 0),
                "low": final_summary.get("LOW", 0),
                "rows": final_rows,
            },
            "pdf_filename": pdf_path.name,
            "pdf_path": str(pdf_path),
            "build_success": iterations[-1]["build_success"] if iterations else False,
        }

        _progress("✅ Fix process complete!")
        return result

    except Exception as exc:
        return {"success": False, "error": str(exc)}
    finally:
        if repo_path:
            cleanup_repo(repo_path)


# ---------------------------------------------------------------------------
# Apply Patch — uses the already-generated scan report as input
# ---------------------------------------------------------------------------

def apply_patch(
    repo_url: str,
    scan_rows: list[list[str]],
    ecosystem: str,
    progress_callback: ProgressFn = None,
    max_iterations: int = MAX_FIX_ITERATIONS,
) -> dict:
    """
    Apply fixes using a previously generated scan report.

    Unlike fix_repo(), this skips the initial scan — it takes the scan_rows
    directly from the report the user already has on screen, extracts fix
    actions, clones the repo, applies version upgrades, verifies the build,
    and re-scans iteratively until clean.

    Parameters:
        repo_url:          Git URL to clone.
        scan_rows:         The rows from a previous scan: [[severity, label, fix], …].
        ecosystem:         Detected ecosystem ('npm', 'python', 'maven', 'dotnet').
        progress_callback: Optional SSE progress function.
        max_iterations:    Max fix-build-scan cycles (default 5).
    """
    def _progress(msg: str):
        if progress_callback:
            progress_callback(msg)

    repo_path = None
    try:
        # ── Clone ──────────────────────────────────────────────────
        _progress("Cloning repository…")
        repo_path = clone_repo(repo_url)
        project_name = repo_path.name or "project"

        eco_label = ECOSYSTEM_LABELS.get(ecosystem, ecosystem)
        _progress(f"Ecosystem: {eco_label}")

        scanner_fn = _SCANNERS.get(ecosystem)
        fix_applier = _FIX_APPLIERS.get(ecosystem)
        builder = _BUILDERS.get(ecosystem)

        if not fix_applier:
            return {"success": False, "error": f"No fix applier for ecosystem: {ecosystem}"}

        # Use the scan report passed in as the initial data
        initial_rows = deepcopy(scan_rows)
        initial_rows.sort(key=lambda r: (SEVERITY_ORDER.get(r[0], 99), r[1]))

        initial_summary = Counter(r[0] for r in initial_rows)
        total_fixable = sum(
            1 for r in initial_rows
            if r[0] in FIXABLE_SEVERITIES and _parse_fix_version(r[2])
        )
        _progress(
            f"Report has {len(initial_rows)} vulnerabilities ({total_fixable} fixable)"
        )

        if total_fixable == 0:
            _progress("No fixable vulnerabilities in the report — nothing to patch.")
            return {
                "success": True,
                "project_name": project_name,
                "ecosystem": ecosystem,
                "ecosystem_label": eco_label,
                "iterations": [],
                "total_iterations": 0,
                "fixes_applied": [],
                "total_fixes": 0,
                "before": {
                    "total": len(initial_rows),
                    "critical": initial_summary.get("CRITICAL", 0),
                    "high": initial_summary.get("HIGH", 0),
                    "moderate": initial_summary.get("MODERATE", 0),
                    "low": initial_summary.get("LOW", 0),
                    "rows": initial_rows,
                },
                "after": {
                    "total": len(initial_rows),
                    "critical": initial_summary.get("CRITICAL", 0),
                    "high": initial_summary.get("HIGH", 0),
                    "moderate": initial_summary.get("MODERATE", 0),
                    "low": initial_summary.get("LOW", 0),
                    "rows": initial_rows,
                },
                "pdf_filename": "",
                "pdf_path": "",
                "build_success": True,
            }

        iterations: list[dict] = []
        all_fixes_applied: list[dict] = []

        # The first iteration uses the rows from the existing report;
        # subsequent iterations re-scan the patched repo.
        current_rows = initial_rows

        for iteration in range(1, max_iterations + 1):
            _progress(f"━━━ Iteration {iteration}/{max_iterations} ━━━")

            summary = Counter(r[0] for r in current_rows)
            fixable_count = sum(
                1 for r in current_rows
                if r[0] in FIXABLE_SEVERITIES and _parse_fix_version(r[2])
            )

            _progress(
                f"[Iteration {iteration}] {len(current_rows)} vulnerabilities "
                f"({fixable_count} fixable)"
            )

            if fixable_count == 0:
                _progress(f"[Iteration {iteration}] No more fixable vulnerabilities — done!")
                iterations.append({
                    "iteration": iteration,
                    "fixes_applied": [],
                    "build_success": True,
                    "build_output": "",
                    "remaining_vulns": len(current_rows),
                    "remaining_fixable": 0,
                    "summary": dict(summary),
                })
                break

            # ── Extract & apply fixes ──────────────────────────────
            fix_actions = extract_fix_actions(current_rows)
            _progress(f"[Iteration {iteration}] Applying {len(fix_actions)} version upgrades…")

            applied = fix_applier(repo_path, fix_actions, progress=_progress)

            applied_dicts = [
                {
                    "package": fa.package,
                    "from": fa.current_version,
                    "to": fa.target_version,
                    "vuln_id": fa.vuln_id,
                    "severity": fa.severity,
                }
                for fa in applied
            ]
            all_fixes_applied.extend(applied_dicts)

            if not applied:
                _progress(
                    f"[Iteration {iteration}] Could not apply any fixes "
                    "(versions may already match or fix format unsupported)"
                )
                iterations.append({
                    "iteration": iteration,
                    "fixes_applied": applied_dicts,
                    "build_success": False,
                    "build_output": "No fixes could be applied.",
                    "remaining_vulns": len(current_rows),
                    "remaining_fixable": fixable_count,
                    "summary": dict(summary),
                })
                break

            _progress(f"[Iteration {iteration}] Applied {len(applied)} fixes")

            # ── Build verification ─────────────────────────────────
            build_ok = True
            build_output = ""
            if builder:
                _progress(f"[Iteration {iteration}] Running build verification…")
                build_ok, build_output = builder(repo_path, progress=_progress)
                if build_ok:
                    _progress(f"[Iteration {iteration}] ✅ Build succeeded!")
                else:
                    _progress(f"[Iteration {iteration}] ⚠️ Build failed — will re-scan anyway")

            iterations.append({
                "iteration": iteration,
                "fixes_applied": applied_dicts,
                "build_success": build_ok,
                "build_output": build_output[-2000:] if build_output else "",
                "remaining_vulns": 0,
                "remaining_fixable": 0,
                "summary": {},
            })

            # ── Re-scan for next iteration ─────────────────────────
            if scanner_fn:
                _progress(f"[Iteration {iteration}] Re-scanning for remaining vulnerabilities…")
                current_rows = scanner_fn(repo_path, progress=_progress)
                current_rows.sort(key=lambda r: (SEVERITY_ORDER.get(r[0], 99), r[1]))

        # ── Final state ────────────────────────────────────────────
        final_rows = current_rows
        final_summary = Counter(r[0] for r in final_rows)
        final_fixable = sum(
            1 for r in final_rows
            if r[0] in FIXABLE_SEVERITIES and _parse_fix_version(r[2])
        )

        if iterations:
            iterations[-1]["remaining_vulns"] = len(final_rows)
            iterations[-1]["remaining_fixable"] = final_fixable
            iterations[-1]["summary"] = dict(final_summary)

        _progress("Building final report…")
        pdf_path = build_pdf(final_rows, f"{project_name}_patched", ecosystem)

        # ── Capture changed files + diffs ──────────────────────────
        _progress("Collecting changed files…")
        changed_files = _get_changed_files(repo_path)

        # Generate a patch_id and hold the repo for PR creation
        import uuid as _uuid
        patch_id = _uuid.uuid4().hex[:12]
        _ACTIVE_PATCHES[patch_id] = repo_path

        result = {
            "success": True,
            "project_name": project_name,
            "ecosystem": ecosystem,
            "ecosystem_label": eco_label,
            "iterations": iterations,
            "total_iterations": len(iterations),
            "fixes_applied": all_fixes_applied,
            "total_fixes": len(all_fixes_applied),
            "before": {
                "total": len(initial_rows),
                "critical": initial_summary.get("CRITICAL", 0),
                "high": initial_summary.get("HIGH", 0),
                "moderate": initial_summary.get("MODERATE", 0),
                "low": initial_summary.get("LOW", 0),
                "rows": initial_rows,
            },
            "after": {
                "total": len(final_rows),
                "critical": final_summary.get("CRITICAL", 0),
                "high": final_summary.get("HIGH", 0),
                "moderate": final_summary.get("MODERATE", 0),
                "low": final_summary.get("LOW", 0),
                "rows": final_rows,
            },
            "pdf_filename": pdf_path.name,
            "pdf_path": str(pdf_path),
            "build_success": iterations[-1]["build_success"] if iterations else True,
            "changed_files": changed_files,
            "patch_id": patch_id,
        }

        _progress("✅ Patch applied successfully!")
        return result

    except Exception as exc:
        # Clean up on error
        if repo_path:
            cleanup_repo(repo_path)
        return {"success": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Apply Patch Local — works on a user-specified local repo, no clone/cleanup
# ---------------------------------------------------------------------------

def apply_patch_local(
    local_path: str,
    scan_rows: list[list[str]],
    ecosystem: str,
    progress_callback: ProgressFn = None,
    max_iterations: int = MAX_FIX_ITERATIONS,
) -> dict:
    """
    Apply fixes on a locally cloned repo. The repo is NOT cleaned up after
    the fix — it stays on disk so the user can review and create a PR.

    Parameters:
        local_path:        Absolute path to the local repo.
        scan_rows:         Rows from a previous scan: [[severity, label, fix], …].
        ecosystem:         Detected ecosystem ('npm', 'python', 'maven', 'dotnet').
        progress_callback: Optional SSE progress function.
        max_iterations:    Max fix-build-scan cycles (default 5).
    """
    def _progress(msg: str):
        if progress_callback:
            progress_callback(msg)

    repo_path = Path(local_path)
    if not repo_path.exists():
        return {"success": False, "error": f"Path does not exist: {local_path}"}

    project_name = repo_path.name or "project"
    eco_label = ECOSYSTEM_LABELS.get(ecosystem, ecosystem)
    _progress(f"Working on local repo: {repo_path}")
    _progress(f"Ecosystem: {eco_label}")

    scanner_fn = _SCANNERS.get(ecosystem)
    fix_applier = _FIX_APPLIERS.get(ecosystem)
    builder = _BUILDERS.get(ecosystem)

    if not fix_applier:
        return {"success": False, "error": f"No fix applier for ecosystem: {ecosystem}"}

    initial_rows = deepcopy(scan_rows)
    initial_rows.sort(key=lambda r: (SEVERITY_ORDER.get(r[0], 99), r[1]))
    initial_summary = Counter(r[0] for r in initial_rows)

    total_fixable = sum(
        1 for r in initial_rows
        if r[0] in FIXABLE_SEVERITIES and _parse_fix_version(r[2])
    )
    _progress(f"Report has {len(initial_rows)} vulnerabilities ({total_fixable} fixable)")

    if total_fixable == 0:
        _progress("No fixable vulnerabilities — nothing to patch.")
        return {
            "success": True, "project_name": project_name,
            "ecosystem": ecosystem, "ecosystem_label": eco_label,
            "iterations": [], "total_iterations": 0,
            "fixes_applied": [], "total_fixes": 0,
            "before": {"total": len(initial_rows), "critical": initial_summary.get("CRITICAL", 0),
                       "high": initial_summary.get("HIGH", 0), "moderate": initial_summary.get("MODERATE", 0),
                       "low": initial_summary.get("LOW", 0), "rows": initial_rows},
            "after": {"total": len(initial_rows), "critical": initial_summary.get("CRITICAL", 0),
                      "high": initial_summary.get("HIGH", 0), "moderate": initial_summary.get("MODERATE", 0),
                      "low": initial_summary.get("LOW", 0), "rows": initial_rows},
            "pdf_filename": "", "pdf_path": "", "build_success": True,
            "changed_files": [], "patch_id": "", "local_path": str(repo_path),
        }

    try:
        iterations: list[dict] = []
        all_fixes_applied: list[dict] = []
        current_rows = initial_rows

        for iteration in range(1, max_iterations + 1):
            _progress(f"━━━ Iteration {iteration}/{max_iterations} ━━━")

            summary = Counter(r[0] for r in current_rows)
            fixable_count = sum(
                1 for r in current_rows
                if r[0] in FIXABLE_SEVERITIES and _parse_fix_version(r[2])
            )
            _progress(f"[Iteration {iteration}] {len(current_rows)} vulnerabilities ({fixable_count} fixable)")

            if fixable_count == 0:
                _progress(f"[Iteration {iteration}] No more fixable vulnerabilities — done!")
                iterations.append({"iteration": iteration, "fixes_applied": [],
                                   "build_success": True, "build_output": "",
                                   "remaining_vulns": len(current_rows),
                                   "remaining_fixable": 0, "summary": dict(summary)})
                break

            fix_actions = extract_fix_actions(current_rows)
            _progress(f"[Iteration {iteration}] Applying {len(fix_actions)} version upgrades…")
            applied = fix_applier(repo_path, fix_actions, progress=_progress)

            applied_dicts = [
                {"package": fa.package, "from": fa.current_version,
                 "to": fa.target_version, "vuln_id": fa.vuln_id, "severity": fa.severity}
                for fa in applied
            ]
            all_fixes_applied.extend(applied_dicts)

            if not applied:
                _progress(f"[Iteration {iteration}] Could not apply any fixes")
                iterations.append({"iteration": iteration, "fixes_applied": applied_dicts,
                                   "build_success": False, "build_output": "No fixes could be applied.",
                                   "remaining_vulns": len(current_rows),
                                   "remaining_fixable": fixable_count, "summary": dict(summary)})
                break

            _progress(f"[Iteration {iteration}] Applied {len(applied)} fixes")

            build_ok, build_output = True, ""
            if builder:
                _progress(f"[Iteration {iteration}] Running build verification…")
                build_ok, build_output = builder(repo_path, progress=_progress)
                _progress(f"[Iteration {iteration}] {'✅ Build succeeded!' if build_ok else '⚠️ Build failed'}")

            iterations.append({"iteration": iteration, "fixes_applied": applied_dicts,
                               "build_success": build_ok,
                               "build_output": build_output[-2000:] if build_output else "",
                               "remaining_vulns": 0, "remaining_fixable": 0, "summary": {}})

            if scanner_fn:
                _progress(f"[Iteration {iteration}] Re-scanning…")
                current_rows = scanner_fn(repo_path, progress=_progress)
                current_rows.sort(key=lambda r: (SEVERITY_ORDER.get(r[0], 99), r[1]))

        final_rows = current_rows
        final_summary = Counter(r[0] for r in final_rows)
        final_fixable = sum(1 for r in final_rows if r[0] in FIXABLE_SEVERITIES and _parse_fix_version(r[2]))

        if iterations:
            iterations[-1]["remaining_vulns"] = len(final_rows)
            iterations[-1]["remaining_fixable"] = final_fixable
            iterations[-1]["summary"] = dict(final_summary)

        _progress("Building final report…")
        pdf_path = build_pdf(final_rows, f"{project_name}_patched", ecosystem)

        _progress("Collecting changed files…")
        changed_files = _get_changed_files(repo_path)

        # Register patch for PR creation — local repo, NOT cleaned up
        import uuid as _uuid
        patch_id = _uuid.uuid4().hex[:12]
        _ACTIVE_PATCHES[patch_id] = repo_path

        result = {
            "success": True,
            "project_name": project_name,
            "ecosystem": ecosystem,
            "ecosystem_label": eco_label,
            "iterations": iterations,
            "total_iterations": len(iterations),
            "fixes_applied": all_fixes_applied,
            "total_fixes": len(all_fixes_applied),
            "before": {"total": len(initial_rows), "critical": initial_summary.get("CRITICAL", 0),
                       "high": initial_summary.get("HIGH", 0), "moderate": initial_summary.get("MODERATE", 0),
                       "low": initial_summary.get("LOW", 0), "rows": initial_rows},
            "after": {"total": len(final_rows), "critical": final_summary.get("CRITICAL", 0),
                      "high": final_summary.get("HIGH", 0), "moderate": final_summary.get("MODERATE", 0),
                      "low": final_summary.get("LOW", 0), "rows": final_rows},
            "pdf_filename": pdf_path.name,
            "pdf_path": str(pdf_path),
            "build_success": iterations[-1]["build_success"] if iterations else True,
            "changed_files": changed_files,
            "patch_id": patch_id,
            "local_path": str(repo_path),
        }

        _progress("✅ Patch applied to local repo!")
        return result

    except Exception as exc:
        return {"success": False, "error": str(exc)}
