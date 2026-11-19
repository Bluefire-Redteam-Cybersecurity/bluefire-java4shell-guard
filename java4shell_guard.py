#!/usr/bin/env python3
"""Bluefire Redteam — Java4Shell Guard.

Safe exposure check for CVE-2026-114938 (Java4Shell).

The check compares a Java runtime version, the host CPU flags, and JVM
startup flags with the public vendor tables. It does not decode Base64,
does not send a payload, and does not test whether a process can be
crashed or taken over. See README for the disclaimer and LICENSE for
the MIT terms.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import platform
import re
import shutil
import subprocess
import sys
from contextlib import redirect_stdout
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent

CVE = "CVE-2026-114938"
CVSS_ORACLE = "8.1"
CVSS_REPORTER = "9.2"
ORACLE = "https://www.oracle.com/security-alerts/cspunov2026.html"
CISA = "https://www.cisa.gov/news-events/alerts/2026/11/17/critical-java-vulnerability-requires-immediate-patching"
REDHAT = "https://access.redhat.com/security/vulnerabilities/RHSB-2026-018"
SITE = "https://bluefire-redteam.com"
CONTACT = "contact@bluefire-redteam.com"
CTA = f"Need this checked across your hosts? {SITE}"

# First release on each line that contains the November 17, 2026 fix.
# The fourth component is the out-of-band patch. 17.0.21 without it is
# the October build and is still affected. A fifth component is a vendor
# build counter (Corretto 17.0.21.1.2, Oracle's internal 17.0.21.0.3) and
# is not part of the comparison.
FIXED = {
    17: (17, 0, 21, 1),
    21: (21, 0, 13, 1),
    25: (25, 0, 5, 1),
    27: (27, 0, 1, 1),
}
# The AVX-512 VBMI Base64 intrinsic reached the Java 17 line in 17.0.6
# (January 2023). Earlier 17 updates do not have that code.
INTRODUCED_17 = (17, 0, 6, 0)
# Java 8 is in the CVE record only as the Enterprise Performance Pack.
JAVA8_PERF_FIXED = 513
# Feature releases that inherited the same HotSpot code and have no CPU.
UNSUPPORTED_FEATURES = {22, 23, 24, 26}
# Shipped around the backport. The public tables do not list them.
REVIEW_FEATURES = {20}
# GA before 17.0.6. Not in the affected set.
PRE_INTRINSIC_FEATURES = {18, 19}
# October CPU builds. A banner dated on patch day can be either the old
# build or a vendor respin that kept the same numbers. Do not call it fixed.
PATCH_DAY_BUILDS = {
    (17, 0, 21, 0),
    (21, 0, 13, 0),
    (25, 0, 5, 0),
    (27, 0, 1, 0),
}
PATCH_DAY = date(2026, 11, 17)

QUOTED_VERSION = re.compile(r'version\s+"([^"]+)"', re.I)
JAVA8_UPDATE = re.compile(r"(?:1\.8\.0[_-]|8u)(\d+)", re.I)
MODERN_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?")
PERF_MARK = re.compile(r"(?<![A-Za-z])perf(?![A-Za-z])|performance\s+pack", re.I)
GRAAL_EE = re.compile(r"graal", re.I)
DATE_MARK = re.compile(r"\b(20\d{2}-\d{2}-\d{2})\b")
VBMI_MARK = re.compile(r"avx512[_]?vbmi", re.I)
BASE64_OFF = re.compile(
    r"-XX:-UseBASE64Intrinsics|UseBASE64Intrinsics\s*[:= ]\s*false",
    re.I,
)
BASE64_ON = re.compile(
    r"-XX:\+UseBASE64Intrinsics|UseBASE64Intrinsics\s*[:= ]\s*true",
    re.I,
)
USE_AVX = re.compile(r"(?:-XX:)?UseAVX\s*[=: ]\s*(\d+)", re.I)
JAVA_BIN = re.compile(r"(?:^|[\s/])(java|javaw)(?:\.exe)?(?:\s|$)")
CVE_MARK = re.compile(r"CVE-2026-114938", re.I)

DECISION_RANK = {
    "EXPOSED": 6,
    "VULNERABLE_BUILD": 5,
    "MITIGATED": 4,
    "REVIEW": 3,
    "INCOMPLETE": 2,
    "PATCHED": 1,
    "NOT_AFFECTED": 0,
}
EXIT_CODE = {
    "EXPOSED": 2,
    "VULNERABLE_BUILD": 3,
    "MITIGATED": 3,
    "REVIEW": 3,
    "INCOMPLETE": 3,
    "PATCHED": 0,
    "NOT_AFFECTED": 0,
}


@dataclass(frozen=True)
class RuntimeVersion:
    raw: str
    parts: tuple[int, int, int, int] | None
    perf: bool
    prerelease: bool


@dataclass
class VersionVerdict:
    raw: str
    status: str  # patched, vulnerable, not_affected, unsupported, review, unknown
    fixed_in: str | None
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    name: str
    version: VersionVerdict
    cpu: str  # vbmi, absent, unknown
    cpu_detail: str
    workaround: str | None
    decision: str

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["version"] = self.version.to_dict()
        return payload


def dotted(parts: tuple[int, ...]) -> str:
    return ".".join(str(part) for part in parts)


def _version_token(raw: str) -> str | None:
    """Pull a version token out of a banner or a version string.

    Process command lines are not scanned for numbers. A path such as
    java-17-openjdk or a jar named app-17.0.2.jar is not a runtime version.
    """
    quoted = QUOTED_VERSION.search(raw)
    if quoted:
        return quoted.group(1)
    first = raw.splitlines()[0].strip() if raw else ""
    if not first or JAVA_BIN.search(first) or "/" in first or first.endswith(".jar"):
        return None
    if " " in first and "version" not in first.lower() and not first[0].isdigit():
        return None
    return first


def parse_runtime(text: str) -> RuntimeVersion:
    raw = (text or "").strip()
    perf = bool(PERF_MARK.search(raw))
    token = _version_token(raw)
    if token is None:
        return RuntimeVersion(raw, None, perf, False)
    prerelease = bool(re.search(r"-(?:ea|internal|beta)\b", token, re.I))
    head = token.split("+", 1)[0].strip()

    java8 = JAVA8_UPDATE.search(head)
    if java8 is None and QUOTED_VERSION.search(raw) is None:
        java8 = JAVA8_UPDATE.search(raw)
    if java8 and (head.startswith("1.8") or head.lower().startswith("8u") or "1.8.0" in raw or re.search(r"(?<!\d)8u\d+", raw, re.I)):
        return RuntimeVersion(raw, (8, 0, int(java8.group(1)), 0), perf, prerelease)

    modern = MODERN_VERSION.search(head)
    if modern is None:
        return RuntimeVersion(raw, None, perf, prerelease)

    major, minor, security, fourth, _fifth = modern.groups()
    parts = (int(major), int(minor), int(security), int(fourth) if fourth else 0)
    if parts[0] == 1 and parts[1] == 8:
        update_match = JAVA8_UPDATE.search(raw)
        update = int(update_match.group(1)) if update_match else parts[2]
        parts = (8, 0, update, 0)
    return RuntimeVersion(raw, parts, perf, prerelease)


def banner_date(text: str) -> date | None:
    match = DATE_MARK.search(text or "")
    if not match:
        return None
    try:
        return date.fromisoformat(match.group(1))
    except ValueError:
        return None


def classify_version(
    text: str,
    vendor_fix: bool = False,
    seen_date: date | None = None,
) -> VersionVerdict:
    parsed = parse_runtime(text)
    if vendor_fix:
        return VersionVerdict(
            _label(parsed),
            "patched",
            None,
            "A changelog or package note names CVE-2026-114938. "
            "Confirm every JVM has been restarted on that build.",
        )
    if GRAAL_EE.search(parsed.raw) and re.search(r"\b21\.3\.\d+", parsed.raw):
        return _maybe_prerelease(
            parsed,
            VersionVerdict(
                _label(parsed),
                "review",
                None,
                "Oracle lists GraalVM Enterprise Edition 21.3.20.0.3 as affected. "
                "The CVE record does not publish a fixed build number for that line. "
                "Confirm the November 17, 2026 patch with Oracle before calling it clear.",
            ),
        )

    if parsed.parts is None:
        return VersionVerdict(
            _label(parsed) or "(unreadable)",
            "unknown",
            None,
            "No Java version could be read. Pass --version, --java-bin, or a java -version banner. "
            "A process command line is not a version.",
        )

    major, minor, _security, _patch = parsed.parts
    if major == 8:
        return _maybe_prerelease(parsed, _classify_java8(parsed))
    if minor != 0 and major >= 17:
        return _maybe_prerelease(
            parsed,
            VersionVerdict(
                _label(parsed),
                "review",
                None,
                "OpenJDK update numbers use minor 0, for example 21.0.13. "
                "This looks like GraalVM Enterprise Edition versioning. "
                "Oracle lists 21.3.20.0.3 as affected and does not publish a fixed number here.",
            ),
        )

    if major in FIXED:
        return _maybe_prerelease(parsed, _classify_openjdk_line(parsed, seen_date))
    if major in UNSUPPORTED_FEATURES:
        return _maybe_prerelease(
            parsed,
            VersionVerdict(
                _label(parsed),
                "unsupported",
                "a patched Java 21, 25, or 27 build",
                f"Java {major} is a non-LTS feature release in the same HotSpot generation "
                "as the affected decoder. It has no November 17, 2026 CPU. "
                "Move the service to 21.0.13.1, 25.0.5.1, or 27.0.1.1, or to a later vendor build that names the CVE.",
            ),
        )
    if major in REVIEW_FEATURES:
        return _maybe_prerelease(
            parsed,
            VersionVerdict(
                _label(parsed),
                "review",
                None,
                f"Java {major} shipped around the backport of the affected decoder. "
                "The public tables do not list this feature release. "
                "Treat it as exposed on AVX-512 VBMI hosts unless the vendor changelog says otherwise, "
                "and plan a move to a patched LTS build.",
            ),
        )
    if major in PRE_INTRINSIC_FEATURES or major < 17:
        return _maybe_prerelease(
            parsed,
            VersionVerdict(
                _label(parsed),
                "not_affected",
                None,
                "Standard Java 8 and Java 11, and feature releases from before OpenJDK 17.0.6, "
                "are not in the affected set for this CVE. "
                "Java 8 is affected only as the Enterprise Performance Pack.",
            ),
        )
    return _maybe_prerelease(
        parsed,
        VersionVerdict(
            _label(parsed),
            "review",
            None,
            "This version is newer than the Java 17, 21, 25, and 27 lines in the November 17, 2026 table. "
            "Confirm the release notes name CVE-2026-114938.",
        ),
    )


def _label(parsed: RuntimeVersion) -> str:
    if parsed.parts is None:
        line = (parsed.raw or "").splitlines()[0]
        return line[:160]
    if parsed.parts[0] == 8:
        suffix = "-perf" if parsed.perf else ""
        return f"8u{parsed.parts[2]}{suffix}"
    if parsed.parts[3] == 0:
        return dotted(parsed.parts[:3])
    return dotted(parsed.parts)


def _maybe_prerelease(parsed: RuntimeVersion, verdict: VersionVerdict) -> VersionVerdict:
    if parsed.prerelease and verdict.status == "patched":
        return VersionVerdict(
            verdict.raw,
            "review",
            verdict.fixed_in,
            "This looks like an early-access or internal build of a fixed line. "
            "Confirm the vendor changelog names CVE-2026-114938 before treating it as the patch.",
        )
    return verdict


def _classify_java8(parsed: RuntimeVersion) -> VersionVerdict:
    update = parsed.parts[2] if parsed.parts else 0
    if not parsed.perf:
        return VersionVerdict(
            f"8u{update}",
            "not_affected",
            None,
            "Standard Java 8 does not ship the affected decoder. "
            "The CVE record names the Enterprise Performance Pack only.",
        )
    label = f"8u{update}-perf"
    if update >= JAVA8_PERF_FIXED:
        return VersionVerdict(
            label,
            "patched",
            "8u513-perf",
            "This Enterprise Performance Pack update is at or above 8u513-perf.",
        )
    return VersionVerdict(
        label,
        "vulnerable",
        "8u513-perf",
        "Java 8 is affected only as the Enterprise Performance Pack. "
        "Oracle's fixed pack is 8u513-perf. Restart every JVM after the upgrade.",
    )


def _classify_openjdk_line(parsed: RuntimeVersion, seen_date: date | None) -> VersionVerdict:
    assert parsed.parts is not None
    major = parsed.parts[0]
    fixed = FIXED[major]
    label = _label(parsed)
    fixed_label = dotted(fixed)
    if major == 17 and parsed.parts < INTRODUCED_17:
        return VersionVerdict(
            label,
            "not_affected",
            None,
            "The affected Base64 decoder reached Java 17 in 17.0.6. This update is earlier.",
        )
    if parsed.parts >= fixed:
        return VersionVerdict(
            label,
            "patched",
            fixed_label,
            f"This Java {major} build is at or above {fixed_label}. Restart any JVM that is still on the old build.",
        )
    if parsed.parts in PATCH_DAY_BUILDS and seen_date is not None and seen_date >= PATCH_DAY:
        return VersionVerdict(
            label,
            "review",
            fixed_label,
            f"The banner date is {seen_date.isoformat()}, on or after patch day, "
            f"but the version is still {label} and not {fixed_label}. "
            "Some vendors kept the October numbers. Pass --changelog when the package note names "
            "CVE-2026-114938. Otherwise install the .1 build and restart.",
        )
    return VersionVerdict(
        label,
        "vulnerable",
        fixed_label,
        f"Upgrade this Java {major} runtime to {fixed_label} or newer, then restart every JVM. "
        "A build of 17.0.21, 21.0.13, 25.0.5, or 27.0.1 without the .1 patch is still the affected October update.",
    )


def cpu_state(flag_text: str | None, arch: str) -> tuple[str, str]:
    """Return (vbmi|absent|unknown, detail)."""
    arm = arch.lower() in {"arm64", "aarch64", "arm"}
    if flag_text is not None and VBMI_MARK.search(flag_text):
        where = "an ARM host" if arm else "this CPU"
        return (
            "vbmi",
            f"AVX-512 VBMI is visible on {where}. The affected decoder can run here.",
        )
    if arm:
        return (
            "absent",
            "This CPU is ARM64. The affected path is x86-64 AVX-512 code, so it does not run here. "
            "A vulnerable build is still a vulnerable build if the image moves to an Intel or AMD host.",
        )
    if flag_text is None or not flag_text.strip():
        return ("unknown", "CPU flags could not be read. Pass --cpu-flags or a saved /proc/cpuinfo.")
    return (
        "absent",
        "AVX-512 VBMI is not in the CPU flags. The affected decoder is not selected on this host. "
        "Replace the runtime anyway before it is copied onto a VBMI machine.",
    )


def read_host_cpu() -> tuple[str, str, str]:
    """Return (state, detail, arch)."""
    arch = platform.machine() or "unknown"
    flag_text: str | None = None
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        try:
            flag_text = cpuinfo.read_text(encoding="utf-8", errors="replace")
        except OSError:
            flag_text = None
    elif sys.platform == "darwin":
        chunks: list[str] = []
        for key in ("machdep.cpu.features", "machdep.cpu.leaf7_features"):
            try:
                chunks.append(
                    subprocess.check_output(
                        ["sysctl", "-n", key],
                        text=True,
                        timeout=3,
                        stderr=subprocess.DEVNULL,
                    )
                )
            except (OSError, subprocess.SubprocessError):
                continue
        flag_text = "\n".join(chunks) if chunks else None
    state, detail = cpu_state(flag_text, arch)
    return state, detail, arch


def parse_cpu_override(value: str | None, arch: str) -> tuple[str, str] | None:
    if value is None:
        return None
    token = value.strip().lower()
    if token in {"unknown", "unread"}:
        return "unknown", "CPU flags were left unknown on purpose."
    if token in {"none", "absent", "no", "arm", "arm64", "aarch64"}:
        forced_arch = "aarch64" if token in {"arm", "arm64", "aarch64"} else arch
        return cpu_state("" if token in {"arm", "arm64", "aarch64"} else "avx avx2", forced_arch)
    return cpu_state(value, arch)


def workaround_from_text(text: str | None) -> str | None:
    if not text:
        return None
    if BASE64_OFF.search(text) and not _last_base64_flag_enables(text):
        return "-XX:-UseBASE64Intrinsics is set, so the optimized Base64 decoder is off."
    match = USE_AVX.search(text)
    if match and int(match.group(1)) <= 2:
        return f"UseAVX={match.group(1)} keeps the JVM off the AVX-512 path."
    return None


def _last_base64_flag_enables(text: str) -> bool:
    """A later +UseBASE64Intrinsics on the same command line wins."""
    off = [match.start() for match in BASE64_OFF.finditer(text)]
    on = [match.start() for match in BASE64_ON.finditer(text)]
    if not on:
        return False
    if not off:
        return True
    return max(on) > max(off)


def decide(version: VersionVerdict, cpu: str, workaround: str | None) -> str:
    if version.status == "patched":
        return "PATCHED"
    if version.status == "not_affected":
        return "NOT_AFFECTED"
    if version.status == "unknown":
        return "INCOMPLETE"
    if version.status == "review":
        return "REVIEW"
    if workaround:
        return "MITIGATED"
    if cpu == "vbmi":
        return "EXPOSED"
    if cpu == "absent":
        return "VULNERABLE_BUILD"
    return "REVIEW"


def worst(decisions: list[str]) -> str:
    if not decisions:
        return "INCOMPLETE"
    return max(decisions, key=lambda item: DECISION_RANK[item])


def changelog_names_fix(path: str | None) -> bool:
    if not path:
        return False
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(CVE_MARK.search(text))


def load_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


def run_java_version(binary: str) -> str:
    try:
        completed = subprocess.run(
            [binary, "-version"],
            check=False,
            text=True,
            capture_output=True,
            timeout=8,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return f"java -version failed: {exc}"
    return "\n".join(part for part in (completed.stderr, completed.stdout) if part).strip()


def local_java_processes() -> list[tuple[str, str, str | None]]:
    """Return (name, banner-or-empty, flag-text) for Java processes.

    Version comes from jcmd when the same user can ask for it. Flags come
    from the process command line and, when jcmd works, from VM.flags.
    Nothing is sent to the application.
    """
    if shutil.which("ps") is None:
        return []
    try:
        completed = subprocess.run(
            ["ps", "-ax", "-o", "pid=,command="],
            check=False,
            text=True,
            capture_output=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    rows: list[tuple[str, str, str | None]] = []
    for line in completed.stdout.splitlines():
        stripped = line.strip()
        if not stripped or not JAVA_BIN.search(stripped):
            continue
        pid, _, command = stripped.partition(" ")
        pid = pid.strip()
        command = command.strip()
        if not pid.isdigit():
            continue
        banner = ""
        flags = command
        jcmd = _jcmd_for(command)
        if jcmd:
            version_text = _jcmd(jcmd, pid, "VM.version")
            flag_text = _jcmd(jcmd, pid, "VM.flags")
            if version_text:
                banner = version_text
            if flag_text:
                flags = command + "\n" + flag_text
        if not banner:
            banner = command
        rows.append((f"pid {pid}", banner, flags))
    return rows


def _jcmd_for(command: str) -> str | None:
    binary = command.split()[0]
    candidate = Path(binary).with_name("jcmd")
    if candidate.is_file():
        return str(candidate)
    return shutil.which("jcmd")


def _jcmd(jcmd: str, pid: str, query: str) -> str:
    try:
        completed = subprocess.run(
            [jcmd, pid, query],
            check=False,
            text=True,
            capture_output=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if completed.returncode != 0:
        return ""
    return completed.stdout


def finding_for(
    name: str,
    version_text: str,
    cpu: str,
    cpu_detail: str,
    flag_text: str | None = None,
    vendor_fix: bool = False,
) -> Finding:
    seen = banner_date(version_text)
    version = classify_version(version_text, vendor_fix=vendor_fix, seen_date=seen)
    workaround = workaround_from_text(flag_text)
    return Finding(
        name=name,
        version=version,
        cpu=cpu,
        cpu_detail=cpu_detail,
        workaround=workaround,
        decision=decide(version, cpu, workaround),
    )


def remediation_lines(finding: Finding | None) -> list[str]:
    fixed = finding.version.fixed_in if finding else None
    lines = [
        "1. Install the vendor build that contains the November 17, 2026 fix, then restart every JVM.",
        "   Oracle floors: 17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1, and 8u513-perf for the Enterprise Performance Pack.",
        "   Corretto published 17.0.21.1.2, 21.0.13.1.2, 25.0.5.1.2, and 27.0.1.1.4 on the same day.",
        "   Other builds (Temurin, Zulu, Liberica, Microsoft, Red Hat, distro packages) follow their own advisories.",
        "   A package on disk does nothing until the process starts on that build.",
        "2. Search images and appliances, not only the java binary on PATH. Bundled runtimes are in scope.",
        "   Rebuild the image after the base image moves, then redeploy.",
    ]
    if fixed and finding and finding.version.status not in {"patched", "not_affected"}:
        lines.insert(1, f"   This runtime should move to {fixed} or newer.")
    lines.extend([
        "3. Until that restart, the temporary control reported by researchers is:",
        "   -XX:-UseBASE64Intrinsics",
        "   On x86-64 only, -XX:UseAVX=2 also stays off the affected path.",
        "   Do not put UseAVX=2 on an ARM64 JVM. Those builds do not recognize the flag and will not start.",
        "   Oracle's advisory publishes no workaround. Neither flag is a fix.",
        "4. Prove the running process, not the shell on PATH:",
        "   jcmd <pid> VM.version",
        "   jcmd <pid> VM.flags -all",
        f"5. Advisories: {ORACLE}",
        f"   {CISA}",
        f"   {REDHAT}",
    ])
    return lines


class Paint:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled and sys.stdout.isatty()

    def _w(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def title(self, text: str) -> str:
        return self._w("1;34", text)

    def good(self, text: str) -> str:
        return self._w("32", text)

    def bad(self, text: str) -> str:
        return self._w("1;31", text)

    def warn(self, text: str) -> str:
        return self._w("33", text)

    def dim(self, text: str) -> str:
        return self._w("2", text)


def render_text(findings: list[Finding], color: bool) -> str:
    paint = Paint(color)
    decision = worst([item.decision for item in findings]) if findings else "INCOMPLETE"
    tone = {
        "PATCHED": paint.good,
        "NOT_AFFECTED": paint.good,
        "MITIGATED": paint.warn,
        "VULNERABLE_BUILD": paint.warn,
        "REVIEW": paint.warn,
        "INCOMPLETE": paint.warn,
    }.get(decision, paint.bad)
    rows = [
        paint.title("Bluefire Redteam  ·  Java4Shell Guard"),
        paint.dim(f"{CVE}   Oracle CVSS 3.1 {CVSS_ORACLE}   reporter CVSS 4.0 {CVSS_REPORTER}"),
        "",
        f"Decision   {tone(decision)}",
        paint.dim("Version, CPU flags, and JVM flags only. No Base64 input is sent."),
        "",
    ]
    if not findings:
        rows.append("No Java runtime was supplied.")
    for item in findings:
        rows.append(paint.title(item.name))
        rows.append(f"  Runtime    {item.version.raw}   {item.version.status.upper()}")
        if item.version.fixed_in:
            rows.append(f"  Fixed in   {item.version.fixed_in}")
        rows.append(paint.dim(f"  {item.version.detail}"))
        rows.append(f"  CPU        {item.cpu}")
        rows.append(paint.dim(f"  {item.cpu_detail}"))
        if item.workaround:
            rows.append(f"  Workaround {item.workaround}")
        else:
            rows.append("  Workaround none")
        rows.append(f"  Call       {tone(item.decision)}")
        rows.append("")
    rows.append(paint.title("Remediation"))
    rows.extend(remediation_lines(findings[0] if findings else None))
    rows.append("")
    rows.append(paint.dim(
        "A vulnerable build on a CPU without AVX-512 VBMI is not exploitable on that CPU. "
        "It is still the wrong build to copy onto a newer Intel or AMD host. "
        "A clear result is not proof the application is safe."
    ))
    rows.append("")
    rows.append(paint.title("Bluefire Redteam"))
    rows.append("A global offensive security firm.")
    rows.append(CTA)
    return "\n".join(rows)


def render_markdown(findings: list[Finding]) -> str:
    decision = worst([item.decision for item in findings]) if findings else "INCOMPLETE"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Bluefire Redteam — Java4Shell exposure report",
        "",
        f"Prepared {now}.",
        "",
        f"**Decision: {decision}**",
        "",
        "This is an exposure review for CVE-2026-114938. It compares runtime versions, "
        "CPU flags, and JVM flags with the public vendor tables. It does not decode Base64, "
        "does not send a payload, and it is not evidence that an attacker succeeded.",
        "",
        "## Runtimes",
        "",
        "| Runtime | Version | Version status | CPU | Workaround | Call |",
        "|---|---|---|---|---|---|",
    ]
    for item in findings:
        version = item.version.raw.replace("|", "\\|")
        workaround = (item.workaround or "none").replace("|", "\\|")
        lines.append(
            f"| {item.name} | `{version}` | {item.version.status} | {item.cpu} | {workaround} | {item.decision} |"
        )
    if not findings:
        lines.append("| — | — | — | — | — | No runtime was supplied |")
    lines.extend(["", "## Notes", ""])
    for item in findings:
        lines.append(f"- **{item.name}.** {item.version.detail} {item.cpu_detail}")
    lines.extend(["", "## Remediation", ""])
    for line in remediation_lines(findings[0] if findings else None):
        lines.append(line if line[:1].isdigit() else f"  {line.strip()}")
    lines.extend([
        "",
        "## What has to be true before this CVE applies",
        "",
        "- The runtime contains the affected HotSpot Base64 decoder (Java 17.0.6 through the build before the November 17, 2026 fix, or Java 21, 25, or 27 before that fix, or the Java 8 Enterprise Performance Pack before 8u513-perf).",
        "- The host CPU is x86-64 and advertises AVX-512 VBMI. ARM64, and older x86-64, do not run that path.",
        "- Some application path passes data it does not fully trust to `Base64.getDecoder()` or `Base64.getUrlDecoder()`. This tool does not look for that call site.",
        "",
        "## Compliance mapping",
        "",
        "| Framework | Control | How this helps |",
        "|---|---|---|",
        "| ISO/IEC 27001:2022 | A.8.8 | Records the vulnerable runtime and the build that closes it |",
        "| PCI DSS 4.0 | 6.3.3 | Drives installation of a critical security patch |",
        "| NIST CSF 2.0 | ID.RA-01 | Records the asset, the observed version, and the CPU condition |",
        "| NIST CSF 2.0 | PR.PS-02 | Checks that the runtime is on a maintained release |",
        "",
        "## Limits",
        "",
        "- `java` on PATH can be a different binary from the one inside a service, a container, or an appliance.",
        "- A vendor can ship the fix without moving to 17.0.21.1. Pass `--changelog` when the note names CVE-2026-114938.",
        "- A banner dated November 17, 2026 with version 17.0.21 is not treated as patched. The October and November builds have been confused in the wild.",
        "- GraalVM Enterprise Edition 21.3 is called out for a human to confirm. Oracle did not publish a fixed build number in the CVE record.",
        "- The workaround flags are researcher-reported. Oracle's advisory does not list them.",
        "- CPU flags describe the machine this command ran on, unless the fleet file or `--cpu-flags` says otherwise.",
        "",
        "## Disclaimer",
        "",
        "Checker only. This report is not proof of compromise or of safety, and it is not legal advice. "
        "The tool is provided as-is under the MIT License.",
        "",
        "## See also",
        "",
        "- [PHP2Shell Guard](https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-php2shell-guard)",
        "- [Ivanti Connect Secure check](https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-ivanti-ics-guard)",
        "- [SharePoint CVE-2025-53770 toolkit](https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-sharepoint-cve-2025-53770)",
        "- [Nx s1ngularity check](https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-nx-s1ngularity-check)",
        "",
        "## Bluefire Redteam",
        "",
        "Bluefire Redteam is a global offensive security firm. The work is red teaming, penetration testing, "
        "and AI security testing.",
        "",
        f"This note is a point-in-time exposure check. To run it across a fleet, write to [{CONTACT}](mailto:{CONTACT}) "
        f"or start at [{SITE}]({SITE}).",
        "",
    ])
    return "\n".join(lines)


def interim_env() -> str:
    return "\n".join([
        "# Bluefire Redteam — interim Java4Shell workaround",
        f"# {CVE}",
        "# Not a complete fix. Install a patched runtime and restart every JVM.",
        "# Oracle's advisory publishes no workaround. Researchers report that this",
        "# flag keeps the JVM off the optimized Base64 decoder.",
        "# On x86-64, -XX:UseAVX=2 is the other reported switch. Do not set UseAVX",
        "# on ARM64. Those JVMs do not recognize it and will fail to start.",
        f"# {CTA}",
        "",
        "JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics",
        "",
    ])


def gather(args: argparse.Namespace, include_host: bool) -> list[Finding]:
    if getattr(args, "cpu_flags", None):
        cpu, cpu_detail = parse_cpu_override(args.cpu_flags, platform.machine() or "unknown") or (
            "unknown",
            "CPU override could not be read.",
        )
    elif getattr(args, "cpu_file", None):
        cpu, cpu_detail = cpu_state(load_text(args.cpu_file), getattr(args, "arch", None) or "x86_64")
    elif include_host:
        cpu, cpu_detail, _arch = read_host_cpu()
    else:
        cpu, cpu_detail = "unknown", "No CPU flags were supplied."

    vendor_fix = changelog_names_fix(getattr(args, "changelog", None))
    flag_text = None
    if getattr(args, "jvm_flags", None):
        flag_text = args.jvm_flags
    findings: list[Finding] = []

    version_text = getattr(args, "version", None)
    version_file = getattr(args, "version_file", None)
    java_bin = getattr(args, "java_bin", None)
    if version_file:
        version_text = load_text(version_file)
    elif java_bin:
        version_text = run_java_version(java_bin)
    elif version_text is None and include_host:
        binary = shutil.which("java")
        if binary:
            version_text = run_java_version(binary)
            if _version_token(version_text) is None:
                findings.append(Finding(
                    name="java on PATH",
                    version=VersionVerdict(
                        "not installed",
                        "unknown",
                        None,
                        f"{binary} did not print a version. On macOS, /usr/bin/java is often a stub. "
                        "Pass --java-bin with the real runtime.",
                    ),
                    cpu=cpu,
                    cpu_detail=cpu_detail,
                    workaround=workaround_from_text(flag_text),
                    decision="INCOMPLETE",
                ))
            else:
                findings.append(
                    finding_for("java on PATH", version_text, cpu, cpu_detail, flag_text, vendor_fix)
                )
            version_text = None
    if version_text:
        findings.append(finding_for("runtime", version_text, cpu, cpu_detail, flag_text, vendor_fix))

    if getattr(args, "processes", False):
        for name, banner, flags in local_java_processes():
            findings.append(finding_for(name, banner, cpu, cpu_detail, flags, vendor_fix=False))
    return findings


def emit(findings: list[Finding], as_json: bool, color: bool) -> int:
    decision = worst([item.decision for item in findings]) if findings else "INCOMPLETE"
    if as_json:
        print(json.dumps({
            "product": "Bluefire Java4Shell Guard",
            "cve": CVE,
            "decision": decision,
            "findings": [item.to_dict() for item in findings],
            "by": "Bluefire Redteam",
            "site": SITE,
        }, indent=2))
    else:
        print(render_text(findings, color=color))
    return EXIT_CODE[decision]


def cmd_audit(args: argparse.Namespace) -> int:
    return emit(gather(args, include_host=True), args.json, color=not args.no_color)


def cmd_report(args: argparse.Namespace) -> int:
    findings = gather(args, include_host=True)
    document = render_markdown(findings)
    if args.out:
        Path(args.out).write_text(document, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(document)
    decision = worst([item.decision for item in findings]) if findings else "INCOMPLETE"
    return EXIT_CODE[decision]


def cmd_fleet(args: argparse.Namespace) -> int:
    findings: list[Finding] = []
    with Path(args.csv).open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or "version" not in reader.fieldnames:
            print("Fleet CSV needs a header with a version column.", file=sys.stderr)
            return 1
        for row in reader:
            version = (row.get("version") or "").strip()
            if not version or version.startswith("#"):
                continue
            name = (row.get("name") or version).strip()
            cpu_value = (row.get("cpu") or "unknown").strip()
            cpu, cpu_detail = parse_cpu_override(cpu_value, "x86_64") or (
                "unknown",
                "CPU column was empty.",
            )
            workaround = (row.get("workaround") or "").strip()
            flag_text = None
            if workaround in {"base64-off", "intrinsics-off"}:
                flag_text = "-XX:-UseBASE64Intrinsics"
            elif workaround in {"avx2", "useavx2"}:
                flag_text = "-XX:UseAVX=2"
            elif workaround:
                flag_text = workaround
            findings.append(finding_for(name, version, cpu, cpu_detail, flag_text))
    return emit(findings, args.json, color=not args.no_color)


def cmd_rules(args: argparse.Namespace) -> int:
    destination = Path(args.out)
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / "java4shell-interim.env"
    target.write_text(interim_env(), encoding="utf-8")
    print(f"Wrote {target}")
    print("Temporary only. Install the patched runtime and restart the JVM.")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    banner = load_text(str(ROOT / "fixtures" / "temurin-17.0.21.txt"))
    flags = load_text(str(ROOT / "fixtures" / "cpuinfo-vbmi.txt"))
    cpu, detail = cpu_state(flags, "x86_64")
    finding = finding_for("demo temurin 17.0.21 on VBMI", banner, cpu, detail)
    print(render_text([finding], color=not args.no_color))
    print()
    print("Demo fixture is supposed to be EXPOSED.")
    print("Next: python3 java4shell_guard.py selftest")
    print("      python3 java4shell_guard.py fleet fixtures/fleet.csv")
    print("      python3 java4shell_guard.py rules --out rules")
    return 0


def selftest() -> int:
    failures: list[str] = []

    def expect(condition: bool, message: str) -> None:
        if not condition:
            failures.append(message)

    cases = {
        "17.0.5": "not_affected",
        "17.0.6": "vulnerable",
        "17.0.21": "vulnerable",
        "17.0.21+9": "vulnerable",
        "17.0.21.0.3": "vulnerable",
        "17.0.21.1": "patched",
        "17.0.21.1+4": "patched",
        "17.0.21.1.2": "patched",
        "21.0.0": "vulnerable",
        "21.0.13": "vulnerable",
        "21.0.13.1": "patched",
        "25.0.5": "vulnerable",
        "25.0.5.1": "patched",
        "27.0.1": "vulnerable",
        "27.0.1.1.4": "patched",
        "11.0.33": "not_affected",
        "1.8.0_511": "not_affected",
        "8u511": "not_affected",
        "8u511b33-perf": "vulnerable",
        "8u513-perf": "patched",
        "16.0.2": "not_affected",
        "22.0.2": "unsupported",
        "20.0.2": "review",
        "28.0.1": "review",
    }
    for raw, status in cases.items():
        got = classify_version(raw).status
        expect(got == status, f"{raw} should be {status}, got {got}")

    temurin = load_text(str(ROOT / "fixtures" / "temurin-17.0.21.txt"))
    temurin_verdict = classify_version(temurin)
    expect(temurin_verdict.status == "vulnerable", "Temurin 17.0.21 banner should be vulnerable")
    expect(temurin_verdict.raw == "17.0.21", f"Temurin label should be 17.0.21, got {temurin_verdict.raw}")
    expect(
        classify_version(temurin, seen_date=date(2026, 11, 17)).status == "review",
        "17.0.21 dated on patch day should be review, not patched",
    )
    oracle = load_text(str(ROOT / "fixtures" / "oracle-17.0.21.1.txt"))
    expect(classify_version(oracle).status == "patched", "Oracle 17.0.21.1 banner should be patched")
    perf = load_text(str(ROOT / "fixtures" / "java8-perf.txt"))
    expect(classify_version(perf).status == "vulnerable", "Java 8 perf banner should be vulnerable")
    expect(
        classify_version("17.0.12", vendor_fix=True).status == "patched",
        "a changelog that names the CVE should count as patched",
    )
    expect(classify_version("GraalVM EE 21.3.20.0.3").status == "review", "GraalVM EE should be review")
    expect(
        classify_version("/usr/lib/jvm/java-17-openjdk/bin/java -jar app-17.0.2.jar").status == "unknown",
        "a process command must not be parsed as a Java version",
    )
    expect(classify_version("17.0.21.1-ea").status == "review", "an early-access fixed build should be review")

    vbmi, _ = cpu_state(load_text(str(ROOT / "fixtures" / "cpuinfo-vbmi.txt")), "x86_64")
    avx2, _ = cpu_state(load_text(str(ROOT / "fixtures" / "cpuinfo-avx2.txt")), "x86_64")
    arm, _ = cpu_state(None, "arm64")
    expect(vbmi == "vbmi", "VBMI cpuinfo should match")
    expect(avx2 == "absent", "AVX2-only cpuinfo should be absent")
    expect(arm == "absent", "ARM64 should be absent")

    vulnerable = classify_version("17.0.21")
    expect(decide(vulnerable, "vbmi", None) == "EXPOSED", "vulnerable + VBMI is exposed")
    expect(decide(vulnerable, "absent", None) == "VULNERABLE_BUILD", "vulnerable + no VBMI stays a bad build")
    expect(
        decide(vulnerable, "vbmi", workaround_from_text("-XX:-UseBASE64Intrinsics")) == "MITIGATED",
        "intrinsic flag should mitigate",
    )
    expect(workaround_from_text("-XX:UseAVX=2") is not None, "UseAVX=2 should count")
    expect(workaround_from_text("-XX:UseAVX=3") is None, "UseAVX=3 should not count")
    expect(
        workaround_from_text("-XX:-UseBASE64Intrinsics -XX:+UseBASE64Intrinsics") is None,
        "a later enable flag should win",
    )

    source = Path(__file__).read_text(encoding="utf-8")
    # Built at runtime so the repository never contains the instruction name.
    expect("evmov" + "dqub" not in source, "checker source must not carry the decoder instruction")
    expect("A" * 32 not in source, "checker source must not carry a trigger string")

    quiet = io.StringIO()
    with redirect_stdout(quiet):
        exposed = main(["audit", "--version", "17.0.21", "--cpu-flags", "avx512vbmi", "--no-color"])
        clear = main(["audit", "--version", "17.0.21.1", "--cpu-flags", "avx512vbmi", "--no-color"])
        held = main(["audit", "--version", "21.0.4", "--cpu-flags", "arm64", "--no-color"])
        fleet_code = main(["fleet", str(ROOT / "fixtures" / "fleet.csv"), "--no-color"])
        rules_code = main(["rules", "--out", str(ROOT / "fixtures" / "_rules")])
    expect(exposed == 2, f"audit of 17.0.21 on VBMI should exit 2, got {exposed}")
    expect(clear == 0, f"audit of 17.0.21.1 should exit 0, got {clear}")
    expect(held == 3, f"vulnerable build on ARM should exit 3, got {held}")
    expect(fleet_code == 2, f"fleet fixture should exit 2, got {fleet_code}")
    expect(rules_code == 0, "rules should write the interim env")
    snippet = ROOT / "fixtures" / "_rules" / "java4shell-interim.env"
    expect(snippet.is_file() and "UseBASE64Intrinsics" in snippet.read_text(encoding="utf-8"), "interim env missing")
    shutil.rmtree(ROOT / "fixtures" / "_rules", ignore_errors=True)

    if failures:
        print(f"{len(failures)} selftest failure(s):")
        for item in failures:
            print(f"  - {item}")
        return 1
    print(f"selftest passed ({len(cases)} versions, cpu, flags, fleet)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-color", action="store_true", help="Plain text, no ANSI color")
    parser = argparse.ArgumentParser(
        prog="java4shell_guard.py",
        description="Bluefire Redteam safe exposure check for Java4Shell (CVE-2026-114938).",
        parents=[common],
    )
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", parents=[common], help="Check a runtime version, CPU flags, and JVM flags")
    audit.add_argument("--version", help="Version string or a full java -version banner")
    audit.add_argument("--version-file", help="File containing java -version output")
    audit.add_argument("--java-bin", help="Path to a java binary. Runs java -version only.")
    audit.add_argument("--changelog", help="Package note. Naming CVE-2026-114938 marks a backport as patched.")
    audit.add_argument("--cpu-flags", help="Flag string, or one of: vbmi, none, arm64, unknown")
    audit.add_argument("--cpu-file", help="Saved /proc/cpuinfo. Used when --cpu-flags is omitted.")
    audit.add_argument("--jvm-flags", help="JVM command line or jcmd VM.flags output")
    audit.add_argument("--processes", action="store_true", help="Also read local java processes. Sends nothing to them.")
    audit.add_argument("--json", action="store_true")
    audit.set_defaults(func=cmd_audit)

    fleet = sub.add_parser("fleet", parents=[common], help="Check a CSV of name,version,cpu,workaround")
    fleet.add_argument("csv")
    fleet.add_argument("--json", action="store_true")
    fleet.set_defaults(func=cmd_fleet)

    report = sub.add_parser("report", parents=[common], help="Write a markdown exposure report")
    report.add_argument("--version")
    report.add_argument("--version-file")
    report.add_argument("--java-bin")
    report.add_argument("--changelog")
    report.add_argument("--cpu-flags")
    report.add_argument("--cpu-file")
    report.add_argument("--jvm-flags")
    report.add_argument("--processes", action="store_true")
    report.add_argument("--out")
    report.set_defaults(func=cmd_report)

    rules = sub.add_parser("rules", help="Write the temporary JAVA_TOOL_OPTIONS snippet")
    rules.add_argument("--out", default="rules")
    rules.set_defaults(func=cmd_rules)

    demo = sub.add_parser("demo", parents=[common], help="Show the bundled exposed fixture")
    demo.set_defaults(func=cmd_demo)

    test = sub.add_parser("selftest", help="Run the built-in checks")
    test.set_defaults(func=lambda _args: selftest())
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
