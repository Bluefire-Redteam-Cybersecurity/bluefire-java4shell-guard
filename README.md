# Bluefire Redteam — Java4Shell Guard

Checker only. It compares a Java runtime, the CPU flags, and the JVM flags with the public vendor tables. It does not decode Base64, and it does not try the vulnerability.

Exposure check for **CVE-2026-114938**, called Java4Shell. The bug is an out-of-bounds write in OpenJDK's AVX-512 Base64 decoder. An application that passes untrusted data to `Base64.getDecoder()` or `Base64.getUrlDecoder()` can crash, and on some applications that write can be turned into code execution. Oracle scores it 8.1 (CVSS 3.1, high attack complexity). The reporter scores it 9.2 (CVSS 4.0). CISA asked organizations to patch on 17 November 2026, internet-facing systems first.

Bluefire Redteam is a global offensive security firm. We do red teaming, penetration testing, and AI security testing.

There is no single payload that works against every Java service. This tool does not try to build one. A result is a version and CPU decision.

| Line | Affected | Resolved |
|---|---|---|
| Java 17 | 17.0.6 through 17.0.21, including `17.0.21+build` and Oracle's `17.0.21.0.3` | 17.0.21.1 |
| Java 21 | every 21.0 build before 21.0.13.1 | 21.0.13.1 |
| Java 25 | every 25.0 build before 25.0.5.1 | 25.0.5.1 |
| Java 27 | every 27.0 build before 27.0.1.1 | 27.0.1.1 |
| Java 8 Enterprise Performance Pack | perf packs before 8u513-perf, including 8u511b33-perf | 8u513-perf |
| Java 22, 23, 24, 26 | same HotSpot generation, no November CPU | move to a patched 21, 25, or 27 |

Standard Java 8 and Java 11 are not in the affected set. Java 17.0.5 and earlier do not have the decoder that was added in 17.0.6 (January 2023). A fifth version component is a vendor build counter: Corretto `17.0.21.1.2` is the fixed upstream `17.0.21.1`.

The vulnerable code runs only on x86-64 CPUs that advertise AVX-512 VBMI (Intel Ice Lake and newer, AMD Zen 4 and newer). ARM64, and older x86-64, do not take that path. A bad build on ARM is still a bad build if the image is copied onto a VBMI host.

Oracle: <https://www.oracle.com/security-alerts/cspunov2026.html>
CISA: <https://www.cisa.gov/news-events/alerts/2026/11/17/critical-java-vulnerability-requires-immediate-patching>
Red Hat: <https://access.redhat.com/security/vulnerabilities/RHSB-2026-018>

## Show it

```bash
python3 java4shell_guard.py selftest
python3 java4shell_guard.py demo
python3 java4shell_guard.py audit --version 17.0.21 --cpu-flags avx512vbmi
python3 java4shell_guard.py fleet fixtures/fleet.csv
python3 java4shell_guard.py report --version 17.0.21 --cpu-flags avx512vbmi --out /tmp/java4shell-report.md
```

## Audit a host

```bash
python3 java4shell_guard.py audit
python3 java4shell_guard.py audit --java-bin /usr/lib/jvm/java-17/bin/java --processes
python3 java4shell_guard.py audit --version-file java-version.txt --cpu-file cpuinfo.txt
python3 java4shell_guard.py audit --version 17.0.20 --changelog /usr/share/doc/java-17-openjdk/changelog --cpu-flags none
```

`audit` with no arguments reads `java -version` from `PATH` and the CPU flags of the machine it runs on. `--processes` also asks local `java` processes for `VM.version` and `VM.flags` through `jcmd`, when the same user is allowed to. It does not send anything to the application.

`--changelog` marks the build patched only when the file names `CVE-2026-114938`. A banner dated 17 November 2026 that still says `17.0.21` is not called patched. Temurin `17.0.21+9` is the October build.

Exit codes: `0` patched or not affected, `2` vulnerable build on a VBMI CPU with no workaround, `3` needs a human (bad build on a CPU that cannot run the path, workaround in place, or version unclear), `1` usage error.

## Temporary flag

Oracle's advisory publishes no workaround. Researchers report that this keeps the JVM off the affected decoder until the restart:

```bash
python3 java4shell_guard.py rules --out rules
```

That writes `rules/java4shell-interim.env`:

```
JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics
```

On x86-64, `-XX:UseAVX=2` is the other reported switch. Do not put `UseAVX` on an ARM64 JVM. Those builds do not recognize the flag and will not start. Neither flag replaces the patch. Restart is required either way.

## What a client still has to do

1. Install the vendor build at or above the floor in the table. Corretto shipped fixed 17, 21, 25, and 27 builds on 17 November 2026. Other distributions publish on their own schedule.
2. Restart every JVM, including runtimes bundled in containers and appliances. Rebuild the image after the base image moves.
3. Confirm the process, not the shell on `PATH`, with `jcmd <pid> VM.version`.
4. Remove the temporary flag after the patched process is up.

GraalVM Enterprise Edition `21.3.20.0.3` is in Oracle's CVE record. Oracle did not publish a fixed build number for that line in the record, so this tool leaves it as a review item.

## See also

Other Bluefire Redteam checkers:

- [PHP2Shell Guard](https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-php2shell-guard) — CVE-2026-109618 and CVE-2026-109619
- [Ivanti Connect Secure check](https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-ivanti-ics-guard) — CVE-2026-104935
- [SharePoint CVE-2025-53770 toolkit](https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-sharepoint-cve-2025-53770)
- [Nx s1ngularity check](https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-nx-s1ngularity-check)

## Disclaimer

This repository is a checker. It reads a version you supply, the output of `java -version`, CPU flags, and JVM flags. It does not send exploit traffic and it does not test whether Base64 decoding can crash a process. A result is not proof that a host was compromised, and it is not proof that a host is safe.

Use it only on systems you are authorized to assess. The report is not legal advice and it does not replace the Oracle, CISA, or Red Hat advisory. The software is provided as-is, without warranty, under the [MIT License](LICENSE).

## Work with Bluefire Redteam

To run this across a Java estate, start at [bluefire-redteam.com](https://bluefire-redteam.com) or write to [contact@bluefire-redteam.com](mailto:contact@bluefire-redteam.com).
