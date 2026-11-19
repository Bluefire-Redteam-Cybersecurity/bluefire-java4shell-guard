# Security policy

Java4Shell Guard is a checker. It compares a Java version, CPU flags, and JVM flags. It does not send a payload.

## Report a bug in this repository

Write to [contact@bluefire-redteam.com](mailto:contact@bluefire-redteam.com). Put "Java4Shell Guard" in the subject.

Say which file and version you tested, what you expected, and what happened. A commit hash or a link to the line is enough.

Please do not open a public GitHub issue for a vulnerability in this tool until we have replied. Give us a reasonable window to look at it before you publish details.

## In scope

- `java4shell_guard.py` and the files in this repository
- A check that mislabels a patched build as vulnerable, or a vulnerable build as patched
- Unexpected execution of a command other than `java -version`, `jcmd VM.version`, `jcmd VM.flags`, `ps`, or reading CPU flags
- A result that leaks data from a host the operator did not point the tool at

## Out of scope

- CVE-2026-114938 itself. Report that to the Java vendor. Oracle's advisory is <https://www.oracle.com/security-alerts/cspunov2026.html>.
- Vulnerabilities in Java applications, containers, or appliances the checker only reads a version from.
- Requests to add a crash test, a Base64 payload, or a proof of exploit. This repository will not ship those.

## Supported versions

| Version | Supported |
|---|---|
| `main` at <https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-java4shell-guard> | Yes |

There are no older release branches.

## What you can expect

We will acknowledge a report sent to the address above. If the report is in scope, we will fix it on `main` and credit you if you want to be named. The tool is provided as-is under the [MIT License](LICENSE). A report is not a support contract.
