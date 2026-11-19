# Legal disclaimer

Last updated 19 November 2026.

Java4Shell Guard is published by Bluefire Redteam so an operator can compare a Java runtime, CPU flags, and JVM flags with the public vendor tables for CVE-2026-114938. Read this file before you rely on the tool or on any report it writes.

## Not legal, security, or vendor advice

The output is a technical comparison. It is not legal advice, not a compliance opinion, and not a statement from Oracle, CISA, Red Hat, or any other vendor. Decisions about patching, disclosure, customer notice, contracts, or regulatory deadlines are yours. When the decision matters, read the vendor advisory and get advice from your own counsel.

## A result is not proof

A "patched", "not affected", or exit code `0` is not proof that a host is safe. An "exposed" result or exit code `2` is not proof that a host was compromised, and it is not proof that an attacker can take it over. The tool does not inspect application code, and it does not check whether untrusted data reaches `Base64.getDecoder()` or `Base64.getUrlDecoder()`.

The version table can be wrong or out of date. A vendor can ship the fix under a version this tool still calls vulnerable. A banner dated 17 November 2026 can still be the October build. `java` on `PATH` can be a different binary from the one inside a service, a container, or an appliance. CPU flags describe the machine the command ran on, unless you pass other flags in. GraalVM Enterprise Edition is left for a person to confirm because Oracle's CVE record does not publish a fixed build number for that line.

## Authorized use

Run the tool only on systems, images, and process lists you are allowed to assess. You are responsible for that permission. Bluefire Redteam does not authorize use of this repository against systems you do not own or have written permission to test.

The tool reads versions and flags. It does not send exploit traffic. Do not add a payload, a crash input, or an attack step to it and then present the result as this project.

## Names and trademarks

Java, OpenJDK, Oracle, GraalVM, Corretto, Temurin, and the other product names belong to their owners. Naming them describes what the checker looks at. It does not mean those owners sponsor, review, or endorse this repository. "Java4Shell" is the public name used for CVE-2026-114938. Bluefire Redteam did not assign the CVE.

## No warranty and limit of liability

The software is provided as-is, without warranty of any kind, under the [MIT License](LICENSE). That includes the warranties of merchantability, fitness for a particular purpose, and non-infringement. Bluefire Redteam is not liable for any claim, damages, or other liability arising from the use of the software or from a decision made on the basis of a report, whether in contract, tort, or otherwise. The full license text controls if this summary and the license ever differ.

## Reports about the tool

To report a bug in the checker, use [SECURITY.md](SECURITY.md). To ask Bluefire Redteam to run the check, write to [contact@bluefire-redteam.com](mailto:contact@bluefire-redteam.com).
