---
id: distro-backport-false-positive
title: Distro backports make version-banner CVE claims unreliable
applies_to: [host_package]
tags: [openssh, nginx, openssl, ubuntu, debian, scanner-false-positive, backport]
source_url: https://www.debian.org/security/faq
added_by: seed
review: approved
reviewed_by: secagent-maintainers
reviewed_at: "2026-10-29"
---
Ubuntu and Debian fix security bugs in a stable release by backporting the patch, without moving to the newer upstream version. A server can run `OpenSSH_9.6p1` and still have the fix for a CVE that upstream fixed in 9.8.

External scanners often judge by the version banner and report such a host as vulnerable. Judge by the full distro package version (`1:9.6p1-3ubuntu13.3`) against the fixed version in the distro's own advisory instead: call `verify_claim({host, cve})`. A `fixed_in_installed` or `not_affected` verdict is the evidence for marking the scanner claim `false_positive`.

This only holds for packages installed from the distro's own repositories. A package from a third-party repository (nginx.org, a vendor repo, a PPA) follows that vendor's versions, and distro advisories say nothing about it.
