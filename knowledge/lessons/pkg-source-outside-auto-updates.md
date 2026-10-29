---
id: pkg-source-outside-auto-updates
title: Third-party repository packages are not covered by automatic security updates
applies_to: [host_package, host_config]
tags: [unattended-upgrades, apt, third-party, nginx, docker, patching]
source_url: https://wiki.debian.org/UnattendedUpgrades
added_by: seed
review: approved
reviewed_by: secagent-maintainers
reviewed_at: "2026-10-29"
---
`unattended-upgrades` installs updates only from the origins it is configured for, which by default is the distro's security pocket. Packages from other repositories (nginx.org, Docker, database vendors, PPAs) are not upgraded automatically, even when auto-updates are on.

When a host has auto-updates enabled and also runs third-party packages, say both: the distro packages are patched automatically, and each third-party package needs its own update process (add its origin to `Unattended-Upgrade::Origins-Pattern`, or a scheduled manual update). Check the vendor's advisories for those packages; distro advisories do not cover them.
