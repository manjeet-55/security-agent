---
id: unreachable-is-not-fixed
title: A timeout or refusal from the wrong network proves nothing
applies_to: [port_exposure, tls, http_header, http_redirect, exposed_path]
tags: [network, unverifiable, timeout, allowlist, firewall]
added_by: seed
review: approved
reviewed_by: secagent-maintainers
reviewed_at: "2026-10-29"
---
Many servers only accept connections from an office network, a VPN or a load balancer. A probe from anywhere else times out or is refused, which looks like "closed" or "fixed" but only shows that this network is not allowed in.

Treat a timeout, refusal or DNS failure as `unverifiable`, never as `fixed` or `pass`. Name the network the scan ran from (`scan_label`) and the networks the host should be reachable from (`reachable_from` in project.yaml), and ask the developer to re-run the scan from one of them.

A finding that was open stays open until a check from a network that can reach the target shows it fixed.
