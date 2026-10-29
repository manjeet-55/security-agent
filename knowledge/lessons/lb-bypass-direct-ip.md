---
id: lb-bypass-direct-ip
title: A server behind a load balancer may still answer on its own public IP
applies_to: [port_exposure, tls, http_header]
tags: [load-balancer, waf, direct-ip, exposure, firewall, aws]
added_by: seed
review: approved
reviewed_by: secagent-maintainers
reviewed_at: "2026-10-29"
---
When an instance sits behind a load balancer but keeps a public IP with ports 80/443 open to the internet, clients can reach it directly. That skips the load balancer's WAF rules, its TLS certificate (the instance may serve an expired or self-signed one) and any header or redirect policy set there.

If a host listed in project.yaml with `serves:` answers HTTP or HTTPS on its own address, report it as an exposure. The usual fix is a security group or firewall rule that only allows the load balancer to reach the instance on those ports. The side effect to state: health checks and any direct-IP monitoring must come from allowed sources.
