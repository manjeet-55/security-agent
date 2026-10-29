---
id: stale-dns-records
title: Remove DNS records for services that no longer exist
applies_to: []
tags: [dns, subdomain, attack-surface, subdomain-takeover]
source_url: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover
added_by: seed
review: approved
reviewed_by: secagent-maintainers
reviewed_at: "2026-10-29"
---
External scanners enumerate a domain's DNS records and score every host they find. Old records (ftp, mail, staging and retired subdomains) add findings for services nobody maintains, and a record pointing at a released cloud resource can be taken over by whoever claims that resource next.

When a scanner reports a host that is not in project.yaml, ask the developer whether it is still in use. If not, propose removing the DNS record rather than hardening the service.
