---
id: header-budget-proxy-buffer
title: Adding response headers can break auth responses behind nginx
applies_to: [header_budget, http_header, http_cookie]
tags: [nginx, proxy_buffer_size, headers, "502", csp, cookies]
source_url: https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_buffer_size
added_by: seed
review: approved
reviewed_by: secagent-maintainers
reviewed_at: "2026-10-29"
---
nginx reads the upstream response headers into a buffer of `proxy_buffer_size`, which defaults to one memory page (4 KB or 8 KB). If the headers do not fit, nginx returns 502 Bad Gateway. Login and session responses are the largest: they carry several `Set-Cookie` headers, and security headers such as a long `Content-Security-Policy` add to them.

Before proposing new or longer headers, measure the remaining margin with the `header_budget` check and state it as a side effect of the fix. If the margin is small, raise `proxy_buffer_size` (and `proxy_buffers`) in the same change, and re-test the login flow after deploying.
