# Chapter 10 — CWE-918: Server-Side Request Forgery (SSRF)

**Time budget:** ~45 min · **CWE:** CWE-918 · **Files:** `src/Vulnerable/Shop.Api/Controllers/AvatarController.cs` ↔ `src/Fixed/Shop.Api/Controllers/AvatarController.cs` · test `tests/Shop.Tests/SsrfTests.cs`

## The weakness in one line

The avatar import endpoint passes a user-supplied URL directly to `HttpClient.GetStringAsync`, letting the server make HTTP requests to any destination the attacker names — including internal services that the server can reach but the internet cannot.

## Live demo script

1. Open the Vulnerable `AvatarController`. Read the `// CWE-918` comment aloud — note `new HttpClient().GetStringAsync(req.Url)` with no validation of any kind.
2. Explain the test setup: `SsrfTests.Vulnerable_import_reaches_internal_service` starts a real `HttpListener` on a random loopback port serving the string `"INTERNAL-SECRET-DATA"`. From the test's perspective this stands in for a cloud metadata endpoint or an internal microservice.
3. The test POSTs `{"url":"http://127.0.0.1:<port>/"}` to the vulnerable endpoint → the server fetches the internal listener → the response body contains `"INTERNAL-SECRET-DATA"`. The client's original HTTP request just received data from a service it could never directly reach.
4. Open the Fixed `AvatarController` side-by-side. Walk through the three checks in order: (a) `Uri.TryCreate` — rejects unparseable input; (b) scheme whitelist (`http` or `https` only — blocks `file://`, `dict://`, `gopher://` etc.); (c) `uri.IsLoopback || !uri.Host.EndsWith(".example.com")` — blocks loopback addresses and any host not on the allow-list.
5. Send the same loopback URL to the fixed endpoint → 400 Bad Request, no connection attempted. Send `http://evil.com/payload` → 400 Bad Request (not on allow-list).
6. Run `dotnet test --filter FullyQualifiedName~SsrfTests` → green.

## Why it's exploitable (the mechanism)

The server has network access the external caller does not: it can reach loopback, RFC-1918 private ranges, cloud instance metadata services (e.g., `http://169.254.169.254/latest/meta-data/` on AWS), and internal DNS names. Because the request originates from the server's identity, it may bypass firewall rules, carry instance credentials, or enumerate internal topology. SSRF is a perennial OWASP API Top 10 entry because the pattern — "fetch this URL for me" — is extremely common in avatar imports, link previews, webhook verification, and PDF rendering.

## The fix (and why it's usually less code)

Replace the unchecked fetch with a three-step allow-list gate: parse the URL, assert the scheme is `http` or `https`, and assert the host matches a known-good suffix (here `.example.com`). Reject loopback and private-IP ranges. The allow-list approach is strictly safer than a block-list because any block-list has edge cases (IPv6 representations, DNS aliases, hex-encoded IPs), whereas an allow-list fails closed: anything not explicitly permitted is denied.

## The transferable principle

> **Allow-list outbound destinations; never let input pick where the server connects.**

## "But what about…" — anticipated questions

- **Q:** What are cloud metadata endpoints and why are they especially dangerous? **A:** AWS, Azure, and GCP expose an HTTP endpoint at `169.254.169.254` (and newer IMDSv2/v6 variants) that returns the instance's IAM credentials, region, VPC details, and user-data scripts. No authentication is required from inside the VM. An SSRF that can reach this address can exfiltrate temporary credentials with full production IAM permissions in a single request. This is how several major cloud breaches have occurred.
- **Q:** Why is an allow-list better than blocking known-bad addresses? **A:** A block-list must enumerate every dangerous address class: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `::1`, `fc00::/7`, and many more. Attackers bypass block-lists with decimal-encoded IPs (`2130706433` for `127.0.0.1`), URL shorteners, or DNS rebinding. An allow-list that only permits `.example.com` automatically rejects everything else, including future threat vectors you have not thought of yet.
- **Q:** What is DNS rebinding and does the fixed code fully prevent it? **A:** DNS rebinding is a technique where the attacker controls a DNS name that initially resolves to a permitted IP but then resolves to an internal IP after the allow-list check passes. The teaching allow-list in this demo checks the host name, not the resolved IP, so a real implementation should also resolve the name and validate the resulting IP against a private-range block-list, or use a DNS-pinning proxy. The demo allow-list illustrates the principle; production hardening requires the additional IP validation step.
