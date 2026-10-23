# Security notes

This project intentionally does **not** fetch a submitted URL unless the user selects **Run live checks**.

When live checking is enabled, URL hosts must resolve to globally routable IPs and are contacted using a connection pinned to the verified public IP; redirects are revalidated. Only HTTP and HTTPS on default ports are accepted. HTML is capped at 512 KB and redirects at three. The app will not submit passwords or fill forms.

TLS, RDAP and HTML operations share a **12-second monotonic network budget**
per analysis, with socket operations capped at the smaller of four seconds and
the remaining budget. Reader-level checks include slow headers, chunk framing
and body bytes. DNS caller waits use the same budget; at most four daemon resolver
workers can remain in progress per process. An OS resolver call cannot be forcibly
cancelled; exhausted resolver capacity fails closed rather than queuing more work.
This is not a hard CPU/scheduling limit or a deployment-wide request-rate limit.

Mixed public/private DNS answers, multicast, reserved, mapped/transition and
known NAT64 translation addresses are rejected. Connections use numeric validated
IPs while retaining the hostname for TLS verification and the HTTP Host header.
Every HTML redirect is revalidated; HTTPS-to-HTTP downgrades are rejected. Only
successful, identity-encoded responses of the expected media type are accepted.
Decoded bodies are capped at 512,000 bytes for HTML and 128,000 bytes for RDAP;
per-hop wire reads are additionally capped at the body budget plus 64,000 bytes
for headers/framing. Unsupported/ambiguous framing and truncated declared bodies
fail closed. Connections and response readers close on success and failure.

RDAP contacts **only pinned HTTPS `rdap.org`** and follows no redirects. Registry
redirects therefore produce unavailable age evidence; broader RDAP support needs
a separately reviewed destination/bootstrap policy. The transport uses direct
sockets, not implicit proxy settings, cookies or application credentials. A
deployment requiring an egress proxy must provide an explicitly reviewed transport
integration rather than disabling pinning or TLS verification.

TLS verification failures, timeouts, unavailable RDAP and failed HTML retrieval
are missing evidence. They do not add risk points by themselves. This changes
the former 15-point TLS-unavailability heuristic; ML scores and thresholds are
unchanged. Passive URL signals such as missing HTTPS remain separate heuristics.

The network tests use fake DNS, sockets, TLS contexts, responses and clocks;
they do not visit submitted or feed URLs or establish safety against every
network/platform configuration. See [current project status](docs/PROJECT_STATUS.md).

**Limitations:** These application-level checks are defense-in-depth, not a substitute for a network egress firewall, rate limits or service isolation. Do not run this unmodified in a privileged corporate/private network. Hosting providers may require additional protections and abuse prevention.

- Never commit `.env`, credentials, private datasets, or model artifacts downloaded from untrusted sources.
- Load `.pkl` / `joblib` model files only from your own trusted training process; unpickling arbitrary files is unsafe.
- Keep dependencies updated and review new supply-chain advisories.
- Do not assume low heuristic risk means that a website is safe.

Security reports: please open a GitHub issue **without** including a live exploit URL, credentials, or private data. Share sensitive details through a private channel.
