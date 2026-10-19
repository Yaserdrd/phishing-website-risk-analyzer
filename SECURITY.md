# Security notes

This project intentionally does **not** fetch a submitted URL unless the user selects **Run live checks**.

When live checking is enabled, URL hosts must resolve to globally routable IPs and are contacted using a connection pinned to the verified public IP; redirects are revalidated. Only HTTP and HTTPS on default ports are accepted. HTML is capped at 512 KB and redirects at three. The app will not submit passwords or fill forms.

**Limitations:** These application-level checks are defense-in-depth, not a substitute for a network egress firewall, rate limits or service isolation. Do not run this unmodified in a privileged corporate/private network. Hosting providers may require additional protections and abuse prevention.

- Never commit `.env`, credentials, private datasets, or model artifacts downloaded from untrusted sources.
- Load `.pkl` / `joblib` model files only from your own trusted training process; unpickling arbitrary files is unsafe.
- Keep dependencies updated and review new supply-chain advisories.
- Do not assume low heuristic risk means that a website is safe.

Security reports: please open a GitHub issue **without** including a live exploit URL, credentials, or private data. Share sensitive details through a private channel.
