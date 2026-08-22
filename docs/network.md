# Network and proxy policy

Veilweave has one application-wide `NetworkManager`. Cloudflare APIs,
diagnostics, update metadata, and update packages all use an immutable snapshot
of the active policy. Saving settings builds generation N+1 and atomically
swaps it in; existing requests may finish on N and new requests use N+1.

Modes are Direct, System Proxy, SOCKS5, and HTTP/HTTPS Proxy. Direct disables
environment interception. System follows the platform/reqwest behavior. An
explicit proxy disables system rules and installs exactly one all-destinations
proxy rule, optionally with a NO_PROXY-style bypass list.

SOCKS5 defaults to proxy-side DNS (`socks5h`) to avoid local DNS leakage. Turn
off “Resolve DNS through proxy” only when local DNS (`socks5`) is intentional.
Explicit proxies fail closed: an unreachable proxy is an error and traffic is
not retried directly. Cloudflare and GitHub are never bypassed automatically.

Proxy passwords are stored in the OS credential store. The TOML and WebView
contain only host, port, username, and a non-secret reference; diagnostics and
Debug output show `host:port` only.

CLI precedence is:

1. `--proxy`
2. saved Veilweave network configuration
3. `ALL_PROXY`, only when `VEILWEAVE_USE_ENV_PROXY=1`
4. the selected System or Direct mode

Examples:

```text
veilweave-tools config network --mode socks5 --host 127.0.0.1 --port 10808
veilweave-tools proxy test
veilweave-tools apply --config veilweave.toml --proxy socks5h://127.0.0.1:10808
```

The connection test reports proxy TCP reachability, HTTPS/TLS, the Cloudflare
API, and the GitHub updater endpoint separately. HTTP 4xx authentication
responses prove transport reachability and do not require a Cloudflare token.
