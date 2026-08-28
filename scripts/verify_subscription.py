#!/usr/bin/env python3
"""Strictly inspect a Veilweave URI-list and optionally write an Xray config.

The script deliberately never prints a URI, UUID, token, or generated config.
It is used by the protected Cloudflare E2E workflow, where those values are
short-lived credentials.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import ipaddress
import json
import re
import sys
import uuid
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit


HOST_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$"
)


def fail(message: str) -> "NoReturn":
    raise ValueError(message)


def one(query: dict[str, list[str]], name: str, *, required: bool = True) -> str | None:
    values = query.get(name, [])
    if not values:
        if required:
            fail(f"node is missing {name!r}")
        return None
    if len(values) != 1 or not values[0]:
        fail(f"node has an invalid {name!r} value")
    return values[0]


def valid_host(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(HOST_RE.fullmatch(value))


def decode_body(path: Path, output_format: str) -> str:
    body = path.read_bytes()
    if not body:
        fail("subscription body is empty")
    if output_format == "base64":
        try:
            body = base64.b64decode(body, validate=True)
        except (ValueError, binascii.Error) as error:
            fail(f"subscription is not strict standard Base64: {error}")
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"subscription is not UTF-8: {error}")


def parse_headers(path: Path) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw_line in path.read_text(encoding="iso-8859-1").splitlines():
        if ":" not in raw_line:
            continue
        name, value = raw_line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return headers


def parse_nodes(raw: str) -> list[dict[str, object]]:
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if not lines:
        fail("subscription contains zero nodes")
    nodes: list[dict[str, object]] = []
    for line in lines:
        parsed = urlsplit(line)
        if parsed.scheme != "vless" or parsed.password is not None:
            fail("subscription contains a non-VLESS or password-bearing URI")
        try:
            node_id = uuid.UUID(parsed.username or "")
        except ValueError as error:
            fail(f"subscription contains an invalid UUID: {error}")
        if node_id.int == 0:
            fail("subscription contains the zero UUID")
        try:
            port = parsed.port
        except ValueError as error:
            fail(f"subscription contains an invalid port: {error}")
        if not parsed.hostname or not valid_host(parsed.hostname) or not port:
            fail("subscription contains an invalid entry endpoint")

        query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
        if one(query, "type") != "ws":
            fail("node transport is not WebSocket")
        if one(query, "encryption") != "none":
            fail("protected E2E expects the production-compatible plaintext VLESS mode")
        relay_host = one(query, "host")
        path = one(query, "path")
        security = one(query, "security")
        if not relay_host or not valid_host(relay_host):
            fail("node has an invalid WebSocket Host")
        if not path or not path.startswith("/"):
            fail("node has an invalid WebSocket path")
        if security not in ("tls", "none"):
            fail("node security is neither tls nor none")
        if security == "tls":
            sni = one(query, "sni")
            if sni != relay_host:
                fail("node TLS SNI does not match the relay hostname")
            if one(query, "insecure") != "0" or one(query, "allowInsecure") != "0":
                fail("node does not explicitly require certificate validation")
            if port != 443:
                fail("secure node does not use port 443")
        else:
            if port != 80:
                fail("insecure node does not use port 80")
            sni = None
        label = unquote(parsed.fragment)
        country = label.split("-", 1)[0]
        if not re.fullmatch(r"[A-Z]{2}", country):
            fail("node label does not start with a normalized country code")
        nodes.append(
            {
                "address": parsed.hostname,
                "port": port,
                "id": str(node_id),
                "relay_host": relay_host,
                "path": path,
                "security": security,
                "sni": sni,
                "fingerprint": one(query, "fp", required=False),
                "alpn": one(query, "alpn", required=False),
                "country": country,
            }
        )
    return nodes


def verify_headers(path: Path, output_format: str, node_count: int) -> None:
    headers = parse_headers(path)
    if not headers.get("content-type", "").lower().startswith("text/plain"):
        fail("subscription Content-Type is not text/plain")
    if headers.get("cache-control", "").lower() != "private, no-store":
        fail("subscription Cache-Control is not private, no-store")
    if headers.get("x-veilweave-format") != output_format:
        fail("X-Veilweave-Format does not match the requested format")
    if headers.get("x-node-count") != str(node_count):
        fail("X-Node-Count does not match the parsed node count")
    if headers.get("profile-update-interval") != "6":
        fail("Profile-Update-Interval is not 6")
    if not headers.get("x-proxyip-revision"):
        fail("X-ProxyIP-Revision is missing")


def write_xray_config(node: dict[str, object], output: Path, socks_port: int) -> None:
    stream: dict[str, object] = {
        "network": "ws",
        "security": node["security"],
        "wsSettings": {
            "path": node["path"],
            "headers": {"Host": node["relay_host"]},
        },
    }
    if node["security"] == "tls":
        tls: dict[str, object] = {
            "serverName": node["sni"],
            "allowInsecure": False,
        }
        if node["fingerprint"]:
            tls["fingerprint"] = node["fingerprint"]
        if node["alpn"]:
            tls["alpn"] = [part for part in str(node["alpn"]).split(",") if part]
        stream["tlsSettings"] = tls
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": node["address"],
                            "port": node["port"],
                            "users": [{"id": node["id"], "encryption": "none"}],
                        }
                    ]
                },
                "streamSettings": stream,
            }
        ],
    }
    output.write_text(json.dumps(config, separators=(",", ":")), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--format", choices=("raw", "base64"), required=True)
    parser.add_argument("--headers", type=Path)
    parser.add_argument("--expect-security", choices=("tls", "none"))
    parser.add_argument("--expect-countries", help="comma-separated allowed countries")
    parser.add_argument("--write-xray", type=Path)
    parser.add_argument("--node-index", type=int, default=0)
    parser.add_argument("--socks-port", type=int, default=10808)
    args = parser.parse_args()

    nodes = parse_nodes(decode_body(args.input, args.format))
    if args.headers:
        verify_headers(args.headers, args.format, len(nodes))
    if args.expect_security and any(node["security"] != args.expect_security for node in nodes):
        fail("subscription contains a node with the wrong security mode")
    countries = {str(node["country"]) for node in nodes}
    if args.expect_countries:
        expected = {part for part in args.expect_countries.split(",") if part}
        if not countries or not countries.issubset(expected):
            fail("subscription contains a country outside the requested selection")
        if len(expected) > 1 and countries != expected:
            fail("multi-country subscription did not represent every requested country")
    if args.write_xray:
        if not (0 <= args.node_index < len(nodes)):
            fail("requested Xray node index is out of range")
        if not (1 <= args.socks_port <= 65535):
            fail("SOCKS port is invalid")
        write_xray_config(nodes[args.node_index], args.write_xray, args.socks_port)
    print(f"verified_nodes={len(nodes)} security={args.expect_security or 'mixed'} countries={','.join(sorted(countries))}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print(f"subscription verification failed: {error}", file=sys.stderr)
        sys.exit(1)
