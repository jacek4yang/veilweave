import base64
import json
import tempfile
import unittest
from pathlib import Path

from scripts import verify_subscription


VALID_URI = (
    "vless://01234567-a4cb-660a-881b-b275d397065b@relay.example.com:443"
    "?encryption=none&security=tls&type=ws&host=relay.example.com&path=%2Fedge"
    "&sni=relay.example.com&fp=chrome&alpn=http%2F1.1&insecure=0&allowInsecure=0#JP-01"
)


class VerifySubscriptionTests(unittest.TestCase):
    def test_raw_base64_headers_and_xray_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "raw.txt"
            encoded = root / "base64.txt"
            headers = root / "headers.txt"
            config = root / "xray.json"
            raw.write_text(VALID_URI, encoding="utf-8")
            encoded.write_bytes(base64.b64encode(VALID_URI.encode()))
            headers.write_text(
                "Content-Type: text/plain; charset=utf-8\n"
                "Cache-Control: private, no-store\n"
                "X-Veilweave-Format: raw\n"
                "X-Node-Count: 1\n"
                "Profile-Update-Interval: 6\n"
                "X-ProxyIP-Revision: revision\n",
                encoding="ascii",
            )

            raw_nodes = verify_subscription.parse_nodes(
                verify_subscription.decode_body(raw, "raw")
            )
            encoded_nodes = verify_subscription.parse_nodes(
                verify_subscription.decode_body(encoded, "base64")
            )
            self.assertEqual(raw_nodes, encoded_nodes)
            verify_subscription.verify_headers(headers, "raw", 1)
            verify_subscription.write_xray_config(raw_nodes[0], config, 18080)
            rendered = json.loads(config.read_text(encoding="utf-8"))
            self.assertEqual(rendered["inbounds"][0]["port"], 18080)
            self.assertFalse(
                rendered["outbounds"][0]["streamSettings"]["tlsSettings"][
                    "allowInsecure"
                ]
            )

    def test_zero_uuid_and_wrong_header_count_are_rejected(self):
        zero = VALID_URI.replace(
            "01234567-a4cb-660a-881b-b275d397065b",
            "00000000-0000-0000-0000-000000000000",
        )
        with self.assertRaisesRegex(ValueError, "zero UUID"):
            verify_subscription.parse_nodes(zero)

        with tempfile.TemporaryDirectory() as directory:
            headers = Path(directory) / "headers.txt"
            headers.write_text(
                "Content-Type: text/plain\n"
                "Cache-Control: private, no-store\n"
                "X-Veilweave-Format: raw\n"
                "X-Node-Count: 2\n"
                "Profile-Update-Interval: 6\n"
                "X-ProxyIP-Revision: revision\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(ValueError, "X-Node-Count"):
                verify_subscription.verify_headers(headers, "raw", 1)


if __name__ == "__main__":
    unittest.main()
