import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[3]


class UnboundContractTests(unittest.TestCase):
    def test_resolver_is_full_recursive_and_non_root(self):
        dockerfile = (ROOT / "deploy/docker/unbound/Dockerfile").read_text()
        config = (ROOT / "deploy/docker/unbound/unbound.conf").read_text()

        self.assertIn("FROM alpine:3.24", dockerfile)
        self.assertIn("USER unbound", dockerfile)
        self.assertIn("HEALTHCHECK", dockerfile)
        self.assertIn("drill -p 5353 @127.0.0.1 localhost. A", dockerfile)
        self.assertNotIn(". NS | grep", dockerfile)
        self.assertIn("interface: 0.0.0.0@5353", config)
        self.assertIn('auto-trust-anchor-file: "/var/lib/unbound/root.key"', config)
        self.assertNotIn("forward-zone:", config)
        self.assertNotIn("forward-addr:", config)

    def test_rspamd_uses_unbound_with_docker_fallback_only(self):
        options = (ROOT / "deploy/docker/rspamd/conf/local.d/options.inc").read_text()
        compose = (ROOT / "deploy/docker/docker-compose.yml").read_text()

        self.assertIn("master-slave:unbound:5353,127.0.0.11:53", options)
        self.assertIn("unbound:", compose)
        self.assertIn("condition: service_healthy", compose)
        self.assertIn("drill -p 5353 @127.0.0.1 localhost. A", compose)
        self.assertNotIn("unbound_data", compose)
        self.assertNotIn("unbound_data:/var/lib/unbound", compose)


if __name__ == "__main__":
    unittest.main()
