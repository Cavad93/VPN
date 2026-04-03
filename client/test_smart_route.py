"""Tests for smart_route.py — domain-based selective routing."""

import ipaddress
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch, MagicMock

from smart_route import (
    SmartRouter,
    SmartRouteConfig,
    SmartRouteStats,
    RouteMode,
    _BlocklistManager,
    _DNSCache,
    _RouteInstaller,
    _is_ip_or_cidr,
    _get_default_gateway,
    DEFAULT_BLOCKED_DOMAINS,
    ALWAYS_DIRECT_DOMAINS,
    create_smart_router,
)


# ---------------------------------------------------------------------------
# Helper: stub route commands (no real root needed)
# ---------------------------------------------------------------------------

def _mock_route_cmd(self, action, args, check=True):
    """Always succeed without actually running route commands."""
    return True


# ---------------------------------------------------------------------------
# Tests: _is_ip_or_cidr
# ---------------------------------------------------------------------------

class TestIsIpOrCidr(unittest.TestCase):
    def test_ipv4(self):
        self.assertTrue(_is_ip_or_cidr("1.2.3.4"))

    def test_cidr(self):
        self.assertTrue(_is_ip_or_cidr("10.0.0.0/8"))

    def test_domain(self):
        self.assertFalse(_is_ip_or_cidr("google.com"))

    def test_empty(self):
        self.assertFalse(_is_ip_or_cidr(""))

    def test_invalid(self):
        self.assertFalse(_is_ip_or_cidr("not-an-ip"))


# ---------------------------------------------------------------------------
# Tests: _DNSCache
# ---------------------------------------------------------------------------

class TestDNSCache(unittest.TestCase):
    def test_resolve_localhost(self):
        cache = _DNSCache(ttl=60)
        ips = cache.resolve("localhost")
        self.assertIn("127.0.0.1", ips)

    def test_cache_hit(self):
        cache = _DNSCache(ttl=60)
        ips1 = cache.resolve("localhost")
        ips2 = cache.resolve("localhost")
        self.assertEqual(ips1, ips2)

    def test_cache_expired(self):
        cache = _DNSCache(ttl=0.01)  # 10ms TTL
        cache.resolve("localhost")
        time.sleep(0.02)
        # Should re-resolve (cache expired).
        ips = cache.resolve("localhost")
        self.assertIn("127.0.0.1", ips)

    def test_resolve_nonexistent_domain(self):
        cache = _DNSCache(ttl=60)
        ips = cache.resolve("this.domain.does.not.exist.xyz123abc")
        self.assertEqual(ips, set())
        self.assertGreater(cache.error_count, 0)

    def test_clear(self):
        cache = _DNSCache(ttl=60)
        cache.resolve("localhost")
        cache.clear()
        self.assertEqual(cache.error_count, 0)

    def test_resolve_many(self):
        cache = _DNSCache(ttl=60)
        results = cache.resolve_many(["localhost", "localhost"])
        self.assertIn("localhost", results)
        self.assertIn("127.0.0.1", results["localhost"])

    def test_resolve_many_with_cache(self):
        cache = _DNSCache(ttl=60)
        cache.resolve("localhost")
        # Second call should hit cache.
        results = cache.resolve_many(["localhost"])
        self.assertIn("127.0.0.1", results["localhost"])


# ---------------------------------------------------------------------------
# Tests: _BlocklistManager
# ---------------------------------------------------------------------------

class TestBlocklistManager(unittest.TestCase):
    def test_load_default_blocklist(self):
        config = SmartRouteConfig(use_default_blocklist=True)
        mgr = _BlocklistManager(config)
        mgr.load()
        self.assertGreater(len(mgr.blocked_domains), 0)
        self.assertIn("youtube.com", mgr.blocked_domains)

    def test_load_without_default(self):
        config = SmartRouteConfig(
            use_default_blocklist=False,
            custom_domains=["example.com"],
        )
        mgr = _BlocklistManager(config)
        mgr.load()
        self.assertEqual(mgr.blocked_domains, {"example.com"})

    def test_direct_domains_excluded(self):
        config = SmartRouteConfig(
            use_default_blocklist=False,
            custom_domains=["yandex.ru"],  # yandex is in ALWAYS_DIRECT
        )
        mgr = _BlocklistManager(config)
        mgr.load()
        # yandex.ru should be removed from blocked (it's in ALWAYS_DIRECT).
        self.assertNotIn("yandex.ru", mgr.blocked_domains)
        self.assertIn("yandex.ru", mgr.direct_domains)

    def test_custom_always_direct(self):
        config = SmartRouteConfig(
            use_default_blocklist=False,
            custom_domains=["mysite.com"],
            always_direct=["mysite.com"],
        )
        mgr = _BlocklistManager(config)
        mgr.load()
        self.assertNotIn("mysite.com", mgr.blocked_domains)

    def test_is_blocked_direct_check(self):
        config = SmartRouteConfig(
            use_default_blocklist=False,
            custom_domains=["example.com"],
        )
        mgr = _BlocklistManager(config)
        mgr.load()
        self.assertTrue(mgr.is_blocked("example.com"))
        self.assertFalse(mgr.is_blocked("yandex.ru"))

    def test_is_blocked_subdomain(self):
        config = SmartRouteConfig(
            use_default_blocklist=False,
            custom_domains=["example.com"],
        )
        mgr = _BlocklistManager(config)
        mgr.load()
        self.assertTrue(mgr.is_blocked("sub.example.com"))
        self.assertTrue(mgr.is_blocked("deep.sub.example.com"))

    def test_add_remove_domain(self):
        config = SmartRouteConfig(use_default_blocklist=False)
        mgr = _BlocklistManager(config)
        mgr.load()
        self.assertFalse(mgr.is_blocked("newsite.com"))
        mgr.add_domain("newsite.com")
        self.assertTrue(mgr.is_blocked("newsite.com"))
        mgr.remove_domain("newsite.com")
        self.assertFalse(mgr.is_blocked("newsite.com"))

    def test_load_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# Comment\n")
            f.write("blocked1.com\n")
            f.write("blocked2.org\n")
            f.write("1.2.3.4\n")
            f.write("10.0.0.0/8\n")
            f.write("\n")
            path = f.name

        try:
            config = SmartRouteConfig(
                use_default_blocklist=False,
                blocklist_file=path,
            )
            mgr = _BlocklistManager(config)
            mgr.load()
            self.assertIn("blocked1.com", mgr.blocked_domains)
            self.assertIn("blocked2.org", mgr.blocked_domains)
            self.assertIn("1.2.3.4", mgr.blocked_ips)
            self.assertIn("10.0.0.0/8", mgr.blocked_ips)
        finally:
            os.unlink(path)

    def test_load_file_nonexistent(self):
        config = SmartRouteConfig(
            use_default_blocklist=False,
            blocklist_file="/tmp/nonexistent_blocklist_xyz.txt",
        )
        mgr = _BlocklistManager(config)
        mgr.load()  # Should not raise.
        self.assertEqual(len(mgr.blocked_domains), 0)

    def test_last_updated(self):
        config = SmartRouteConfig(use_default_blocklist=True)
        mgr = _BlocklistManager(config)
        self.assertEqual(mgr.last_updated, "")
        mgr.load()
        self.assertNotEqual(mgr.last_updated, "")


# ---------------------------------------------------------------------------
# Tests: _RouteInstaller (mocked)
# ---------------------------------------------------------------------------

class TestRouteInstaller(unittest.TestCase):
    @patch.object(_RouteInstaller, "_route_cmd", _mock_route_cmd)
    def test_add_vpn_route(self):
        ri = _RouteInstaller("10.8.0.1", "utun5", "192.168.1.1", "en0")
        self.assertTrue(ri.add_vpn_route("1.2.3.4"))
        self.assertEqual(ri.route_count, 1)

    @patch.object(_RouteInstaller, "_route_cmd", _mock_route_cmd)
    def test_add_duplicate_route(self):
        ri = _RouteInstaller("10.8.0.1", "utun5", "192.168.1.1", "en0")
        ri.add_vpn_route("1.2.3.4")
        ri.add_vpn_route("1.2.3.4")  # Should be idempotent.
        self.assertEqual(ri.route_count, 1)

    @patch.object(_RouteInstaller, "_route_cmd", _mock_route_cmd)
    def test_add_vpn_subnet(self):
        ri = _RouteInstaller("10.8.0.1", "utun5", "192.168.1.1", "en0")
        self.assertTrue(ri.add_vpn_subnet("100.0.0.0/8"))
        self.assertEqual(ri.route_count, 1)

    @patch.object(_RouteInstaller, "_route_cmd", _mock_route_cmd)
    def test_remove_all(self):
        ri = _RouteInstaller("10.8.0.1", "utun5", "192.168.1.1", "en0")
        ri.add_vpn_route("1.2.3.4")
        ri.add_vpn_route("5.6.7.8")
        ri.add_vpn_subnet("100.0.0.0/8")
        count = ri.remove_all()
        self.assertEqual(count, 3)
        self.assertEqual(ri.route_count, 0)


# ---------------------------------------------------------------------------
# Tests: SmartRouter
# ---------------------------------------------------------------------------

class TestSmartRouter(unittest.TestCase):
    def _make_router(self, **kwargs):
        config = SmartRouteConfig(
            vpn_interface="utun5",
            use_default_blocklist=False,
            custom_domains=kwargs.get("custom_domains", ["example.com"]),
            always_direct=kwargs.get("always_direct", []),
            refresh_interval=3600,  # Don't auto-refresh in tests.
            **{k: v for k, v in kwargs.items()
               if k not in ("custom_domains", "always_direct")},
        )
        return SmartRouter(config)

    def test_is_blocked(self):
        router = self._make_router(custom_domains=["youtube.com", "x.com"])
        router._blocklist.load()
        self.assertTrue(router.is_blocked("youtube.com"))
        self.assertTrue(router.is_blocked("x.com"))
        self.assertFalse(router.is_blocked("yandex.ru"))

    def test_is_blocked_subdomain(self):
        router = self._make_router(custom_domains=["youtube.com"])
        router._blocklist.load()
        self.assertTrue(router.is_blocked("www.youtube.com"))

    @patch.object(_RouteInstaller, "_route_cmd", _mock_route_cmd)
    def test_start_stop(self):
        router = self._make_router(custom_domains=["localhost"])
        router.start(vpn_gateway="10.8.0.1")
        stats = router.stats()
        self.assertGreater(stats.blocked_domains, 0)
        self.assertGreater(stats.vpn_routes_installed, 0)
        router.stop()
        # After stop, installer is cleaned up.
        stats2 = router.stats()
        self.assertEqual(stats2.vpn_routes_installed, 0)

    @patch.object(_RouteInstaller, "_route_cmd", _mock_route_cmd)
    def test_add_domain_dynamic(self):
        router = self._make_router(custom_domains=[])
        router.start(vpn_gateway="10.8.0.1")
        self.assertFalse(router.is_blocked("localhost"))
        router.add_domain("localhost")
        self.assertTrue(router.is_blocked("localhost"))
        router.stop()

    @patch.object(_RouteInstaller, "_route_cmd", _mock_route_cmd)
    def test_context_manager(self):
        router = self._make_router(custom_domains=["localhost"])
        with router:
            self.assertTrue(router.is_blocked("localhost"))
        # After exit, stopped.

    def test_stats_initial(self):
        router = self._make_router()
        stats = router.stats()
        self.assertEqual(stats.blocked_domains, 0)  # Not loaded yet.
        self.assertEqual(stats.vpn_routes_installed, 0)
        self.assertEqual(stats.mode, "blocklist")

    @patch.object(_RouteInstaller, "_route_cmd", _mock_route_cmd)
    def test_blocked_and_direct_domains(self):
        router = self._make_router(
            custom_domains=["youtube.com"],
            always_direct=["mybank.ru"],
        )
        router._blocklist.load()
        self.assertIn("youtube.com", router.blocked_domains())
        self.assertIn("mybank.ru", router.direct_domains())

    def test_default_blocked_list_contents(self):
        self.assertIn("youtube.com", DEFAULT_BLOCKED_DOMAINS)
        self.assertIn("instagram.com", DEFAULT_BLOCKED_DOMAINS)
        self.assertIn("x.com", DEFAULT_BLOCKED_DOMAINS)

    def test_default_direct_list_contents(self):
        self.assertIn("yandex.ru", ALWAYS_DIRECT_DOMAINS)
        self.assertIn("vk.com", ALWAYS_DIRECT_DOMAINS)
        self.assertIn("sberbank.ru", ALWAYS_DIRECT_DOMAINS)

    @patch.object(_RouteInstaller, "_route_cmd", _mock_route_cmd)
    def test_blocklist_file_integration(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("fileblocked.com\n")
            path = f.name
        try:
            config = SmartRouteConfig(
                vpn_interface="utun5",
                use_default_blocklist=False,
                blocklist_file=path,
                refresh_interval=3600,
            )
            router = SmartRouter(config)
            router.start(vpn_gateway="10.8.0.1")
            self.assertTrue(router.is_blocked("fileblocked.com"))
            router.stop()
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Tests: create_smart_router factory
# ---------------------------------------------------------------------------

class TestCreateSmartRouter(unittest.TestCase):
    def test_factory_defaults(self):
        router = create_smart_router(vpn_interface="utun5")
        self.assertIsInstance(router, SmartRouter)

    def test_factory_custom_domains(self):
        router = create_smart_router(
            vpn_interface="utun5",
            custom_domains=["custom.com"],
            use_default_blocklist=False,
        )
        router._blocklist.load()
        self.assertTrue(router.is_blocked("custom.com"))

    def test_factory_always_direct(self):
        router = create_smart_router(
            vpn_interface="utun5",
            always_direct=["direct.com"],
            custom_domains=["direct.com"],
            use_default_blocklist=False,
        )
        router._blocklist.load()
        self.assertFalse(router.is_blocked("direct.com"))


# ---------------------------------------------------------------------------
# Tests: thread safety
# ---------------------------------------------------------------------------

class TestThreadSafety(unittest.TestCase):
    def test_concurrent_is_blocked(self):
        config = SmartRouteConfig(
            use_default_blocklist=True,
            custom_domains=["extra.com"],
        )
        mgr = _BlocklistManager(config)
        mgr.load()

        errors = []

        def checker():
            try:
                for _ in range(500):
                    mgr.is_blocked("youtube.com")
                    mgr.is_blocked("yandex.ru")
                    mgr.is_blocked("extra.com")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=checker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])

    def test_concurrent_dns_resolve(self):
        cache = _DNSCache(ttl=60)
        errors = []

        def resolver():
            try:
                for _ in range(100):
                    cache.resolve("localhost")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=resolver) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
