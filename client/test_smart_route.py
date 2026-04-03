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
    _BlockProber,
    _DNSCache,
    _RouteInstaller,
    _is_ip_or_cidr,
    _get_default_gateway,
    ProbeResult,
    PROBE_DOMAINS,
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


# ---------------------------------------------------------------------------
# Tests: _BlockProber
# ---------------------------------------------------------------------------

class TestBlockProber(unittest.TestCase):
    def test_probe_localhost_not_blocked(self):
        """localhost should be connectable → not blocked."""
        prober = _BlockProber(timeout=2.0, port=80)
        # Probe localhost — won't have port 80 open on most test systems,
        # but we can at least test the mechanics.
        result = prober._probe_domain("localhost")
        self.assertIsInstance(result, ProbeResult)
        self.assertEqual(result.domain, "localhost")

    def test_probe_nonexistent_domain(self):
        """Non-existent domain → dns_failed → blocked."""
        prober = _BlockProber(timeout=1.0)
        result = prober._probe_domain("this.domain.does.not.exist.xyz123abc")
        self.assertTrue(result.blocked)
        self.assertEqual(result.error, "dns_failed")

    def test_probe_all_parallel(self):
        """probe_all runs domains in parallel and returns results."""
        prober = _BlockProber(timeout=3.0)
        domains = ["localhost", "this.domain.does.not.exist.xyz123abc"]
        results = prober.probe_all(domains, workers=2)
        # At least one result should be returned (DNS for nonexistent may be slow).
        self.assertGreaterEqual(len(results), 1)
        domain_names = {r.domain for r in results}
        self.assertIn("localhost", domain_names)

    def test_blocked_and_direct_properties(self):
        """blocked_domains and direct_domains partitions results."""
        prober = _BlockProber(timeout=1.0)
        # Manually inject results.
        prober._results["blocked.com"] = ProbeResult("blocked.com", True, -1, "timeout")
        prober._results["direct.com"] = ProbeResult("direct.com", False, 50.0)
        self.assertIn("blocked.com", prober.blocked_domains)
        self.assertNotIn("direct.com", prober.blocked_domains)
        self.assertIn("direct.com", prober.direct_domains)
        self.assertNotIn("blocked.com", prober.direct_domains)

    def test_all_results(self):
        prober = _BlockProber()
        prober._results["a.com"] = ProbeResult("a.com", True, -1)
        prober._results["b.com"] = ProbeResult("b.com", False, 10.0)
        self.assertEqual(len(prober.all_results), 2)

    def test_cache_save_and_load(self):
        """Save probe results to cache and reload them."""
        prober = _BlockProber()
        prober._results["youtube.com"] = ProbeResult("youtube.com", True, -1, "timeout")
        prober._results["yandex.ru"] = ProbeResult("yandex.ru", False, 25.0)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            prober.save_cache(path)

            prober2 = _BlockProber()
            loaded = prober2.load_cache(path)
            self.assertTrue(loaded)
            self.assertIn("youtube.com", prober2.blocked_domains)
            self.assertIn("yandex.ru", prober2.direct_domains)
            self.assertEqual(prober2.all_results["youtube.com"].error, "timeout")
        finally:
            os.unlink(path)

    def test_cache_load_nonexistent(self):
        prober = _BlockProber()
        self.assertFalse(prober.load_cache("/tmp/nonexistent_probe_cache_xyz.json"))

    def test_cache_load_corrupted(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json{{{")
            path = f.name
        try:
            prober = _BlockProber()
            self.assertFalse(prober.load_cache(path))
        finally:
            os.unlink(path)

    def test_probe_domains_list_nonempty(self):
        """PROBE_DOMAINS should contain a reasonable set of domains."""
        self.assertGreater(len(PROBE_DOMAINS), 10)


# ---------------------------------------------------------------------------
# Tests: auto-detect integration
# ---------------------------------------------------------------------------

def _mock_probe_domain(self, domain):
    """Mock probe: domains containing 'blocked' are blocked, others direct."""
    if "blocked" in domain:
        return ProbeResult(domain=domain, blocked=True, latency_ms=-1, error="timeout")
    return ProbeResult(domain=domain, blocked=False, latency_ms=25.0)


class TestAutoDetect(unittest.TestCase):
    @patch.object(_RouteInstaller, "_route_cmd", _mock_route_cmd)
    @patch.object(_BlockProber, "_probe_domain", _mock_probe_domain)
    def test_auto_detect_start(self):
        """SmartRouter with auto_detect probes and populates blocklist."""
        config = SmartRouteConfig(
            vpn_interface="utun5",
            use_default_blocklist=False,
            auto_detect=True,
            probe_domains=["blocked-site.com", "direct-site.com"],
            probe_timeout=1.0,
            refresh_interval=3600,
        )
        router = SmartRouter(config)
        router.start(vpn_gateway="10.8.0.1")
        self.assertTrue(router.is_blocked("blocked-site.com"))
        self.assertFalse(router.is_blocked("direct-site.com"))
        stats = router.stats()
        self.assertGreater(stats.probed_blocked, 0)
        router.stop()

    @patch.object(_RouteInstaller, "_route_cmd", _mock_route_cmd)
    def test_auto_detect_with_cache(self):
        """Auto-detect loads from cache when available."""
        cache_data = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "results": {
                "cached-blocked.com": {"blocked": True, "latency_ms": -1, "error": "timeout"},
                "cached-direct.com": {"blocked": False, "latency_ms": 30.0, "error": ""},
            },
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(cache_data, f)
            cache_path = f.name

        try:
            config = SmartRouteConfig(
                vpn_interface="utun5",
                use_default_blocklist=False,
                auto_detect=True,
                probe_cache_file=cache_path,
                refresh_interval=3600,
            )
            router = SmartRouter(config)
            router.start(vpn_gateway="10.8.0.1")
            self.assertTrue(router.is_blocked("cached-blocked.com"))
            self.assertFalse(router.is_blocked("cached-direct.com"))
            router.stop()
        finally:
            os.unlink(cache_path)

    def test_factory_auto_detect(self):
        """create_smart_router accepts auto_detect parameter."""
        router = create_smart_router(
            vpn_interface="utun5",
            auto_detect=True,
            probe_timeout=1.0,
            probe_domains=["example.com"],
            use_default_blocklist=False,
        )
        self.assertIsInstance(router, SmartRouter)
        self.assertTrue(router._config.auto_detect)
        self.assertEqual(router._config.probe_timeout, 1.0)

    @patch.object(_RouteInstaller, "_route_cmd", _mock_route_cmd)
    @patch.object(_BlockProber, "_probe_domain", _mock_probe_domain)
    def test_probe_results_method(self):
        """probe_results() returns results after auto-detect."""
        config = SmartRouteConfig(
            vpn_interface="utun5",
            use_default_blocklist=False,
            auto_detect=True,
            probe_domains=["blocked-x.com", "direct-y.com"],
            probe_timeout=1.0,
            refresh_interval=3600,
        )
        router = SmartRouter(config)
        router.start(vpn_gateway="10.8.0.1")
        results = router.probe_results()
        self.assertGreater(len(results), 0)
        self.assertIn("blocked-x.com", results)
        self.assertTrue(results["blocked-x.com"].blocked)
        router.stop()

    @patch.object(_RouteInstaller, "_route_cmd", _mock_route_cmd)
    def test_no_auto_detect_by_default(self):
        """Without auto_detect, no prober is created."""
        config = SmartRouteConfig(
            vpn_interface="utun5",
            use_default_blocklist=False,
            custom_domains=["localhost"],
            refresh_interval=3600,
        )
        router = SmartRouter(config)
        router.start(vpn_gateway="10.8.0.1")
        self.assertEqual(router.probe_results(), {})
        router.stop()


if __name__ == "__main__":
    unittest.main()
