"""Unit tests for SHA-256 result caching engine."""
import os
import unittest

from lensint.cache import get_cached, put_cache, cache_stats, clear_cache


class TestCacheModule(unittest.TestCase):
    def test_cache_put_get_cycle(self):
        fake_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        fake_data = {"test_key": "test_value", "risk": 15.0}

        # Put in cache
        put_cache(fake_sha256, fake_data)

        # Retrieve
        cached = get_cached(fake_sha256)
        self.assertIsNotNone(cached)
        self.assertEqual(cached["test_key"], "test_value")

        # Stats check
        stats = cache_stats()
        self.assertGreater(stats["count"], 0)

        # Clean up
        deleted = clear_cache()
        self.assertGreater(deleted, 0)
        self.assertIsNone(get_cached(fake_sha256))


if __name__ == "__main__":
    unittest.main()
