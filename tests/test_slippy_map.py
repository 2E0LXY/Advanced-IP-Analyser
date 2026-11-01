import math
import unittest

from ip_analyser.slippy_map import pixel_location, world_pixel


class SlippyMapProjectionTests(unittest.TestCase):
    def test_web_mercator_round_trip(self):
        expected = (53.7939, -1.7521)
        pixel = world_pixel(*expected, zoom=10)
        actual = pixel_location(*pixel, zoom=10)
        self.assertTrue(math.isclose(actual[0], expected[0], abs_tol=1e-7))
        self.assertTrue(math.isclose(actual[1], expected[1], abs_tol=1e-7))

    def test_web_mercator_clamps_poles(self):
        self.assertEqual(world_pixel(90, 0, 2), world_pixel(85.05112878, 0, 2))
        self.assertEqual(world_pixel(-90, 0, 2), world_pixel(-85.05112878, 0, 2))

    def test_panning_beyond_world_clamps_latitude(self):
        scale = 256 * (2 ** 3)
        self.assertLessEqual(pixel_location(0, -scale * 20, 3)[0], 85.0512)
        self.assertGreaterEqual(pixel_location(0, scale * 20, 3)[0], -85.0512)
