import unittest

@unittest.skip("flaky on CI")
def test_feature():
    print("skipped")
