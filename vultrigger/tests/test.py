# tests/test_cv_extract.py

import unittest
from joern_slice.cv_extract import extract_info

class TestCVExtract(unittest.TestCase):
    def test_extract_cv_info(self):
        diff_path = './data'
        info_path = './diff_info'
        extract_info(diff_path, info_path)

if __name__ == "__main__":
    unittest.main()
