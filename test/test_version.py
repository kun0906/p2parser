from __future__ import print_function

import os
import sys
from os import path as pth

sys.path.append(pth.basename(os.getcwd()))
print(sys.path)

import splitter

from unittest import TestCase


class TestCollectEnv(TestCase):
    def test_smoke(self):
        info_output = splitter.parser(n=1)
        # self.assertTrue(info_output.count('\n') >= 17)

    def test_splitter(self):
        info_output = splitter.parser(n=2)
        # self.assertTrue(info_output.count('\n') >= 17)


if __name__ == '__main__':
    run_tests()
