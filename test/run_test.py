

from __future__ import print_function

import argparse
from datetime import datetime
import os
import shutil
import signal
import subprocess
import sys
import tempfile

from test import test_utils

PY33 = sys.version_info >= (3, 3)
PY36 = sys.version_info >= (3, 6)

TESTS = [
    'test_version',
    'data/test_xxx',

]

# https://stackoverflow.com/questions/2549939/get-signal-names-from-numbers-in-python
SIGNALS_TO_NAMES_DICT = {getattr(signal, n): n for n in dir(signal)
                         if n.startswith('SIG') and '_' not in n}

def print_to_stderr(message):
    print(message, file=sys.stderr)


def run_test(executable, test_module, test_directory, options, *extra_unittest_args):
    unittest_args = options.additional_unittest_args
    if options.verbose:
        unittest_args.append('--verbose')
    # Can't call `python -m unittest test_*` here because it doesn't run code
    # in `if __name__ == '__main__': `. So call `python test_*.py` instead.
    argv = [test_module + '.py'] + unittest_args + list(extra_unittest_args)

    command = executable + argv
    return shell(command, test_directory)


def test_cuda_primary_ctx(executable, test_module, test_directory, options):
    return run_test(executable, test_module, test_directory, options, '--subprocess')


def parse_test_module(test):
    return test.split('.')[0]


class TestChoices(list):
    def __init__(self, *args, **kwargs):
        super(TestChoices, self).__init__(args[0])

    def __contains__(self, item):
        return list.__contains__(self, parse_test_module(item))


def parse_args():
    parser = argparse.ArgumentParser(
        description='Run the p2parser unit test suite',
        epilog='where TESTS is any of: {}'.format(', '.join(TESTS)))
    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='print verbose information and test-by-test results')
    parser.add_argument(
        '--jit',
        '--jit',
        action='store_true',
        help='run all jit tests')
    parser.add_argument(
        '-pt', '--pytest', action='store_true',
        help='If true, use `pytest` to execute the tests. E.g., this runs '
             'TestTorch with pytest in verbose and coverage mode: '
             'python run_test.py -vci torch -pt')
    parser.add_argument(
        '-c', '--coverage', action='store_true', help='enable coverage')
    parser.add_argument(
        '-i',
        '--include',
        nargs='+',
        choices=TestChoices(TESTS),
        default=TESTS,
        metavar='TESTS',
        help='select a set of tests to include (defaults to ALL tests).'
             ' tests can be specified with module name, module.TestClass'
             ' or module.TestClass.test_method')
    parser.add_argument(
        '-x',
        '--exclude',
        nargs='+',
        choices=TESTS,
        metavar='TESTS',
        default=[],
        help='select a set of tests to exclude')
    parser.add_argument(
        '-f',
        '--first',
        choices=TESTS,
        metavar='TESTS',
        help='select the test to start from (excludes previous tests)')
    parser.add_argument(
        '-l',
        '--last',
        choices=TESTS,
        metavar='TESTS',
        help='select the last test to run (excludes following tests)')
    parser.add_argument(
        '--bring-to-front',
        nargs='+',
        choices=TestChoices(TESTS),
        default=[],
        metavar='TESTS',
        help='select a set of tests to run first. This can be used in situations'
             ' where you want to run all tests, but care more about some set, '
             'e.g. after making a change to a specific component')
    parser.add_argument(
        '--ignore-win-blacklist',
        action='store_true',
        help='always run blacklisted windows tests')
    parser.add_argument(
        'additional_unittest_args',
        nargs='*',
        help='additional arguments passed through to unittest, e.g., '
             'python run_test.py -i sparse -- TestSparse.test_factory_size_check')
    return parser.parse_args()


def get_executable_command(options):
    if options.coverage:
        executable = ['coverage', 'run', '--parallel-mode', '--source torch']
    else:
        executable = [sys.executable]
    if options.pytest:
        executable += ['-m', 'pytest']
    return executable


def find_test_index(test, selected_tests, find_last_index=False):
    """Find the index of the first or last occurrence of a given test/test module in the list of selected tests.

    This function is used to determine the indices when slicing the list of selected tests when
    ``options.first``(:attr:`find_last_index`=False) and/or ``options.last``(:attr:`find_last_index`=True) are used.

    :attr:`selected_tests` can be a list that contains multiple consequent occurrences of tests
    as part of the same test module, e.g.:

    ```
    selected_tests = ['autograd', 'cuda', **'torch.TestTorch.test_acos',
                     'torch.TestTorch.test_tan', 'torch.TestTorch.test_add'**, 'utils']
    ```

    If :attr:`test`='torch' and :attr:`find_last_index`=False, result should be **2**.
    If :attr:`test`='torch' and :attr:`find_last_index`=True, result should be **4**.

    Arguments:
        test (str): Name of test to lookup
        selected_tests (list): List of tests
        find_last_index (bool, optional): should we lookup the index of first or last
            occurrence (first is default)

    Returns:
        index of the first or last occurrence of the given test
    """
    idx = 0
    found_idx = -1
    for t in selected_tests:
        if t.startswith(test):
            found_idx = idx
            if not find_last_index:
                break
        idx += 1
    return found_idx


def shell(command, cwd=None, env=None):
    sys.stdout.flush()
    sys.stderr.flush()
    # The following cool snippet is copied from Py3 core library subprocess.call
    # only the with
    #   1. `except KeyboardInterrupt` block added for SIGINT handling.
    #   2. In Py2, subprocess.Popen doesn't return a context manager, so we do
    #      `p.wait()` in a `final` block for the code to be portable.
    #
    # https://github.com/python/cpython/blob/71b6c1af727fbe13525fb734568057d78cea33f3/Lib/subprocess.py#L309-L323
    assert not isinstance(command, torch._six.string_classes), "Command to shell should be a list or tuple of tokens"
    p = subprocess.Popen(command, universal_newlines=True, cwd=cwd, env=env)
    try:
        return p.wait()
    except KeyboardInterrupt:
        # Give `p` a chance to handle KeyboardInterrupt. Without this,
        # `pytest` can't print errors it collected so far upon KeyboardInterrupt.
        exit_status = p.wait(timeout=5)
        if exit_status is not None:
            return exit_status
        else:
            p.kill()
            raise
    except:  # noqa E722, copied from python core library
        p.kill()
        raise
    finally:
        # Always call p.wait() to ensure exit
        p.wait()

def exclude_tests(exclude_list, selected_tests, exclude_message=None):
    for exclude_test in exclude_list:
        tests_copy = selected_tests[:]
        for test in tests_copy:
            if test.startswith(exclude_test):
                if exclude_message is not None:
                    print_to_stderr('Excluding {} {}'.format(test, exclude_message))
                selected_tests.remove(test)
    return selected_tests


def get_selected_tests(options):
    selected_tests = options.include

    if options.bring_to_front:
        to_front = set(options.bring_to_front)
        selected_tests = options.bring_to_front + list(filter(lambda name: name not in to_front,
                                                              selected_tests))

    if options.first:
        first_index = find_test_index(options.first, selected_tests)
        selected_tests = selected_tests[first_index:]

    if options.last:
        last_index = find_test_index(options.last, selected_tests, find_last_index=True)
        selected_tests = selected_tests[:last_index + 1]

    selected_tests = exclude_tests(options.exclude, selected_tests)

    return selected_tests


CUSTOM_HANDLERS = {
    # 'test_utils': test_utils
    'test_cuda_primary_ctx': test_cuda_primary_ctx,
    # 'test_cpp_extensions_aot': test_cpp_extensions_aot,
    # 'test_cpp_extensions_aot_no_ninja': test_cpp_extensions_aot_no_ninja,
    # 'distributed/test_distributed': test_distributed,
}


def main():
    options = parse_args()
    executable = get_executable_command(options)  # this is a list
    print_to_stderr('Test executor: {}'.format(executable))
    test_directory = os.path.dirname(os.path.abspath(__file__))
    selected_tests = get_selected_tests(options)

    if options.verbose:
        print_to_stderr('Selected tests: {}'.format(', '.join(selected_tests)))

    if options.coverage:
        shell(['coverage', 'erase'])

    if options.jit:
        selected_tests = filter(lambda test_name: "jit" in test_name, TESTS)

    for test in selected_tests:

        test_module = parse_test_module(test)

        # Printing the date here can help diagnose which tests are slow
        print_to_stderr('Running {} ... [{}]'.format(test, datetime.now()))
        handler = CUSTOM_HANDLERS.get(test, run_test)
        return_code = handler(executable, test_module, test_directory, options)
        assert isinstance(return_code, int) and not isinstance(
            return_code, bool), 'Return code should be an integer'
        if return_code != 0:
            message = '{} failed!'.format(test)
            if return_code < 0:
                # subprocess.Popen returns the child process' exit signal as
                # return code -N, where N is the signal number.
                signal_name = SIGNALS_TO_NAMES_DICT[-return_code]
                message += ' Received signal: {}'.format(signal_name)
            raise RuntimeError(message)
    if options.coverage:
        shell(['coverage', 'combine'])
        shell(['coverage', 'html'])


if __name__ == '__main__':
    main()
