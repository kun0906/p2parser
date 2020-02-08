from setuptools import find_packages, setup
from os import path as pth
# from tools.setup_helpers.cmake import CMake

# check if the python version is python2.x
try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError  # Python 2.7 does not have FileNotFoundError

current_dir = pth.abspath(pth.dirname(__file__))

version_file = pth.join(current_dir, 'p2parser/version.py')


def get_version(file_name=''):
    with open(file_name, mode='r') as f:
        exec(f.read())  # get __version__ from p2parser/version.py
    return locals()['__version__']


# read the contents of README.md (or README.rst)
readme_file = pth.join(current_dir, 'README.md')
requirement_file = pth.join(current_dir, 'requirements.txt')

def get_content(file_name=''):
    with open(file_name, mode='r') as f:
        values = f.readlines()
    print(values)
    return values

setup(
    name='p2parser',
    version=get_version(version_file),
    description='A python toolkit for pcap parser',
    long_description=get_content(file_name=readme_file),
    long_description_content_type='text/x-md',
    author='Kun',
    author_email='kun.bj@outlook.com',
    url='https://github.com/Learn-Live',
    download_url='https://github.com/Learn-Live',
    keywords=['network traffic analysis', 'flow/subflow', 'pcap'],
    packages=find_packages(exclude=['test']),
    include_package_data=True,
    install_requires=get_content(file_name=requirement_file),
    setup_requires=['setuptools>=38.6.0'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Education',
        'Intended Audience :: Financial and Insurance Industry',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
)
