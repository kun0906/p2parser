### use 'sphinx-quickstart' and 'iphinx-apidoc' to generate the docs.
### https://samnicholls.net/2016/06/15/how-to-sphinx-readthedocs/
###https://medium.com/@eikonomega/getting-started-with-sphinx-autodoc-part-1-2cebbbca5365
### http://www.sphinx-doc.org/en/master/usage/quickstart.htmlcd

1. sphinx-quickstart
# add the following int the docs/conf.py
import os
import sys
sys.path.insert(0, os.path.abspath('.'))
sys.path.append(os.path.dirname(os.getcwd()))

# extensions = []   # error: Unknown directive type "automodule".
extensions = ['sphinx.ext.autodoc', 'sphinx.ext.coverage', 'sphinx.ext.napoleon',
              'sphinx.ext.todo', 'sphinx.ext.viewcode',]

# -E without "packages" , "module"
# https://stackoverflow.com/questions/21003122/sphinx-apidoc-section-titles-for-python-module-package-names
2. sphinx-apidoc -o sources/  -E ../itod ../itod/legacy/*
# usage: sphinx-apidoc [OPTIONS] -o <OUTPUT_PATH> <MODULE_PATH> [EXCLUDE_PATTERN, ...]
# https://github.com/sphinx-doc/sphinx/issues/944
#$ sphinx-apidoc -h
#Usage: sphinx-apidoc [options] -o <output_path> <module_path> [exclude_path, ...]

2.1 modify the html theme
      https://pypi.org/project/groundwork-sphinx-theme/
    a) install the package using pip: pip install groundwork-sphinx-theme
    b) Add this to conf.py:
      html_theme = 'groundwork'

3. make html

