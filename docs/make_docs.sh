# !/bin/sh

cd docs
# be careful for 'pwd' and 'PWD. 'pwd' might not be recognized.
echo 'current_dir:' ${PWD}
make html-stable

cd ..
echo 'current_dir:' ${PWD}



