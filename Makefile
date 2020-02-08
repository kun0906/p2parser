# This makefile does nothing but delegating the actual building to cmake.

# You can set these variables from the command line.
PROJ_NAME	=	p2parser

all:
	@mkdir -p build && cd build && cmake .. $(shell python ./scripts/get_python_cmake_flags.py) && $(MAKE)

myclean:
	@./scripts/build_ios.sh

clean: # This will remove ALL build folders.
	@rm -rf build/*
	@rm -rf ${PROJ_NAME}.egg_info/
	@./scripts/clean.py		# using python to clean up


linecount:
	@cloc --read-lang-def=caffe.cloc caffe2 || \
		echo "Cloc is not available on the machine. You can install cloc with " && \
		echo "    sudo apt-get install cloc"