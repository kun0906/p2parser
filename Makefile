# make life easier.

# You can set these variables from the command line.
PROJ_NAME	=	p2parser
TRASH_DIR 	= 	.trash
RM			=	mv		# use 'mv' instead of 'rm' for safety
PYTHON		= 	python3	# python version

#all:
##	@mkdir -p build && cd build && cmake .. $(shell python ./scripts/get_python_cmake_flags.py) && $(MAKE)
#	@mkdir -p build && cd build

run_examples:
#	@./srcipts/run_p2parser.sh  #
#	@${PYTHON} ./examples/pcap_parser.py		# with '@', the command line won't show the command.
	${PYTHON} ./examples/splitter_scapy.py

docs_all:
	@chmod 755 ./docs/make_docs.sh
	@./docs/make_docs.sh

myclean:	# suppres echoing the output, use the "@" sign.
	@chmod 755 ./scripts/clean.sh
	@./scripts/clean.sh

clean:
# This will remove ALL build folders.
#	@PWD		# show the current directory
#	#if possible, please avoid using 'rm -rf' (it's not easy to recover once you make a mistake).
#	# Try 'mv files ./trash' instead.
#	#rm -rf build*/		# remove all files and folders under 'build', and remove 'build' itself.
#	#rm -rf ${PROJ_NAME}.egg-info*/


#	Note that the closing ";" and "\" are necessary.
#	'-d' for directory, and '-f' for file
	@if [ -d build ]; then \
		${RM} build*/ $(TRASH_DIR); \
	fi

	@if [ -d ${PROJ_NAME}.egg-info ]; then	\
		${RM} ${PROJ_NAME}.egg-info*/ $(TRASH_DIR);	\
	fi

	${PYTHON} ./scripts/clean.py		# using python to clean up


linecount:
	@cloc --read-lang-def=caffe.cloc caffe2 || \
		echo "Cloc is not available on the machine. You can install cloc with " && \
		echo "    sudo apt-get install cloc"