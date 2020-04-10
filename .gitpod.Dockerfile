FROM gitpod/workspace-full

# Install custom tools, runtime, etc.
RUN sudo apt-get update && \
	sudo apt-get install -y ccache clang cppcheck && \
	sudo rm -rf /var/lib/apt/lists/* && \
	pip3 install cpplint
