AUTOMAKE_OPTIONS = foreign

CC = gcc
CPP = gcc -E
CXX = g++
CXXCPP = g++ -E
LD = g++

DEFS = 
INCLUDES=

#remove everything that build auto generates
DISTCLEANFILES = aclocal.m4 autom4te.cache/* config.guess config.sub configure \
	depcomp documentation install-sh ltmain.sh missing mkinstalldirs \
	Makefile.in

COPTFLAGS_DEBUG = -ggdb -D_DEBUG
COPTFLAGS_OPTIMIZE = -O3 -ggdb -DNDEBUG
COPTFLAGS = $(COPTFLAGS_DEBUG)

CFLAGS = $(COPTFLAGS) -Wall -pipe
CXXFLAGS = $(COPTFLAGS) -Wall -pipe -fno-rtti -fno-exceptions

