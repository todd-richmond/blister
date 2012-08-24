AUTOMAKE_OPTIONS = foreign

CC = gcc
CPP = $(CC) -E
CXX = g++
CXXCPP = $(CXX) -E
LD = $(CXX)

DEFS = 
INCLUDES=

#remove everything that build auto generates
DISTCLEANFILES = aclocal.m4 autom4te.cache/* config.guess config.sub configure \
	depcomp documentation install-sh ltmain.sh missing mkinstalldirs \
	Makefile.in

if Linux
if Intel32
EXTRACFLAGS = -march=pentium4
endif
endif

CFLAGS = -Wall -Werror -pipe $(EXTRACFLAGS) @optimize@ 
CXXFLAGS = $(CFLAGS) -Wno-deprecated -fno-rtti -fno-exceptions

