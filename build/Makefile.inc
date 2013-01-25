AUTOMAKE_OPTIONS = foreign

#remove everything that build auto generates
DISTCLEANFILES = aclocal.m4 autom4te.cache/* config.guess config.sub configure \
	depcomp documentation install-sh ltmain.sh missing mkinstalldirs \
	Makefile.in

CFLAGS = -Wall -Werror -pipe $(EXTRACFLAGS) @optimize@ 
CXXFLAGS = $(CFLAGS) -Wno-deprecated -fno-rtti -fno-exceptions

