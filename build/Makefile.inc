# eliminate unused configure macros
DEFS = 

# remove generated files
DISTCLEANFILES = aclocal.m4 ar-lib autom4te.cache/* config.guess config.sub \
	configure depcomp documentation install-sh ltmain.sh \
	missing mkinstalldirs Makefile.in

AM_CFLAGS = -Wall -Werror -pipe $(CFLAGS) @OPTIMIZE@
AM_CXXFLAGS = -fno-rtti -fno-exceptions $(AM_CFLAGS) -Wno-deprecated

