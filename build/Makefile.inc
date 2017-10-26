# eliminate unused configure macros
DEFS = 

# remove generated files
DISTCLEANFILES = aclocal.m4 ar-lib autom4te.cache/* compile \
	config.guess config.sub configure depcomp documentation \
	install-sh ltmain.sh missing mkinstalldirs Makefile.in

stdapi.h.gch: ../lib/stdapi.h
	$(CXXCOMPILE) -xc++-header -o $@ $<

