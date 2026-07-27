# see configure.ac for why this is needed on Darwin
MACOSX_DEPLOYMENT_TARGET = @MACOSX_DEPLOYMENT_TARGET@
export MACOSX_DEPLOYMENT_TARGET

# extra flags for the shared library link only (see configure.ac); a target
# that sets its own per-target LDFLAGS must combine this with $(AM_LDFLAGS)
# itself, since automake doesn't do so automatically
SHARED_LDFLAGS = @SHARED_LDFLAGS@

# eliminate unused configure macros
DEFS =

# remove generated files
DISTCLEANFILES = *.gch aclocal.m4 ar-lib autom4te.cache/* compile \
	config.guess config.sub configure depcomp documentation \
	install-sh ltmain.sh missing mkinstalldirs Makefile.in

stdapi.h.gch: ../lib/stdapi.h
	$(CXXCOMPILE) -xc++-header -o $@ $<

