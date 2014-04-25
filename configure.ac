AC_INIT(Blister, 1.1)
AM_INIT_AUTOMAKE

AM_CONDITIONAL(OSX, test "`uname -s`" = Darwin)
AM_CONDITIONAL(Linux, test "`uname -s`" = Linux)
AM_CONDITIONAL(SunOS, test "`uname -s`" = SunOS)
AM_CONDITIONAL(Intel32, test "`uname -p`" = i686 -o "`uname -p`" = i386)
AM_CONDITIONAL(Intel64, test "`uname -p`" = x86_64)

AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LD
AC_PROG_LIBTOOL
AC_PROG_LN_S

AC_HAVE_LIBRARY(dl)
AC_HAVE_LIBRARY(nsl)
AC_HAVE_LIBRARY(pthread)
AC_HAVE_LIBRARY(rt)
AC_HAVE_LIBRARY(socket)

AC_ARG_ENABLE(optimize,
    [AC_HELP_STRING([--enable-optimize@<:@=CFLAGS@:>@],
	[C++ compiler options @<:@default=-O3 -g -DNDEBUG@:>@])],
    [
	if test "$enableval" = no -o "$enableval" = debug; then
	    optimize="-g -D_DEBUG"
	elif test "$enableval" = yes; then
	    optimize="-O3 -g -DNDEBUG"
	else
	    optimize="$enableval"
	fi
    ],
    [ optimize="-O3 -g -DNDEBUG"]
)

AC_SUBST(optimize)

AC_OUTPUT(Makefile lib/Makefile test/Makefile)

