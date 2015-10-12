AC_PREREQ([2.63])
AC_INIT([Blister],[1.2])
AC_CONFIG_SRCDIR([lib/stdapi.h])
AM_INIT_AUTOMAKE([-Wall -Werror dist-zip foreign no-define no-installinfo no-installman ])

AM_CONDITIONAL(OSX, test "`uname -s`" = Darwin)
AM_CONDITIONAL(Linux, test "`uname -s`" = Linux)
AM_CONDITIONAL(SunOS, test "`uname -s`" = SunOS)
AM_CONDITIONAL(Intel32, test "`uname -p`" = i686 -o "`uname -p`" = i386)
AM_CONDITIONAL(Intel64, test "`uname -p`" = x86_64)

: ${CFLAGS=""}
: ${CXXFLAGS=""}

AC_C_BIGENDIAN
AC_PROG_MAKE_SET
AM_PROG_AR
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LN_S

LT_INIT
LT_LANG([C++])
LT_PATH_LD

AC_CHECK_LIB([dl],[main])
AC_CHECK_LIB([pthread],[main])
AC_CHECK_LIB([rt],[main])
AC_CHECK_LIB([socket],[main])
AC_SEARCH_LIBS([gethostbyname],[nsl])

AC_MSG_CHECKING(for compiler optimizations)
AC_ARG_ENABLE(optimize,
    [AS_HELP_STRING([--enable-optimize@<:@=CFLAGS@:>@],[C++ compiler optimizations @<:@default=-O3 -g -DNDEBUG@:>@])],
    [
	if test "$enable_optimize" = no -o "$enable_optimize" = debug; then
	    optimize="-g -D_DEBUG"
	elif test "$enable_optimize" = yes; then
	    optimize="-O3 -g -DNDEBUG"
	else
	    optimize="$enable_optimize"
	fi
    ],
    [optimize="-O3 -g -DNDEBUG"]
)
AC_MSG_RESULT("$optimize")
AC_SUBST(optimize)

COMMON_CFLAGS="-pipe -Wall -Werror $optimize"
AM_CFLAGS="$AM_CFLAGS $COMMON_CFLAGS"
AM_CXXFLAGS="$AM_CXXFLAGS -fno-rtti -fno-exceptions -Wno-deprecated $COMMON_CFLAGS"

AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_CXXFLAGS])
AC_SUBST([AM_LDFLAGS])
AC_SUBST([LIBS])

AC_CONFIG_FILES([Makefile lib/Makefile test/Makefile])

AC_OUTPUT

