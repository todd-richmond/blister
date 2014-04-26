AC_PREREQ([2.69])
AC_INIT([Blister],[1.1])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

AM_CONDITIONAL(OSX, test "`uname -s`" = Darwin)
AM_CONDITIONAL(Linux, test "`uname -s`" = Linux)
AM_CONDITIONAL(SunOS, test "`uname -s`" = SunOS)
AM_CONDITIONAL(Intel32, test "`uname -p`" = i686 -o "`uname -p`" = i386)
AM_CONDITIONAL(Intel64, test "`uname -p`" = x86_64)

: ${CFLAGS=""}
: ${CXXFLAGS=""}

AC_C_BIGENDIAN
AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LN_S
AM_PROG_AR

LT_INIT
LT_LANG([C++])
LT_PATH_LD

AC_CHECK_LIB([dl],[main])ac_cv_lib_dl=ac_cv_lib_dl_main
AC_CHECK_LIB([nsl],[main])ac_cv_lib_nsl=ac_cv_lib_nsl_main
AC_CHECK_LIB([pthread],[main])ac_cv_lib_pthread=ac_cv_lib_pthread_main
AC_CHECK_LIB([rt],[main])ac_cv_lib_rt=ac_cv_lib_rt_main
AC_CHECK_LIB([socket],[main])ac_cv_lib_socket=ac_cv_lib_socket_main

AC_ARG_ENABLE(OPTIMIZE,
    [AS_HELP_STRING([--enable-optimize@<:@=CFLAGS@:>@],[C++ compiler optimizations @<:@default=-O3 -g -DNDEBUG@:>@])],
    [
	if test "$enableval" = no -o "$enableval" = debug; then
	    OPTIMIZE="-g -D_DEBUG"
	elif test "$enableval" = yes; then
	    OPTIMIZE="-O3 -g -DNDEBUG"
	else
	    OPTIMIZE="$enableval"
	fi
    ],
    [ OPTIMIZE="-O3 -g -DNDEBUG"]
)

AC_SUBST(OPTIMIZE)

AC_CONFIG_FILES([Makefile lib/Makefile test/Makefile])

AC_OUTPUT

