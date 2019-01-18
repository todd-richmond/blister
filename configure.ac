AC_PREREQ([2.63])
AC_INIT([Blister],[1.4])
AC_CONFIG_SRCDIR([lib/stdapi.h])
AM_INIT_AUTOMAKE([-Wall -Werror dist-zip foreign no-define no-installinfo no-installman ])

AM_CONDITIONAL(OSX, test "`uname -s`" = Darwin)
AM_CONDITIONAL(Linux, test "`uname -s`" = Linux)
AM_CONDITIONAL(SunOS, test "`uname -s`" = SunOS)
AM_CONDITIONAL(Intel32, test "`uname -p`" = i686 -o "`uname -p`" = i386)
AM_CONDITIONAL(Intel64, test "`uname -p`" = x86_64)
AM_CONDITIONAL(StackProtector, test "`echo '$(gcc -dumpversion) >= 4.9' | bc`" = 1)

: ${CFLAGS=""}
: ${CXXFLAGS=""}
: ${GCCREL="`gcc -dumpversion`"}
: ${OPTIMIZE="-O3 -fdata-sections -ffunction-sections -g -DNDEBUG"}
: ${OSREL="`uname -r | cut -d. -f1-2`"}
: ${STACKPROTECTOR="-fstack-protector-strong"}

AC_C_BIGENDIAN
AC_PROG_MAKE_SET
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
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
    [AS_HELP_STRING([--enable-optimize@<:@=CFLAGS@:>@],[C++ compiler optimizations @<:@default=-O3@:>@])],
    [
	if test "$enable_optimize" = no -o "$enable_optimize" = debug; then
	    optimize="-O1 -fno-omit-frame-pointer -g3 -D_DEBUG"
	elif test "$enable_optimize" = yes; then
	    optimize="$OPTIMIZE"
	else
	    optimize="$enable_optimize"
	fi
    ],
    [optimize="$OPTIMIZE"]
)
AC_MSG_RESULT("$optimize")
AC_SUBST(optimize)

COMMON_CFLAGS="-ffast-math -march=native -pipe -Wall -Wconversion -Werror -Wextra -Wformat=2 -Wno-format-nonliteral -Wformat-security -Wno-format-y2k -Wmultichar -Wno-pragmas -Wredundant-decls -Wsign-conversion -Wstrict-aliasing -Wstrict-overflow=2 -Wtrampolines -Wno-unknown-pragmas -Wwrite-strings $optimize"
AM_CFLAGS="$AM_CFLAGS $COMMON_CFLAGS"
AM_CXXFLAGS="$AM_CXXFLAGS -fno-exceptions -fno-rtti -Wno-deprecated -Wnon-virtual-dtor -Woverloaded-virtual -Wsign-promo $COMMON_CFLAGS"

AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_CXXFLAGS])
AC_SUBST([AM_LDFLAGS])
AC_SUBST([LIBS])

AC_CONFIG_FILES([Makefile lib/Makefile test/Makefile])

AC_OUTPUT

