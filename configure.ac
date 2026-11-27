# Targets the GNU autotools generation from 2020 or later:
#   autoconf  >= 2.71 (2021) - 2.70 dropped pre-POSIX /bin/sh support
#   automake  >= 1.16.2 (2020)
#   libtool   >= 2.4.7 (2022)
AC_PREREQ([2.71])
AC_INIT([Blister],[1.4])
AC_CONFIG_SRCDIR([lib/stdapi.h])
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([1.16.2 -Wall -Werror dist-zip foreign no-define no-installinfo no-installman])
AM_SILENT_RULES([yes])

: ${CFLAGS=""}
: ${CXXFLAGS=""}
: ${OPTIMIZE="-O3 -fdata-sections -ffunction-sections -DNDEBUG"}

AC_C_BIGENDIAN
AM_PROG_AR
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LN_S

# Detect the compiler family the way CMake does (by asking the compiler,
# not by trusting -dumpversion/--version output). Needed here, ahead of
# LT_INIT, to pick an LTO-aware archiver below: plain ar/ranlib can't read
# GCC/Clang LTO intermediate objects without the compiler's plugin, and
# libtool bakes whatever AR/RANLIB are set to at LT_INIT time into the
# generated libtool script.
AC_LANG_PUSH([C++])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [[
#ifndef __clang__
# error not clang
#endif
]])], [compiler_clang=yes], [compiler_clang=no])
AC_LANG_POP([C++])
AC_MSG_CHECKING([whether $CXX is clang])
AC_MSG_RESULT([$compiler_clang])

if test "$compiler_clang" = yes; then
    AC_PATH_TOOL([LTO_AR], [llvm-ar])
    AC_PATH_TOOL([LTO_RANLIB], [llvm-ranlib])
    AC_PATH_TOOL([LTO_NM], [llvm-nm])
else
    AC_PATH_TOOL([LTO_AR], [gcc-ar])
    AC_PATH_TOOL([LTO_RANLIB], [gcc-ranlib])
    AC_PATH_TOOL([LTO_NM], [gcc-nm])
fi
test -n "$LTO_AR" && AR=$LTO_AR
test -n "$LTO_RANLIB" && RANLIB=$LTO_RANLIB
test -n "$LTO_NM" && NM=$LTO_NM

LT_PREREQ([2.4.7])
LT_INIT
LT_LANG([C++])
LT_PATH_LD

if test "$(uname -s)" = Darwin; then
    : ${MACOSX_DEPLOYMENT_TARGET=$(sw_vers -productVersion | cut -d. -f1-2)}
fi
AC_SUBST([MACOSX_DEPLOYMENT_TARGET])

# CMake adds the llvm libc++ directory to the link path on macOS
LLVM_LDFLAGS=
if test "$(uname -s)" = Darwin; then
    AC_PATH_PROG([LLVM_CONFIG], [llvm-config])
    if test -n "$LLVM_CONFIG"; then
	llvm_libdir=`"$LLVM_CONFIG" --libdir`
	test -n "$llvm_libdir" && LLVM_LDFLAGS="-L$llvm_libdir/c++"
    fi
fi

AC_CHECK_LIB([dl], [dlopen])
AC_CHECK_LIB([pthread], [pthread_create])
AC_CHECK_LIB([rt], [clock_gettime])
AC_CHECK_LIB([socket], [socket])
AC_SEARCH_LIBS([gethostbyname], [nsl])

# uvechotest is an optional libuv-based analog of echotest; shell out to
# pkg-config directly rather than using PKG_CHECK_MODULES since pkg.m4 is
# not reliably on aclocal's search path across environments
AC_PATH_PROG([PKGCONFIG], [pkg-config])
LIBUV_CFLAGS=
LIBUV_LIBS=
AS_IF([test -n "$PKGCONFIG" && "$PKGCONFIG" --exists libuv 2>/dev/null],
    [have_libuv=yes
     LIBUV_CFLAGS=`"$PKGCONFIG" --cflags libuv`
     LIBUV_LIBS=`"$PKGCONFIG" --libs libuv`],
    [have_libuv=no])
AM_CONDITIONAL([HAVE_LIBUV], [test "$have_libuv" = yes])
AC_SUBST([LIBUV_CFLAGS])
AC_SUBST([LIBUV_LIBS])

# libblistertls uses OpenSSL 3.5+ if found, else fails TLS requests; as
# CMakeLists.txt, prefer a toolchain bundled OpenSSL over an older system one
AC_ARG_WITH([openssl],
    [AS_HELP_STRING([--with-openssl=DIR],[OpenSSL 3.5+ prefix @<:@default=compiler prefix, then pkg-config@:>@])],
    [],
    [with_openssl=check]
)
TLS_CPPFLAGS=
TLS_LIBS=
ssl_cflags=
ssl_libs=
ssl_dir=$with_openssl
if test "$with_openssl" = check; then
    ssl_dir=`command -v $CXX`
    ssl_dir=`dirname "$ssl_dir"`/..
    test -r "$ssl_dir/include/openssl/ssl.h" || ssl_dir=
fi
if test "$with_openssl" = no; then
    :
elif test -n "$ssl_dir"; then
    ssl_cflags="-I$ssl_dir/include"
    ssl_libs="-L$ssl_dir/lib64 -L$ssl_dir/lib -lssl -lcrypto"
elif test -n "$PKGCONFIG" && "$PKGCONFIG" --exists openssl 2>/dev/null; then
    ssl_cflags=`"$PKGCONFIG" --cflags openssl`
    ssl_libs=`"$PKGCONFIG" --libs openssl`
else
    ssl_libs="-lssl -lcrypto"
fi
if test -n "$ssl_libs"; then
    save_CPPFLAGS=$CPPFLAGS
    save_LIBS=$LIBS
    CPPFLAGS="$CPPFLAGS $ssl_cflags"
    LIBS="$ssl_libs $LIBS"
    AC_MSG_CHECKING([for OpenSSL 3.5 or newer])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <openssl/ssl.h>
#if OPENSSL_VERSION_NUMBER < 0x30500000L
#error OpenSSL too old
#endif]], [[
SSL_CTX *ctx = SSL_CTX_new(TLS_method());
SSL *ssl = SSL_new(ctx);
(void)SSL_get0_group_name(ssl);
SSL_free(ssl);
SSL_CTX_free(ctx);
]])],
	[AC_MSG_RESULT([yes])
	 TLS_CPPFLAGS="-DBLISTER_TLS $ssl_cflags"
	 TLS_LIBS=$ssl_libs],
	[AC_MSG_RESULT([no])
	 test "$with_openssl" = check ||
	    AC_MSG_ERROR([OpenSSL 3.5 or newer not found in $with_openssl])])
    CPPFLAGS=$save_CPPFLAGS
    LIBS=$save_LIBS
fi
AC_SUBST([TLS_CPPFLAGS])
AC_SUBST([TLS_LIBS])

# The remaining flag logic mirrors CMakeLists.txt's per-compiler,
# per-version selection so both build systems compile with the same
# options. ($compiler_clang was already determined above, ahead of LT_INIT.)
gcc_major=0
if test "$compiler_clang" != yes; then
    gcc_major=`$CXX -dumpfullversion 2>/dev/null | cut -d. -f1`
    test -n "$gcc_major" || gcc_major=`$CXX -dumpversion | cut -d. -f1`
fi

AC_MSG_CHECKING([for compiler optimizations])
AC_ARG_ENABLE([optimize],
    [AS_HELP_STRING([--enable-optimize@<:@=CFLAGS@:>@],[C++ compiler optimizations @<:@default=-O3@:>@])],
    [
	if test "$enable_optimize" = no -o "$enable_optimize" = debug; then
	    optimize="-O1 -fno-omit-frame-pointer -fno-optimize-sibling-calls -ggdb -gz -D_DEBUG"
	    build_debug=yes
	elif test "$enable_optimize" = yes; then
	    optimize="$OPTIMIZE"
	    build_debug=no
	else
	    optimize="$enable_optimize"
	    build_debug=no
	fi
    ],
    [optimize="$OPTIMIZE"
     build_debug=no]
)
AC_MSG_RESULT([$optimize])
AC_SUBST([optimize])

# mirrors CMake's CHECK_TSAN; the fortify flags are SANITIZE_FLAGS' default
# whenever a sanitizer build isn't requested
AC_ARG_ENABLE([tsan],
    [AS_HELP_STRING([--enable-tsan@<:@=SANITIZER@:>@],[sanitizer build: -fsanitize=SANITIZER @<:@default=thread@:>@])],
    [],
    [enable_tsan=no]
)
case $enable_tsan in
    no) SANITIZE_FLAGS="-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3" ;;
    yes|on|true|1) SANITIZE_FLAGS="-fsanitize=thread -fno-omit-frame-pointer" ;;
    *) SANITIZE_FLAGS="-fsanitize=$enable_tsan -fno-omit-frame-pointer" ;;
esac
COMMON_CFLAGS="$SANITIZE_FLAGS -ffast-math -march=native -pipe -Wall -Wconversion -Werror -Wextra -Wno-attributes -Wformat=2 -Wno-format-nonliteral -Wformat-security -Wno-format-y2k -Wmultichar -Wno-pragmas -Wredundant-decls -Wsign-conversion -Wstrict-aliasing -Wstrict-overflow=2 -Wno-unknown-pragmas -Wwrite-strings -fvisibility=hidden"
COMMON_CXXFLAGS="-fno-exceptions -fno-rtti -Wno-deprecated -Wno-deprecated-declarations -Wnon-virtual-dtor -Woverloaded-virtual -Wsign-promo -fvisibility-inlines-hidden"
COMMON_LDFLAGS="$SANITIZE_FLAGS"
SHARED_LDFLAGS=

if test "$compiler_clang" = yes; then
    COMMON_CFLAGS="$COMMON_CFLAGS -fno-standalone-debug -Wdouble-promotion -Wnull-dereference -Wno-null-pointer-subtraction -Wodr -Wshadow -Wno-unknown-warning-option"
    COMMON_CXXFLAGS="$COMMON_CXXFLAGS -Wno-c++11-extensions -Wextra-semi"
    COMMON_LDFLAGS="$COMMON_LDFLAGS -fno-plt"
    if test "$(uname -s)" != Darwin; then
	SHARED_LDFLAGS="-Wl,-Bsymbolic-functions"
    fi
    lto_flag="-flto=thin"
else
    if test "$gcc_major" -ge 5; then
	COMMON_CFLAGS="$COMMON_CFLAGS -fmax-errors=8 -fno-semantic-interposition -fstack-protector-strong -Wdouble-promotion -Wformat-overflow=2 -Wformat-signedness -Wformat-truncation=2 -Wlogical-op -Wodr -Wshadow -Wstack-usage=16384 -Wtrampolines"
    fi
    if test "$gcc_major" -ge 6; then
	COMMON_CFLAGS="$COMMON_CFLAGS -Wduplicated-branches -Wduplicated-cond -Wnull-dereference -Wstringop-overflow=3"
	COMMON_LDFLAGS="$COMMON_LDFLAGS -fno-plt"
    fi
    if test "$gcc_major" -ge 7; then
	COMMON_CFLAGS="$COMMON_CFLAGS -fstack-clash-protection"
	case "$(uname -m)" in
	x86_64|amd64|i[[3-6]]86) COMMON_CFLAGS="$COMMON_CFLAGS -fcf-protection=full";;
	esac
    fi
    if test "$gcc_major" -ge 8; then
	COMMON_CXXFLAGS="$COMMON_CXXFLAGS -Wextra-semi"
    fi
    if test "$gcc_major" -ge 13; then
	COMMON_CFLAGS="$COMMON_CFLAGS -fstrict-flex-arrays=2"
    fi
    COMMON_LDFLAGS="$COMMON_LDFLAGS -Wl,--as-needed,-gc-sections,-z,relro"
    SHARED_LDFLAGS="-Wl,--no-undefined,-Bsymbolic-functions"
    lto_flag="-flto=auto"
fi

# profile-guided optimization, as CMake's PGO setting; profiles live in .pgo
AC_ARG_WITH([pgo],
    [AS_HELP_STRING([--with-pgo=generate|use],[profile-guided optimization using profiles in .pgo])],
    [],
    [with_pgo=no]
)
pgo_dir=$ac_pwd/.pgo
case $with_pgo in
    no) ;;
    generate)
	COMMON_CFLAGS="$COMMON_CFLAGS -fprofile-generate=$pgo_dir -fprofile-update=atomic" ;;
    use)
	if test "$compiler_clang" = yes; then
	    COMMON_CFLAGS="$COMMON_CFLAGS -fprofile-use=$pgo_dir/default.profdata"
	else
	    COMMON_CFLAGS="$COMMON_CFLAGS -fprofile-use=$pgo_dir -fprofile-partial-training -Wno-missing-profile"
	fi ;;
    *) AC_MSG_ERROR([--with-pgo must be generate or use]) ;;
esac

# mirror CMakeLists.txt's check_ipo_supported(): only try LTO for a
# non-debug, non-sanitizer build, and only keep it if the compiler/linker
# actually accept the flag
LTO_CFLAGS=
LTO_LDFLAGS=
if test "$build_debug" != yes -a "$enable_tsan" = no; then
    save_CFLAGS=$CFLAGS
    CFLAGS="$CFLAGS $lto_flag"
    AC_MSG_CHECKING([whether $CC supports $lto_flag])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([], [])],
	[AC_MSG_RESULT([yes])
	 LTO_CFLAGS="$lto_flag"],
	[AC_MSG_RESULT([no])])
    CFLAGS=$save_CFLAGS
    if test -n "$LTO_CFLAGS" -a "$compiler_clang" = yes -a \
	"$(uname -s)" = Darwin; then
	LTO_LDFLAGS="-Wl,-cache_path_lto,$ac_pwd/.lto"
    elif test -n "$LTO_CFLAGS" -a "$compiler_clang" != yes -a \
	"$gcc_major" -ge 15; then
	mkdir -p .lto
	LTO_LDFLAGS="-flto-incremental=$ac_pwd/.lto"
    fi
fi

AM_CFLAGS="$AM_CFLAGS -std=gnu23 $COMMON_CFLAGS $optimize $LTO_CFLAGS"
AM_CXXFLAGS="$AM_CXXFLAGS -std=gnu++23 $COMMON_CXXFLAGS $COMMON_CFLAGS $optimize $LTO_CFLAGS"
AM_LDFLAGS="$COMMON_LDFLAGS $LTO_LDFLAGS $LLVM_LDFLAGS"

AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_CXXFLAGS])
AC_SUBST([AM_LDFLAGS])
AC_SUBST([SHARED_LDFLAGS])
AC_SUBST([LIBS])

AC_CONFIG_FILES([Makefile lib/Makefile test/Makefile])

AC_OUTPUT
