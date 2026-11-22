include $(top_srcdir)/build/Makefile.inc

AM_CPPFLAGS = -I$(top_srcdir)/lib
LDADD = $(top_builddir)/lib/libblister.la
TLS_LDADD = $(top_builddir)/lib/libblistertls.la $(LDADD)

# load tools linked statically, as CMake's blistertls_static
STATIC_LINK = $(AM_LDFLAGS) -static

bin_PROGRAMS = cfg daemonize dlog httpload smtpload smtpsink
noinst_PROGRAMS = dtiming echotest httptest uhttpd
check_PROGRAMS = hashtest
noinst_HEADERS = Load.h TestUtil.h
sysconf_DATA = http.wld smtp.wld
EXTRA_DIST = httpd.cfg
TESTS = hashtest

cfg_SOURCES = Cfg.cpp
daemonize_SOURCES = Daemonize.cpp
dlog_SOURCES = DLog.cpp
dtiming_SOURCES = DTiming.cpp
echotest_SOURCES = EchoTest.cpp
echotest_LDADD = $(TLS_LDADD)
hashtest_SOURCES = HashTest.cpp
httpload_SOURCES = HTTPLoad.cpp
httpload_LDADD = $(TLS_LDADD)
httpload_LDFLAGS = $(STATIC_LINK)
httptest_SOURCES = HTTPTest.cpp
httptest_LDADD = $(TLS_LDADD)
smtpload_SOURCES = SMTPLoad.cpp
smtpload_LDADD = $(TLS_LDADD)
smtpload_LDFLAGS = $(STATIC_LINK)
smtpsink_SOURCES = SMTPSink.cpp
smtpsink_LDADD = $(TLS_LDADD)
smtpsink_LDFLAGS = $(STATIC_LINK)
uhttpd_SOURCES = HTTPd.cpp
uhttpd_LDADD = $(TLS_LDADD)

if HAVE_LIBUV
noinst_PROGRAMS += uvechotest
uvechotest_SOURCES = UVEchoTest.cpp
uvechotest_CPPFLAGS = $(AM_CPPFLAGS) $(LIBUV_CFLAGS)
uvechotest_LDADD = $(top_builddir)/lib/libblister.la $(LIBUV_LIBS)
endif
