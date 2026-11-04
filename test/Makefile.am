include $(top_srcdir)/build/Makefile.inc

AM_CPPFLAGS = -I$(top_srcdir)/lib
LDADD = $(top_builddir)/lib/libblister.la

# tools linked against the static library, as CMake's blister_static
STATIC_LINK = $(AM_LDFLAGS) -static

bin_PROGRAMS = cfg daemonize dlog httpload smtpload smtpsink
noinst_PROGRAMS = dtiming echotest httptest uhttpd
check_PROGRAMS = hashtest
noinst_HEADERS = Load.h
sysconf_DATA = http.wld smtp.wld
EXTRA_DIST = httpd.cfg
TESTS = hashtest

cfg_SOURCES = Cfg.cpp
cfg_LDFLAGS = $(STATIC_LINK)
daemonize_SOURCES = Daemonize.cpp
daemonize_LDFLAGS = $(STATIC_LINK)
dlog_SOURCES = DLog.cpp
dlog_LDFLAGS = $(STATIC_LINK)
dtiming_SOURCES = DTiming.cpp
echotest_SOURCES = EchoTest.cpp
hashtest_SOURCES = HashTest.cpp
httpload_SOURCES = HTTPLoad.cpp
httpload_LDFLAGS = $(STATIC_LINK)
httptest_SOURCES = HTTPTest.cpp
smtpload_SOURCES = SMTPLoad.cpp
smtpload_LDFLAGS = $(STATIC_LINK)
smtpsink_SOURCES = SMTPSink.cpp
smtpsink_LDFLAGS = $(STATIC_LINK)
uhttpd_SOURCES = HTTPd.cpp

if HAVE_LIBUV
noinst_PROGRAMS += uvechotest
uvechotest_SOURCES = UVEchoTest.cpp
uvechotest_CPPFLAGS = $(AM_CPPFLAGS) $(LIBUV_CFLAGS)
uvechotest_LDADD = $(top_builddir)/lib/libblister.la $(LIBUV_LIBS)
endif
