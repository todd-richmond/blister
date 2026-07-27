include $(top_srcdir)/build/Makefile.inc

AM_CPPFLAGS = -I$(top_srcdir)/lib
LDADD = $(top_builddir)/lib/libblister.la

bin_PROGRAMS = cfg daemonize dlog dtiming httpload smtpload
noinst_PROGRAMS = echotest httpd hashtest
sysconf_DATA = http.wld smtp.wld
EXTRA_DIST = echo.cfg httpd.cfg

cfg_SOURCES = Cfg.cpp
daemonize_SOURCES = Daemonize.cpp
dlog_SOURCES = DLog.cpp
dlog_LDFLAGS = $(AM_LDFLAGS) -static
dtiming_SOURCES = DTiming.cpp
echotest_SOURCES = EchoTest.cpp
hashtest_SOURCES = HashTest.cpp
httpd_SOURCES = HTTPd.cpp
httpload_SOURCES = HTTPLoad.cpp
smtpload_SOURCES = SMTPLoad.cpp

if HAVE_LIBUV
noinst_PROGRAMS += uvechotest
uvechotest_SOURCES = UVEchoTest.cpp
uvechotest_CPPFLAGS = $(AM_CPPFLAGS) $(LIBUV_CFLAGS)
uvechotest_LDADD = $(top_builddir)/lib/libblister.la $(LIBUV_LIBS)
endif
