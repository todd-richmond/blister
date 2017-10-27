include $(top_srcdir)/build/Makefile.inc

AM_CPPFLAGS = -I../lib
AM_LDFLAGS = -L../lib -lblister

bin_PROGRAMS = cfg daemonize dlog dtiming httpload smtpload
noinst_PROGRAMS = echotest httpd
sysconf_DATA = *.wld
EXTRA_DIST=*.cfg *.wld

cfg_SOURCES = Cfg.cpp
daemonize_SOURCES = Daemonize.cpp
dlog_SOURCES = DLog.cpp
dlog_LDFLAGS = $(AM_LDFLAGS) -static
dtiming_SOURCES = DTiming.cpp
echotest_SOURCES = EchoTest.cpp
httpd_SOURCES = HTTPd.cpp
httpload_SOURCES = HTTPLoad.cpp
smtpload_SOURCES = SMTPLoad.cpp

