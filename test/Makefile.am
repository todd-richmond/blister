include $(top_srcdir)/build/Makefile.inc

AM_CPPFLAGS = -I../lib
AM_LDFLAGS = -L../lib -lblister

bin_PROGRAMS = cfg daemonize dlog dtiming httpload smtpload
noinst_PROGRAMS = echotest httpd
sysconf_DATA = http.wld smtp.wld

cfg_SOURCES = Cfg.cpp
cfg_LDFLAGS = $(AM_LDFLAGS) -static
daemonize_SOURCES = Daemonize.cpp
daemonize_LDFLAGS = $(AM_LDFLAGS) -static
dlog_SOURCES = DLog.cpp
dlog_LDFLAGS = $(AM_LDFLAGS) -static
dtiming_SOURCES = DTiming.cpp
echotest_SOURCES = EchoTest.cpp
httpd_SOURCES = HTTPd.cpp
httpload_SOURCES = HTTPLoad.cpp
httpload_LDFLAGS = $(AM_LDFLAGS) -static
smtpload_SOURCES = SMTPLoad.cpp
smtpload_LDFLAGS = $(AM_LDFLAGS) -static

