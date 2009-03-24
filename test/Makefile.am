include $(top_srcdir)/build/Makefile.inc

CPPFLAGS = -I../lib
LDFLAGS = -L../lib -lblister

bin_PROGRAMS = cfg dlog httpload smtpload
noinst_PROGRAMS = echotest httpd
sysconf_DATA = http.wld smtp.wld

cfg_SOURCES = Cfg.cpp
cfg_LDFLAGS = -static
dlog_SOURCES = DLog.cpp
dlog_LDFLAGS = -static
echotest_SOURCES = EchoTest.cpp
httpd_SOURCES = HTTPd.cpp
httpload_SOURCES = HTTPLoad.cpp
httpload_LDFLAGS = -static
smtpload_SOURCES = SMTPLoad.cpp
smtpload_LDFLAGS = -static

