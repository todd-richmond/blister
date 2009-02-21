include $(top_srcdir)/build/Makefile.inc

CPPFLAGS = -I../lib
LDFLAGS = -L../lib -lblister

noinst_PROGRAMS = dlog echotest httpd httpload smtpload
sysconf_DATA = http.wld smtp.wld

dlog_SOURCES = DLog.cpp
dlog_LDFLAGS = -static
echotest_SOURCES = EchoTest.cpp
httpd_SOURCES = HTTPd.cpp
httpload_SOURCES = HTTPLoad.cpp
httpload_LDFLAGS = -static
smtpload_SOURCES = SMTPLoad.cpp
smtpload_LDFLAGS = -static

