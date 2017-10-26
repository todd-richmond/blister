include $(top_srcdir)/build/Makefile.inc

EXTRA_DIST=Version.rc Windows.c WindowsCPP.cpp

pkginclude_HEADERS = Config.h Dispatch.h HTTPClient.h HTTPServer.h Log.h MD5.h \
	stdapi.h Service.h SMTPClient.h Socket.h Streams.h Thread.h Timing.h

lib_LTLIBRARIES = libblister.la

libblister_la_SOURCES = Config.cpp Dispatch.cpp \
	HTTPClient.cpp HTTPServer.cpp Log.cpp MD5.c Service.cpp \
	Socket.cpp SMTPClient.cpp Thread.cpp Timing.cpp Unix.c

libblister_la_LDFLAGS = -avoid-version

