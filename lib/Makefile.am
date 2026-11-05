include $(top_srcdir)/build/Makefile.inc

EXTRA_DIST = Version.rc Windows.cpp

include_HEADERS = Config.h Dispatch.h HTTPClient.h HTTPServer.h Log.h \
	LRUCache.h stdapi.h Service.h SMTPClient.h ResourcePool.h \
	Socket.h Streams.h Thread.h Timing.h

lib_LTLIBRARIES = libblister.la

libblister_la_SOURCES = Config.cpp Dispatch.cpp \
	HTTPClient.cpp HTTPServer.cpp Log.cpp Service.cpp SMTPClient.cpp \
	Socket.cpp Thread.cpp Timing.cpp Unix.c

libblister_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILD_BLISTER
libblister_la_LDFLAGS = $(AM_LDFLAGS) $(SHARED_LDFLAGS) -avoid-version

