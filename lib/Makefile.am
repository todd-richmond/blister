include $(top_srcdir)/build/Makefile.inc

lib_LTLIBRARIES = libblister.la

libblister_la_SOURCES = Config.cpp Dispatch.cpp \
	HTTPClient.cpp HTTPServer.cpp Log.cpp MD5.c Service.cpp \
	Socket.cpp SMTPClient.cpp Thread.cpp Timing.cpp Unix.c

libblister_la_CXXFLAGS = $(AM_CXXFLAGS) -Wno-format-y2k
libblister_la_LDFLAGS = -avoid-version

