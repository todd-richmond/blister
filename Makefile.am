include $(top_srcdir)/build/Makefile.inc

EXTRA_DIST=.autotools .cproject .project .settings LICENSE NOTICE \
	build/Blister.sln build/build build/clean build/dist \
	build/Blister.xcodeproj/BlisterProj.xcconfig \
	build/Blister.xcodeproj/BlisterTarget.xcconfig \
	build/Blister.xcodeproj/project.pbxproj \
	build/Blister.xcworkspace/contents.xcworkspacedata \
	*/*.vcproj */*.vcxproj */*.vcxproj.filters

SUBDIRS = lib test

cppcheck:
	cppcheck --enable=all --force --inline-suppr */*.h */*.c */*.cpp
