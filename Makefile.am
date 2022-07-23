include $(top_srcdir)/build/Makefile.inc

EXTRA_DIST=.cproject .project LICENSE NOTICE \
	build/Blister.sln build/build build/clean \
	build/Blister.xcodeproj/BlisterProj.xcconfig \
	build/Blister.xcodeproj/BlisterTarget.xcconfig \
	build/Blister.xcodeproj/project.pbxproj \
	build/Blister.xcworkspace/contents.xcworkspacedata \
	*/*.vcxproj */*.vcxproj.filters

SUBDIRS = lib test

cppcheck:
	cppcheck --enable=warning,style,performance,portability,information,missingInclude --force --inline-suppr -j 4 -q --template="{file}:{line} {severity}={id} {message}" --suppress=preprocessorErrorDirective --suppress=ConfigurationNotChecked -I lib lib test
