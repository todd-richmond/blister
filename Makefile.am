include $(top_srcdir)/build/Makefile.inc

EXTRA_DIST=.clang-tidy .cppcheck-suppressions CMakeLists.txt CPPLINT.cfg \
	LICENSE NOTICE \
	build/Blister.sln build/build build/clean \
	build/Blister.xcodeproj/project.pbxproj \
	lib/CMakeLists.txt test/CMakeLists.txt */*.vcxproj */*.vcxproj.filters

SUBDIRS = lib test

.PHONY: cppcheck
cppcheck:
	cppcheck --enable=warning,style,performance,portability,missingInclude --force --inline-suppr -j 4 -q --suppressions-list=$(top_srcdir)/.cppcheck-suppressions --template="{file}:{line} {severity}={id} {message}" -I lib lib test
