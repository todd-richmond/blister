cmake_minimum_required(VERSION 2.8.12)
project (Blister C CXX)

find_package(Threads QUIET)
find_program(CMAKE_CPPCHECK NAMES cppcheck PATHS ENV PATH)

if(CMAKE_BUILD_TYPE STREQUAL "")
    set(CMAKE_BUILD_TYPE Debug)
endif()
set(CMAKE_MACOSX_RPATH 1)

# set(CMAKE_CXX_STANDARD 11)
IF(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
    set(COMMON_C_FLAGS "-pipe -Wall -Werror -Wformat=2 -Wno-format-nonliteral -Wno-format-y2k -Wstrict-aliasing=2 -Wwrite-strings")
    set(COMMON_C_FLAGS_DEBUG "-O1 -fno-omit-frame-pointer -D_DEBUG")
    set(COMMON_C_FLAGS_MINSIZEREL "")
    set(COMMON_C_FLAGS_RELEASE "-O3")
    set(COMMON_C_FLAGS_RELWITHDEBINFO "-g -O3")
    set(COMMON_CXX_FLAGS "${COMMON_C_FLAGS} -fno-exceptions -fno-rtti -Wno-deprecated")
    # CXX CMAKE_BUILD_TYPE flags are not always set
    set(COMMON_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${COMMON_C_FLAGS_DEBUG}")
    set(COMMON_CXX_FLAGS_MINSIZEREL "${CMAKE_C_FLAGS_MINSIZEREL} ${COMMON_C_FLAGS_MINSIZEREL}")
    set(COMMON_CXX_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${COMMON_C_FLAGS_RELEASE}")
    set(COMMON_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} ${COMMON_C_FLAGS_RELWITHDEBINFO}")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMMON_C_FLAGS}")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${COMMON_C_FLAGS_DEBUG}")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${COMMON_C_FLAGS_RELEASE}")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} ${COMMON_C_FLAGS_RELWITHDEBINFO}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COMMON_CXX_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${COMMON_CXX_FLAGS_DEBUG}")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${COMMON_CXX_FLAGS_RELEASE}")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} ${COMMON_CXX_FLAGS_RELWITHDEBINFO}")

# cppcheck support
list(APPEND cppcheck_args --enable=warning,style,performance,portability,information,missingInclude --force --inline-suppr -j 4 -q --template="{file}:{line} {severity}={id} {message}")
list(APPEND cppcheck_suppressions ConfigurationNotChecked cstyleCast noExplicitConstructor postfixOperator preprocessorErrorDirective uninitMemberVar unmatchedSuppression unreadVariable variableScope)
foreach(suppression ${cppcheck_suppressions})
    list(APPEND cppcheck_args --suppress=${suppression})
endforeach()

function(target_cppcheck target)
    if(NOT TARGET ${target})
        message(FATAL_ERROR "cppcheck target does not exist: ${target}")
    elseif(NOT CMAKE_CPPCHECK STREQUAL CMAKE_CPPCHECK-NOTFOUND)
        get_target_property(includes ${target} INCLUDE_DIRECTORIES)
        set(cppcheck_includes)
        foreach(include ${includes})
	    if(NOT include STREQUAL includes-NOTFOUND)
		list(APPEND cppcheck_includes "-I${include}")
	    endif()
        endforeach()
        get_target_property(sources ${target} SOURCES)
        set(cppcheck_files)
        foreach(source ${sources})
            get_source_file_property(cppcheck_lang ${source} LANGUAGE)
            get_source_file_property(cppcheck_loc ${source} LOCATION)
            if(cppcheck_lang AND ((cppcheck_lang STREQUAL C) OR (cppcheck_lang STREQUAL CXX)))
                list(APPEND cppcheck_files ${cppcheck_loc})
            endif()
        endforeach()
        add_custom_target(${target}_cppcheck
            COMMAND ${CMAKE_CPPCHECK} ${cppcheck_args} ${cppcheck_includes} ${cppcheck_files}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            COMMENT "Running cppcheck on ${target}" VERBATIM)
        add_dependencies(cppcheck ${target}_cppcheck)
    endif()
endfunction()

function(cppcheck)
    foreach(target ${ARGN})
        target_cppcheck(${target})
    endforeach()
endfunction()

if(CMAKE_CPPCHECK STREQUAL CMAKE_CPPCHECK-NOTFOUND)
    add_custom_target(cppcheck COMMENT "cppcheck not available")
else()
    add_custom_target(cppcheck COMMENT "C/C++ static code analysis")
endif()
set_target_properties(cppcheck PROPERTIES EXCLUDE_FROM_ALL TRUE)

# distclean equivalent
# set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES CMakeCache.txt CMakeFiles cmake_install.cmake)
add_custom_target(distclean)
add_custom_command(
    COMMENT "Cleaning distribution"
    COMMAND $(MAKE) clean
    COMMAND find . -name CMakeFiles -o -name CMakeCache.txt -o -name cmake_install.cmake -o -name Makefile | xargs rm -rf
    TARGET distclean)

add_subdirectory(lib)
add_subdirectory(test)

