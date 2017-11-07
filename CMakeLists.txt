cmake_minimum_required(VERSION 2.8.12)
project (Blister)

set(CMAKE_MACOSX_RPATH 1)

# set(CMAKE_CXX_STANDARD 11)
IF(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
    set(COMMON_C_FLAGS "-pipe -Wall -Werror -Wformat=2 -Wno-format-nonliteral -Wno-format-y2k -Wstrict-aliasing=2 -Wwrite-strings")
    set(COMMON_CXX_FLAGS "${COMMON_C_FLAGS} -fno-exceptions -fno-rtti -Wno-deprecated")
else()
endif()

add_subdirectory(lib)
add_subdirectory(test)

