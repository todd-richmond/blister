project(blister)

set(blister_INC_SRCS
    Config.h
    Dispatch.h
    HTTPClient.h
    HTTPServer.h
    Log.h
    MD5.h
    Service.h
    SMTPClient.h
    Socket.h
    stdapi.h
    Streams.h
    Thread.h
    Timing.h)

set(blister_LIB_SRCS
    Config.cpp
    Dispatch.cpp
    HTTPClient.cpp
    HTTPServer.cpp
    Log.cpp
    MD5.c
    Service.cpp
    Socket.cpp
    SMTPClient.cpp
    Thread.cpp
    Timing.cpp)

if(WIN32)
    set(blister_LIB_SRCS ${blister_LIB_SRCS} Windows.c WindowsCPP.cpp)
else()
    set(blister_LIB_SRCS ${blister_LIB_SRCS} Unix.c)
endif()

add_library(blister_lib OBJECT ${blister_LIB_SRCS})
set_target_properties(blister_lib PROPERTIES POSITION_INDEPENDENT_CODE 1)
target_include_directories(blister_lib PUBLIC .)

add_library(blister SHARED $<TARGET_OBJECTS:blister_lib>)
target_include_directories(blister PUBLIC $<TARGET_PROPERTY:blister_lib,INCLUDE_DIRECTORIES>)

add_library(blister_static STATIC $<TARGET_OBJECTS:blister_lib>)
# set_target_properties(blister_static PROPERTIES OUTPUT_NAME stdapi)
target_include_directories(blister_static PUBLIC $<TARGET_PROPERTY:blister_lib,INCLUDE_DIRECTORIES>)

install(FILES ${blister_INC_SRCS} DESTINATION include)

if(WIN32)
    install(TARGETS blister RUNTIME DESTINATION bin)
else()
    install(TARGETS blister LIBRARY DESTINATION lib)
    install(TARGETS blister_static ARCHIVE DESTINATION lib)
endif()

