project(blister)

set(blister_INCLUDE_SRCS
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

add_library(objlib OBJECT ${blister_LIB_SRCS})
add_library(blister_shared SHARED $<TARGET_OBJECTS:objlib>)
add_library(blister_static STATIC $<TARGET_OBJECTS:objlib>)

set_property(TARGET objlib PROPERTY POSITION_INDEPENDENT_CODE 1)

set_target_properties(blister_shared PROPERTIES OUTPUT_NAME blister)

target_include_directories(objlib PUBLIC include)

install(FILES ${blister_INCLUDE_SRCS} DESTINATION include)

if(WIN32)
    install(TARGETS ${NAME} RUNTIME DESTINATION bin)
else()
    set_target_properties(blister_shared PROPERTIES VERSION 1.4.0 SOVERSION 1)
    install(TARGETS blister_shared ${INSTALL_TARGETS_DEFAULT_ARGS} LIBRARY DESTINATION lib)
endif()

