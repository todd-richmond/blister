set(blister_INC_SOURCE
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

set(blister_LIB_SOURCE
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
    list(APPEND blister_LIB_SOURCE Windows.c WindowsCPP.cpp)
else()
    list(APPEND blister_LIB_SOURCE Unix.c)
endif()

add_library(blister_lib OBJECT ${blister_LIB_SOURCE})
set_target_properties(blister_lib PROPERTIES POSITION_INDEPENDENT_CODE 1)
target_include_directories(blister_lib PUBLIC .)
target_cppcheck(blister_lib)

add_library(blister SHARED $<TARGET_OBJECTS:blister_lib>)
target_include_directories(blister PUBLIC $<TARGET_PROPERTY:blister_lib,INCLUDE_DIRECTORIES>)
target_link_libraries(blister INTERFACE ${CMAKE_DL_LIBS} ${CMAKE_THREAD_LIBS_INIT})
if(UNIX AND NOT APPLE)
    target_link_libraries(blister INTERFACE rt)
endif()

add_library(blister_static STATIC $<TARGET_OBJECTS:blister_lib>)
set_target_properties(blister_static PROPERTIES OUTPUT_NAME stdapi)
target_include_directories(blister_static PUBLIC $<TARGET_PROPERTY:blister_lib,INCLUDE_DIRECTORIES>)
target_link_libraries(blister_static INTERFACE $<TARGET_PROPERTY:blister,INTERFACE_LINK_LIBRARIES>)

install(FILES ${blister_INC_SOURCE} DESTINATION include)
if(WIN32)
    install(TARGETS blister RUNTIME DESTINATION bin)
    install(TARGETS blister_static ARCHIVE DESTINATION lib)
else()
    install(TARGETS blister blister_static DESTINATION lib)
endif()

if(NOT APPLE AND COMMAND cotire)
    cotire(blister_lib)
    set_target_properties(blister_lib PROPERTIES COTIRE_ADD_UNITY_BUILD FALSE)
endif()

