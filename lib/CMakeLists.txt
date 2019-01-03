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

add_library(blister_obj OBJECT ${blister_LIB_SOURCE})
set_target_properties(blister_obj PROPERTIES POSITION_INDEPENDENT_CODE 1)
target_compile_definitions(blister_obj PRIVATE BUILD_BLISTER)
target_include_directories(blister_obj PUBLIC .)
target_cppcheck(blister_obj)
target_cpplint(blister_obj ${blister_INC_SOURCE})

if(BLISTER_DLL)
    add_library(blister SHARED $<TARGET_OBJECTS:blister_obj>)
    target_include_directories(blister PUBLIC $<TARGET_PROPERTY:blister_obj,INCLUDE_DIRECTORIES>)
    target_link_libraries(blister ${CMAKE_DL_LIBS} ${CMAKE_THREAD_LIBS_INIT})
    if(UNIX AND NOT APPLE)
	target_link_libraries(blister ${SYSTEM_RT_LIB})
    endif()
endif()

if(BLISTER_LIB)
    add_library(blister_static STATIC $<TARGET_OBJECTS:blister_obj>)
    set_target_properties(blister_static PROPERTIES OUTPUT_NAME blister)
    target_include_directories(blister_static PUBLIC $<TARGET_PROPERTY:blister_obj,INCLUDE_DIRECTORIES>)
    if(BLISTER_DLL)
	target_link_libraries(blister_static INTERFACE $<TARGET_PROPERTY:blister,INTERFACE_LINK_LIBRARIES>)
    else()
	add_library(blister ALIAS blister_static)
    endif()
else()
    add_library(blister_static ALIAS blister)
endif()

install(FILES ${blister_INC_SOURCE} DESTINATION include)
if(WIN32)
    if(BLISTER_DLL)
	install(TARGETS blister RUNTIME DESTINATION bin)
    endif()
    if(BLISTER_LIB)
	install(TARGETS blister_static ARCHIVE DESTINATION lib)
    endif()
else()
    install(TARGETS blister blister_static DESTINATION lib)
endif()

cotire(blister_obj)

