add_executable(cfg Cfg.cpp)
target_link_libraries(cfg blister_static)

add_executable(daemonize Daemonize.cpp)
target_link_libraries(daemonize blister_static)
if(CMAKE_COMPILER_IS_GNUCXX AND NOT CHECK_CLANG_TIDY)
    target_compile_options(daemonize PRIVATE -Werror=stack-usage=12288)
endif()

add_executable(dlog DLog.cpp)
target_link_libraries(dlog blister_static)

add_executable(dtiming DTiming.cpp)
target_link_libraries(dtiming blister)

add_executable(echotest EchoTest.cpp)
target_link_libraries(echotest blistertls)

add_executable(httptest HTTPTest.cpp)
target_link_libraries(httptest blistertls)

add_executable(httpload HTTPLoad.cpp)
target_link_libraries(httpload blistertls_static)

add_executable(smtpload SMTPLoad.cpp)
target_link_libraries(smtpload blistertls_static)

add_executable(smtpsink SMTPSink.cpp)
target_link_libraries(smtpsink blistertls_static)

add_executable(uhttpd HTTPd.cpp)
target_link_libraries(uhttpd blistertls)

add_executable(hashtest HashTest.cpp)
set_target_properties(hashtest PROPERTIES EXCLUDE_FROM_ALL TRUE)
target_link_libraries(hashtest blister)

if(LIBUV_INCLUDE_DIR AND LIBUV_LIBRARY)
    add_executable(uvechotest UVEchoTest.cpp)
    target_include_directories(uvechotest SYSTEM PRIVATE ${LIBUV_INCLUDE_DIR})
    target_link_libraries(uvechotest blister ${LIBUV_LIBRARY})
    if(COMPILE_PCH)
	target_precompile_headers(uvechotest REUSE_FROM cfg)
    endif()
endif()

# hashtest is EXCLUDE_FROM_ALL, so ctest builds it first
add_test(NAME HashTestBuild COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}
    --target hashtest --config $<CONFIG>)
set_tests_properties(HashTestBuild PROPERTIES FIXTURES_SETUP hashtest)
add_test(NAME HashFunctors COMMAND hashtest)
set_tests_properties(HashFunctors PROPERTIES FIXTURES_REQUIRED hashtest)
add_test(NAME EchoTest COMMAND echotest -h unix:./echotest.sock -l 1000000)
add_test(NAME HTTPTest COMMAND httptest -h unix:./httptest.sock -l 1000000)
if(TLS_LIBS)
    add_test(NAME EchoTestTLS
	COMMAND echotest -h unix:./echotest-tls.sock -l 500000 -ssl)
    add_test(NAME HTTPTestTLS
	COMMAND httptest -h unix:./httptest-tls.sock -l 500000 -ssl)
endif()

if(COMPILE_PCH)
    target_precompile_headers(cfg PRIVATE [["stdapi.h"]])
    target_precompile_headers(daemonize REUSE_FROM cfg)
    target_precompile_headers(dlog REUSE_FROM cfg)
    target_precompile_headers(dtiming REUSE_FROM cfg)
    target_precompile_headers(echotest REUSE_FROM cfg)
    target_precompile_headers(httpload REUSE_FROM cfg)
    target_precompile_headers(httptest REUSE_FROM cfg)
    target_precompile_headers(smtpload REUSE_FROM cfg)
    target_precompile_headers(smtpsink REUSE_FROM cfg)
    target_precompile_headers(uhttpd REUSE_FROM cfg)
    target_precompile_headers(hashtest REUSE_FROM cfg)
endif()

install(FILES http.wld smtp.wld DESTINATION etc)
install(TARGETS cfg daemonize dlog httpload smtpload smtpsink DESTINATION bin)


# executables, not DLLs, set the process code page
if(WIN32)
    get_property(targets DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
    foreach(target ${targets})
	get_target_property(type ${target} TYPE)
	if(type STREQUAL "EXECUTABLE")
	    target_sources(${target} PRIVATE ${PROJECT_SOURCE_DIR}/lib/utf8.manifest)
	endif()
    endforeach()
endif()
