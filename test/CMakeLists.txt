add_executable(cfg Cfg.cpp)
target_link_libraries(cfg blister_static)

add_executable(daemonize Daemonize.cpp)
target_link_libraries(daemonize blister_static)
if(CMAKE_COMPILER_IS_GNUCXX)
    target_link_libraries(daemonize -Werror=stack-usage=12288)
endif()

add_executable(dlog DLog.cpp)
target_link_libraries(dlog blister_static)

add_executable(dtiming DTiming.cpp)
target_link_libraries(dtiming blister)

add_executable(echotest EchoTest.cpp)
target_link_libraries(echotest blister)

add_executable(httpload HTTPLoad.cpp)
target_link_libraries(httpload blister_static)

add_executable(smtpload SMTPLoad.cpp)
target_link_libraries(smtpload blister_static)

add_executable(uhttpd HTTPd.cpp)
target_link_libraries(uhttpd blister)

if(COMPILE_PCH AND NOT CMAKE_VERSION VERSION_LESS 3.16)
    target_precompile_headers(cfg PRIVATE [["stdapi.h"]])
    target_precompile_headers(daemonize REUSE_FROM cfg)
    target_precompile_headers(dlog REUSE_FROM cfg)
    target_precompile_headers(dtiming REUSE_FROM cfg)
    target_precompile_headers(echotest REUSE_FROM cfg)
    target_precompile_headers(httpload REUSE_FROM cfg)
    target_precompile_headers(smtpload REUSE_FROM cfg)
    target_precompile_headers(uhttpd REUSE_FROM cfg)
endif()

install(FILES http.wld smtp.wld DESTINATION etc)
install(TARGETS cfg daemonize dlog httpload smtpload DESTINATION bin)

