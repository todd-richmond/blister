include_directories(${blister_SOURCE_DIR})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMMON_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COMMON_CXX_FLAGS}")

add_executable(cfg Cfg.cpp)
target_link_libraries(cfg LINK_PUBLIC blister_static)

add_executable(daemonize Daemonize.cpp)
target_link_libraries(daemonize LINK_PUBLIC blister_static)

add_executable(dlog DLog.cpp)
target_link_libraries(dlog LINK_PUBLIC blister_static)

add_executable(dtiming DTiming.cpp)
target_link_libraries(dtiming LINK_PUBLIC blister_shared)

add_executable(httpload HTTPLoad.cpp)
target_link_libraries(httpload LINK_PUBLIC blister_static)

add_executable(smtpload SMTPLoad.cpp)
target_link_libraries(smtpload LINK_PUBLIC blister_static)

add_executable(echotest EchoTest.cpp)
target_link_libraries(echotest LINK_PUBLIC blister_shared)

add_executable(httpd HTTPd.cpp)
target_link_libraries(httpd LINK_PUBLIC blister_shared)

install(FILES *.wld DESTINATION etc)
install(TARGETS cfg daemonize dlog httpload smtpload DESTINATION bin)

