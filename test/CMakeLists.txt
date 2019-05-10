add_executable(cfg Cfg.cpp)
target_link_libraries(cfg blister_static)

add_executable(daemonize Daemonize.cpp)
target_link_libraries(daemonize blister_static)

add_executable(dlog DLog.cpp)
target_link_libraries(dlog blister_static)

add_executable(dtiming DTiming.cpp)
target_link_libraries(dtiming blister)

add_executable(echotest EchoTest.cpp)
target_link_libraries(echotest blister)

add_executable(httpd HTTPd.cpp)
target_link_libraries(httpd blister)

add_executable(httpload HTTPLoad.cpp)
target_link_libraries(httpload blister_static)

add_executable(smtpload SMTPLoad.cpp)
target_link_libraries(smtpload blister_static)

analyze(cfg daemonize dlog dtiming echotest httpd httpload smtpload)

install(FILES http.wld smtp.wld DESTINATION etc)
install(TARGETS cfg daemonize dlog httpload smtpload DESTINATION bin)
