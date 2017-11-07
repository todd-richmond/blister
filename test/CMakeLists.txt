include_directories(${blister_SOURCE_DIR})

find_package(Threads)

set(COMMON_LIBS ${CMAKE_DL_LIBS} ${CMAKE_THREAD_LIBS_INIT})
if(UNIX AND NOT APPLE)
    set(COMMON_LIBS ${COMMON_LIBS} rt)
endif()

add_executable(cfg Cfg.cpp)
target_link_libraries(cfg blister_static ${COMMON_LIBS})

add_executable(daemonize Daemonize.cpp)
target_link_libraries(daemonize blister_static ${COMMON_LIBS})

add_executable(dlog DLog.cpp)
target_link_libraries(dlog blister_static ${COMMON_LIBS})

add_executable(dtiming DTiming.cpp)
target_link_libraries(dtiming blister_shared ${COMMON_LIBS})

add_executable(httpload HTTPLoad.cpp)
target_link_libraries(httpload blister_static ${COMMON_LIBS})

add_executable(smtpload SMTPLoad.cpp)
target_link_libraries(smtpload blister_static ${COMMON_LIBS})

add_executable(echotest EchoTest.cpp)
target_link_libraries(echotest blister_shared ${COMMON_LIBS})

add_executable(httpd HTTPd.cpp)
target_link_libraries(httpd blister_shared ${COMMON_LIBS})

install(FILES *.wld DESTINATION etc)
install(TARGETS cfg daemonize dlog httpload smtpload DESTINATION bin)

