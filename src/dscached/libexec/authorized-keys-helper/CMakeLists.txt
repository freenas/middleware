cmake_minimum_required(VERSION 2.8)

project (authorized-keys-helper)
set(CMAKE_BUILD_TYPE Debug)

find_package (Threads)
find_package(PkgConfig)

pkg_check_modules(JANSSON REQUIRED jansson)
pkg_search_module(JANSSON jansson)
include_directories(${JANSSON_INCLUDE_DIRS})
link_directories(${JANSSON_LIBRARY_DIRS})

add_executable(authorized-keys-helper authorized-keys-helper.c)
target_link_libraries(authorized-keys-helper /usr/local/lib/libdispatcherclient.so)
target_link_libraries(authorized-keys-helper ${JANSSON_LIBRARIES})
target_link_libraries(authorized-keys-helper ${CMAKE_THREAD_LIBS_INIT})
include_directories(/usr/local/include)

install(TARGETS authorized-keys-helper RUNTIME DESTINATION libexec)
