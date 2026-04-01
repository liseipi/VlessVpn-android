cmake_minimum_required(VERSION 3.10.2)
project("tun2socks")

find_library(log-lib log)

add_library(tun2socks
        SHARED
        tun2socks.cpp)

target_include_directories(tun2socks PRIVATE
        ${CMAKE_SOURCE_DIR}/prebuilt/include)

target_link_libraries(tun2socks
        ${CMAKE_SOURCE_DIR}/prebuilt/lib/${ANDROID_ABI}/libtun2socks.a
        ${log-lib})
