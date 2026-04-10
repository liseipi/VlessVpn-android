cmake_minimum_required(VERSION 4.1.2)   # 提升到较新版本，更稳定

project("tun2socks")

# 查找 log 库
find_library(log-lib log)

# 添加共享库
add_library(tun2socks
        SHARED
        tun2socks.cpp)

# 包含头文件（如果有 prebuilt/include）
target_include_directories(tun2socks PRIVATE
        ${CMAKE_SOURCE_DIR}/prebuilt/include)

# 链接预编译的静态库 + log
target_link_libraries(tun2socks
        ${CMAKE_SOURCE_DIR}/prebuilt/lib/${ANDROID_ABI}/libtun2socks.a
        ${log-lib})

# ==================== 关键修复：支持 16 KB 页面大小 ====================
# Google Play 从 2025-11-01 要求必须支持 16KB 对齐
target_link_options(tun2socks PRIVATE
        "-Wl,-z,max-page-size=16384"
)

# 可选：为所有 ABI 都加上（更保险）
if(ANDROID_ABI STREQUAL "x86_64" OR ANDROID_ABI STREQUAL "arm64-v8a")
    target_link_options(tun2socks PRIVATE "-Wl,-z,max-page-size=16384")
endif()