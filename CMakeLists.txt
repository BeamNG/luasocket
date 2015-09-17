cmake_minimum_required (VERSION 2.6) 
project(luasocket)


#BEAMNG_PATCH_HOOK

#include_directories (../LuaJIT/src) 


add_definitions(-DLUASOCKET_API= -DLUASOCKET_INET_PTON=1 -DLUASOCKET_INET_ATON=1)
if(WIN32)
    add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS -D_CRT_SECURE_NO_WARNINGS -D_WIN32_WINNT=0x501)
endif()

option(LUASOCKET_SECURITY_SANDBOX "enables or disables the security sandbox" ON)
if(LUASOCKET_SECURITY_SANDBOX)
add_definitions(-DLUASOCKET_SECURITY_SANDBOX)
endif()

option(LUASOCKET_SECURITY_SANDBOX_EXTERNAL "if enabled, use external security checks, otherwise allow private networks only" ON)
if(LUASOCKET_SECURITY_SANDBOX_EXTERNAL)
add_definitions(-DLUASOCKET_SECURITY_SANDBOX_EXTERNAL)
endif()

set(sources src/auxiliar.c src/buffer.c src/except.c src/inet.c src/io.c src/luasocket.c src/options.c src/select.c src/tcp.c src/timeout.c src/udp.c src/wsocket.c src/compat.c src/luasocket_restriction.c) 

add_library(luasocket ${sources})
