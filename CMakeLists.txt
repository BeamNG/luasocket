cmake_minimum_required (VERSION 2.6) 
project(luasocket)

include_directories (INCLUDEPATH1) 
include_directories (INCLUDEPATH2) 
add_definitions(-DLUASOCKET_API= -D_WIN32_WINNT=0x501 -DLUASOCKET_INET_PTON=1 -DLUASOCKET_INET_ATON=1)

#FILE(GLOB sources src/*.cpp src/*.h src/*.c) 
set(sources src/auxiliar.c src/buffer.c src/except.c src/inet.c src/io.c src/luasocket.c src/options.c src/select.c src/tcp.c src/timeout.c src/udp.c src/wsocket.c src/luasocket_restriction.c) 

add_library(luasocket ${sources})
