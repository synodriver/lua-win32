cmake_minimum_required(VERSION 3.20)
project(luawin32 C)
set(CMAKE_C_STANDARD 11)

if(WIN32)
    message(STATUS "Detected Windows system. Continuing with the build.")
else()
    message(FATAL_ERROR "Unsupported operating system. Exiting CMake.")
endif()

# change this to your lua.h directory
include_directories(D:\\conda\\envs\\py310\\Library\\include)
# change this to your lua.lib\liblua.a directory
link_directories("D:\\conda\\envs\\py310\\Library\\lib" D:\\conda\\envs\\py310\\Library\\bin)



add_library(win32 SHARED src/lwin32.c
        src/lwin32.c)
target_link_libraries(win32 lua)
set_target_properties(win32 PROPERTIES PREFIX "")
#add_compile_definitions(_DEBUG)
