cmake_minimum_required(VERSION 3.10)

set(CMAKE_C_STANDARD 99)

project(ssq)

add_library(ssq STATIC src/ssq.c)

target_include_directories(ssq PUBLIC include/)
