cmake_minimum_required(VERSION 3.10)

set(CMAKE_C_STANDARD 99)

project(ssq VERSION 1.0)

add_library(ssq STATIC src/ssq.c)
