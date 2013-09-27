cmake_minimum_required(VERSION 2.8)
project(liballium)

if (NOT CMAKE_BUILD_TYPE)
	message(STATUS "No build type selected, defaulting to Debug")
	set(CMAKE_BUILD_TYPE "Debug")
endif()
ADD_DEFINITIONS(-Wall -Werror)

add_subdirectory(src)
add_subdirectory(tests)
add_subdirectory(examples)

