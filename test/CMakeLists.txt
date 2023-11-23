cmake_minimum_required (VERSION 3.5)
project(mycrypt_test VERSION 1.0)

# set(DEBUG 1)
if(DEBUG)
message(STATUS "compile debug version.")
add_definitions(-std=c++11 -g -O0 -DDEBUG -Wunused-variable)
else()
message(STATUS "compile release version.")
add_definitions(-std=c++11 -O3 -Wunused-variable)
endif(DEBUG)

set(CXX_FLAGS "-Wall")
set(CMAKE_CXX_FLAGS "${CXX_FLAGS}")

#
# Sub modules directories
#
set(SRC_DIRECTORY .)

#
# Mycrypt include path
#
include_directories(
  ../src
)

#
# System include path and link path
#
include_directories(/usr/local/include)
link_directories(/usr/local/lib)

#
# Main Test
#
add_executable(test_sm2 ${SRC_DIRECTORY}/test_sm2.cc)
target_link_libraries(test_sm2 mycrypt gtest pthread)
add_executable(test_sm3 ${SRC_DIRECTORY}/test_sm3.cc)
target_link_libraries(test_sm3 mycrypt gtest pthread)
add_executable(test_sm4 ${SRC_DIRECTORY}/test_sm4.cc)
target_link_libraries(test_sm4 mycrypt gtest pthread)