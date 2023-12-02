cmake_minimum_required (VERSION 3.5)
project(mycrypt VERSION 1.0)

set(DEBUG 1)
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
set(SRC_DIRECTORY ./src)

#
# My include path
#
include_directories(
  ./
  ./src
)

#
# System include path and link path
#
include_directories(/usr/local/include)
link_directories(/usr/local/lib)

#
# My public header file
#
set(MYCRYPT_PUBLIC_HEADERS
  ${SRC_DIRECTORY}/mycrypt.h
  ${SRC_DIRECTORY}/compile.h
  ${SRC_DIRECTORY}/exception.h
  ${SRC_DIRECTORY}/debug.h
  ${SRC_DIRECTORY}/sm2.h
  ${SRC_DIRECTORY}/sm3.h
  ${SRC_DIRECTORY}/sm4.h
)

#
# Library Build
#
add_library(${PROJECT_NAME} STATIC
  ${SRC_DIRECTORY}/sm2.cc
  ${SRC_DIRECTORY}/sm3.cc
  ${SRC_DIRECTORY}/sm4.cc
)
target_link_libraries(${PROJECT_NAME} my)


#
# Add SubDirectory
#
add_subdirectory(test)

#
# Enable Test
#
enable_testing()
add_test(NAME test_sm2 COMMAND test_sm2)
set_tests_properties(test_sm2 PROPERTIES FAIL_REGULAR_EXPRESSION "failed")
add_test(NAME test_sm3 COMMAND test_sm3)
set_tests_properties(test_sm3 PROPERTIES FAIL_REGULAR_EXPRESSION "failed")
add_test(NAME test_sm4 COMMAND test_sm4)
set_tests_properties(test_sm4 PROPERTIES FAIL_REGULAR_EXPRESSION "failed")

#
# Install Set
#
INSTALL(TARGETS mycrypt ARCHIVE DESTINATION lib)
INSTALL(FILES ${MYCRYPT_PUBLIC_HEADERS} DESTINATION include/mycrypt)
