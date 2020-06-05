cmake_minimum_required(VERSION 3.13)  # CMake version check
project(openssl_test)
set(CMAKE_CXX_STANDARD 17)            # Enable c++17 standard

# openssl
find_package(PkgConfig REQUIRED)
pkg_check_modules(OPENSSL openssl)
pkg_search_module(OPENSSL openssl REQUIRED )

set(LINK_LIBS ${OPENSSL_LIBRARIES} openssl_mylib)

# GTest/GMock
set(BUILD_GMOCK ON)


include_directories(SYSTEM
    ${gtest_SOURCE_DIR}
    ${gtest_SOURCE_DIR}/include
    ${gmock_SOURCE_DIR}
    ${gmock_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIRS}
    ${PROJECT_BINARY_DIR}/include)

file(GLOB_RECURSE test_cases *.cpp)
foreach(case_file ${test_cases})
    get_filename_component( case_name ${case_file} NAME_WE )
    set (case_name test_${case_name})
    add_executable(${case_name} ${case_file})
    target_compile_options(${case_name} PUBLIC -fno-exceptions -fdiagnostics-color=always)

    target_link_libraries(
        ${case_name} PUBLIC
        ${LINK_LIBS} gtest_main gmock_main pthread )

    add_test(
        NAME ${case_name}
        COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${case_name}
        WORKING_DIRECTORY ${PROJECT_BINARY_DIR})
endforeach()

