cmake_minimum_required(VERSION 3.13)  # CMake version check
project(openssl_mylib)               # Create project "simple_example"
set(CMAKE_CXX_STANDARD 17)            # Enable c++17 standard

# set(SOURCE_FILES main.cpp)
file(GLOB_RECURSE SOURCE_FILES src/*.cpp)

set(TARGET openssl_mylib)

# Add executable target with source files listed in SOURCE_FILES variable
add_library(${TARGET} ${SOURCE_FILES})

# tl-expected
#add_dependencies(openssl_mylib tl-expected)
#find_package(tl-expected REQUIRED PATHS ${CMAKE_BINARY_DIR}/expected)

# openssl
find_package(PkgConfig REQUIRED)
pkg_check_modules(OPENSSL openssl)
pkg_search_module(OPENSSL openssl REQUIRED )


target_compile_options(${TARGET} PUBLIC -fno-exceptions)
target_link_libraries(${TARGET} PUBLIC ${OPENSSL_LIBRARIES})
include_directories(include ${OPENSSL_INCLUDE_DIRS})

install(TARGETS ${TARGET}
        EXPORT ${TARGET}
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        INCLUDES DESTINATION include
        )
