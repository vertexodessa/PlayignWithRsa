cmake_minimum_required(VERSION 3.13)  # CMake version check
project(openssl_app)               # Create project "simple_example"
set(CMAKE_CXX_STANDARD 17)            # Enable c++17 standard


set(TARGET openssl_app)
set(SOURCE_FILES main.cpp)


# openssl
find_package(PkgConfig REQUIRED)
pkg_check_modules(OPENSSL openssl)
pkg_search_module(OPENSSL openssl REQUIRED )


#find_package(openssl_mylib REQUIRED)

# Add executable target with source files listed in SOURCE_FILES variable
add_executable(${TARGET} ${SOURCE_FILES})

target_compile_options(${TARGET} PUBLIC -fno-exceptions -fdiagnostics-color=always)
target_link_libraries(${TARGET} PUBLIC ${OPENSSL_LIBRARIES})
include_directories(${OPENSSL_INCLUDE_DIRS})
