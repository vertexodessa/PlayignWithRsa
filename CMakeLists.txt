cmake_minimum_required(VERSION 3.13)

project(openssl_example)

find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache) # Less useful to do it for linking, see edit2
endif(CCACHE_FOUND)

add_subdirectory(googletest)
enable_testing()

add_subdirectory(expected)

add_subdirectory(app)
add_subdirectory(lib)
add_subdirectory(test)
