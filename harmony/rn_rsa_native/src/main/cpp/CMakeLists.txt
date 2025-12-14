cmake_minimum_required(VERSION 3.13)
set(CMAKE_VERBOSE_MAKEFILE on)

set(rnoh_rsa_native_generated_dir "${CMAKE_CURRENT_SOURCE_DIR}/generated")
file(GLOB_RECURSE rnoh_rsa_native_generated_SRC "${rnoh_rsa_native_generated_dir}/**/*.cpp")
file(GLOB rnoh_rsa_native_SRC CONFIGURE_DEPENDS *.cpp)
add_library(rnoh_rsa_native SHARED ${rnoh_rsa_native_generated_SRC} ${rnoh_rsa_native_SRC})
target_include_directories(rnoh_rsa_native PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${rnoh_rsa_native_generated_dir})
target_link_libraries(rnoh_rsa_native PUBLIC rnoh)