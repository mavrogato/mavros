
cmake_minimum_required(VERSION 3.22)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_COMPILER "clang")
set(CMAKE_C_STANDARD "17")
set(CMAKE_CXX_COMPILER "clang++")
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_FLAGS "-fsycl -fsycl-targets=nvptx64-nvidia-cuda -Wno-unknown-cuda-version")

include_directories(
  $ENV{LLVM_SYCL_HOME}/include
  ${CMAKE_CURRENT_BINARY_DIR})

project(mavros)

add_executable(mavros
  main.cc)

target_link_libraries(mavros
  PRIVATE
  wayland-client
  wayland-client++
  wayland-client-extra++)

add_custom_target(run
  DEPENDS mavros
  COMMAND WAYLAND_DEBUG=1 ./mavros)
