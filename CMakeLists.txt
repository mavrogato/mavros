
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

#############################################################################
# https://github.com/Cloudef/wlc/blob/master/CMake/FindWaylandProtocols.cmake
include(FeatureSummary)
set_package_properties(WaylandProtocols PROPERTIES
  URL "https://cgit.freedesktop.org/wayland/wayland-protocols"
  DESCRIPTION "Wayland protocol development")

unset(WAYLANDPROTOCOLS_PATH)
find_package(PkgConfig)
if (PKG_CONFIG_FOUND)
  execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} --variable=pkgdatadir wayland-protocols
    OUTPUT_VARIABLE WAYLANDPROTOCOLS_PATH OUTPUT_STRIP_TRAILING_WHITESPACE)
endif ()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(WaylandProtocols DEFAULT_MSG WAYLANDPROTOCOLS_PATH)
mark_as_advanced(WAYLANDPROTOCOLS_PATH)


set(XDG_SHELL_V6_PROTOCOL ${WAYLANDPROTOCOLS_PATH}/unstable/xdg-shell/xdg-shell-unstable-v6.xml)
set(ZWP_TABLET_V2_PROTOCOL ${WAYLANDPROTOCOLS_PATH}/unstable/tablet/tablet-unstable-v2.xml)
add_custom_command(
  OUTPUT xdg-shell-v6-private.c
  COMMAND wayland-scanner client-header ${XDG_SHELL_V6_PROTOCOL} xdg-shell-v6-client.h
  COMMAND wayland-scanner private-code  ${XDG_SHELL_V6_PROTOCOL} xdg-shell-v6-private.c)
add_custom_command(
  OUTPUT zwp-tablet-v2-private.c
  COMMAND wayland-scanner client-header ${ZWP_TABLET_V2_PROTOCOL} zwp-tablet-v2-client.h
  COMMAND wayland-scanner private-code  ${ZWP_TABLET_V2_PROTOCOL} zwp-tablet-v2-private.c)

add_executable(mavros
  main.cc
  ${CMAKE_CURRENT_BINARY_DIR}/xdg-shell-v6-private.c
  ${CMAKE_CURRENT_BINARY_DIR}/zwp-tablet-v2-private.c)

target_link_libraries(mavros
  PRIVATE
  wayland-client)

add_custom_target(run
  DEPENDS mavros
  COMMAND WAYLAND_DEBUG=1 ./mavros)
