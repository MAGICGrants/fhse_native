# The library Dart opens (lib/fhse_native.dart), built from ../src as on every
# other platform. Flutter copies what `fhse_native_bundled_libraries` names
# next to the app.
cmake_minimum_required(VERSION 3.14)

set(PROJECT_NAME "fhse_native")
project(${PROJECT_NAME} LANGUAGES C)

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../src" "${CMAKE_CURRENT_BINARY_DIR}/shared")

set(fhse_native_bundled_libraries
  $<TARGET_FILE:fhse_native>
  PARENT_SCOPE
)
