### cmchrpath utilities
cmake_minimum_required(VERSION 3.10)
project(cmchrpath)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

if(NOT DEFINED CMCHRPATH_MAJOR)
  set(CMCHRPATH_MAJOR 1)
endif()
if(NOT DEFINED CMCHRPATH_MINOR)
  set(CMCHRPATH_MINOR 0)
endif()
if(NOT DEFINED CMCHRPATH_PATCH)
  set(CMCHRPATH_PATCH 0)
endif()

if (NOT PACKAGE_VERSION)
  set(PACKAGE_VERSION
    "${CMCHRPATH_MAJOR}.${CMCHRPATH_MINOR}.${CMCHRPATH_PATCH}")
endif()

set(CPACK_PACKAGE_NAME "cmchrpath")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "cmchrpath")
set(CPACK_PACKAGE_VERSION_MAJOR ${CMCHRPATH_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${CMCHRPATH_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${CMCHRPATH_PATCH})
set(CPACK_PACKAGE_VERSION ${PACKAGE_VERSION})
set(CPACK_PACKAGE_VENDOR "cmchrpath")
set(CPACK_PACKAGE_CONTACT "Force Charlie")
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Force Charlie")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "cmchrpath utils")
include(CPack)


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED YES)

if (NOT MSVC)
  add_compile_options("-g")
  add_compile_options("-Wall")
  add_compile_options("-march=native")
  add_compile_options("-Wextra")
endif()



add_subdirectory(tools/cmchrpath)
add_subdirectory(tools/elfinfo)
