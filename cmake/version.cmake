# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# If possible, deduce project version from git environment.
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/.git)
  find_package(Git)

  execute_process(
    COMMAND git describe --tags
    OUTPUT_VARIABLE "CCF_VERSION"
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  execute_process(
    COMMAND "bash" "-c" "git describe --tags --abbrev=0 | tr -d v"
    OUTPUT_VARIABLE "CCF_RELEASE_VERSION" OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  # Check that git release tag follows semver
  execute_process(
    COMMAND
      "bash" "-c"
      "[[ ${CCF_RELEASE_VERSION} =~ ^([[:digit:]])+(\.([[:digit:]])+)*$ ]]"
    RESULT_VARIABLE "TAG_IS_SEMVER"
  )

  if(NOT ${TAG_IS_SEMVER} STREQUAL "0")
    message(
      WARNING
        "git tag \"${CCF_RELEASE_VERSION}\" does not follow semver. Defaulting to project version 0.0.0"
    )
    set(CCF_RELEASE_VERSION "0.0.0")
  endif()
else()
  # If not in a git environment (e.g. release tarball), deduce version from the
  # source directory name
  execute_process(
    COMMAND "bash" "-c"
            "[[ $(basename ${CMAKE_CURRENT_SOURCE_DIR}) =~ ^CCF-.* ]]"
    RESULT_VARIABLE "IS_CCF_FOLDER"
  )

  if(NOT ${IS_CCF_FOLDER} STREQUAL "0")
    message(FATAL_ERROR "Sources directory is not in \"CCF-...\" folder")
  endif()

  execute_process(
    COMMAND "bash" "-c" "basename ${CMAKE_CURRENT_SOURCE_DIR} | cut -d'-' -f2"
    OUTPUT_VARIABLE "CCF_VERSION" OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  set(CCF_RELEASE_VERSION ${CCF_VERSION})
  message(STATUS "CCF version deduced from sources directory: ${CCF_VERSION}")
endif()
