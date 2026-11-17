# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
# Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
cmake_minimum_required(VERSION 3.16)
project(pandawatch VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

option(PW_WERROR "Treat warnings as errors" ON)
set(PW_WARN -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes)
if(PW_WERROR)
  list(APPEND PW_WARN -Werror)
endif()

set(PW_INC ${CMAKE_CURRENT_SOURCE_DIR}/include/pandawatch)

add_library(pandawatch STATIC
  src/pw_sha256.c
  src/pw_xray_canon.c
  src/pw_xray_bundle.c
  src/pw_xray_demo.c
  src/pw_io.c)
target_include_directories(pandawatch PUBLIC ${PW_INC})
target_compile_options(pandawatch PRIVATE ${PW_WARN})

add_executable(pw-xray tools/pw_xray_main.c)
target_link_libraries(pw-xray PRIVATE pandawatch)
target_compile_options(pw-xray PRIVATE ${PW_WARN})

add_executable(pw-xray-verify tools/pw_xray_verify_main.c)
target_link_libraries(pw-xray-verify PRIVATE pandawatch)
target_compile_options(pw-xray-verify PRIVATE ${PW_WARN})

install(TARGETS pw-xray pw-xray-verify RUNTIME DESTINATION bin)

include(CTest)
if(BUILD_TESTING)
  set(PW_TEST_INC ${CMAKE_CURRENT_SOURCE_DIR}/tests)
  foreach(t test_layout test_sha256 test_canon test_sort test_bundle original_ir_compiles)
    add_executable(${t} tests/${t}.c)
    target_link_libraries(${t} PRIVATE pandawatch)
    target_include_directories(${t} PRIVATE ${PW_TEST_INC})
    target_compile_options(${t} PRIVATE ${PW_WARN})
  endforeach()

  add_test(NAME layout_static_asserts COMMAND test_layout)
  add_test(NAME original_ir_header_compiles COMMAND original_ir_compiles)
  add_test(NAME sha256_nist_vectors COMMAND test_sha256)
  add_test(NAME canon_commutative_and_le COMMAND test_canon)
  add_test(NAME sort_determinism COMMAND test_sort)
  add_test(NAME bundle_roundtrip_golden_mutation
    COMMAND test_bundle
      ${CMAKE_CURRENT_SOURCE_DIR}/native/tests/proxy.tsv
      ${CMAKE_CURRENT_SOURCE_DIR}/native/Trust.als
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/demo-bundle.golden)

  # The spec header and source compile as-is (with the _reserved1 fix):
  # standalone syntax checks with -Werror, plus 192/160 layout asserts.
  add_test(NAME evidence_header_compiles_192_bytes
    COMMAND ${CMAKE_C_COMPILER} -std=c11 -Wall -Wextra -Werror -fsyntax-only -I${PW_INC}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/original_evidence_probe.c)
  add_test(NAME canon_c_compiles
    COMMAND ${CMAKE_C_COMPILER} -std=c11 -Wall -Wextra -Werror -fsyntax-only -I${PW_INC}
            ${CMAKE_CURRENT_SOURCE_DIR}/src/pw_xray_canon.c)

  # CLI end to end: demo bundle -> verifier (with and without --binary).
  add_test(NAME cli_demo_bundle
    COMMAND pw-xray demo --binary ${CMAKE_CURRENT_SOURCE_DIR}/native/tests/proxy.tsv
            --alloy ${CMAKE_CURRENT_SOURCE_DIR}/native/Trust.als -o ${CMAKE_CURRENT_BINARY_DIR}/demo.pwxray)
  add_test(NAME cli_verify_bundle
    COMMAND pw-xray-verify ${CMAKE_CURRENT_BINARY_DIR}/demo.pwxray
            --binary ${CMAKE_CURRENT_SOURCE_DIR}/native/tests/proxy.tsv)
  add_test(NAME cli_verify_rejects_wrong_binary
    COMMAND pw-xray-verify ${CMAKE_CURRENT_BINARY_DIR}/demo.pwxray
            --binary ${CMAKE_CURRENT_SOURCE_DIR}/native/tests/proxy.expected.tsv)
  set_tests_properties(cli_verify_bundle cli_verify_rejects_wrong_binary PROPERTIES DEPENDS cli_demo_bundle)
  set_tests_properties(cli_verify_rejects_wrong_binary PROPERTIES WILL_FAIL TRUE)
  add_test(NAME cli_inspect_bundle COMMAND pw-xray inspect ${CMAKE_CURRENT_BINARY_DIR}/demo.pwxray)
  set_tests_properties(cli_inspect_bundle PROPERTIES DEPENDS cli_demo_bundle)
endif()
