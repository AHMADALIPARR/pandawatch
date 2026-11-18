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

# pw-xasm: x86-64 subset decoder in GNU assembler, FORTRAN 77 struct parser,
# C23 driver. Built when a Fortran compiler is present on an x86-64 host.
option(PW_XASM "Build pw-xasm (x86-64 decoder in asm, FORTRAN 77 struct parser, C23)" ON)
if(PW_XASM)
  include(CheckLanguage)
  check_language(Fortran)
  if(NOT CMAKE_Fortran_COMPILER)
    message(STATUS "pw-xasm: no Fortran compiler found, not built")
  elseif(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$")
    message(STATUS "pw-xasm: decoder is x86-64 assembly, not built on ${CMAKE_SYSTEM_PROCESSOR}")
  elseif(CMAKE_VERSION VERSION_LESS 3.21)
    message(STATUS "pw-xasm: needs CMake >= 3.21 for C23, not built")
  else()
    enable_language(Fortran)
    enable_language(ASM)

    add_library(pw_struct_f77 STATIC fortran/pw_struct.f)
    target_compile_options(pw_struct_f77 PRIVATE -std=legacy -ffixed-form -Wall -Wno-conversion)

    add_library(pw_xasm_core STATIC
      asm/pw_x86_decode.S
      xasm/pw_x86_text.c
      xasm/pw_x86_asm.c
      xasm/pw_x86_lift.c)
    set_target_properties(pw_xasm_core PROPERTIES C_STANDARD 23 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
    target_include_directories(pw_xasm_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/xasm)
    target_compile_options(pw_xasm_core PRIVATE $<$<COMPILE_LANGUAGE:C>:${PW_WARN}>)
    target_link_libraries(pw_xasm_core PUBLIC pandawatch pw_struct_f77)

    add_executable(pw-xasm xasm/pw_xasm_main.c)
    set_target_properties(pw-xasm PROPERTIES C_STANDARD 23 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
                                             LINKER_LANGUAGE Fortran)
    target_compile_options(pw-xasm PRIVATE ${PW_WARN})
    target_link_libraries(pw-xasm PRIVATE pw_xasm_core)
    install(TARGETS pw-xasm RUNTIME DESTINATION bin)

    if(BUILD_TESTING)
      add_executable(test_xasm tests/xasm/test_xasm.c)
      set_target_properties(test_xasm PROPERTIES C_STANDARD 23 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
                                                 LINKER_LANGUAGE Fortran)
      target_include_directories(test_xasm PRIVATE ${PW_TEST_INC})
      target_compile_options(test_xasm PRIVATE ${PW_WARN})
      target_link_libraries(test_xasm PRIVATE pw_xasm_core m)

      set(PW_XASM_CORPUS ${CMAKE_CURRENT_SOURCE_DIR}/tests/xasm/corpus.s)
      add_test(NAME xasm_encodings_roundtrip_fortran_lift COMMAND test_xasm ${PW_XASM_CORPUS})
      add_test(NAME xasm_cli_roundtrip_lift_verify
        COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/xasm/cli_roundtrip.sh
                $<TARGET_FILE:pw-xasm> $<TARGET_FILE:pw-xray-verify> ${PW_XASM_CORPUS}
                ${CMAKE_CURRENT_BINARY_DIR}/xasm-cli)
      add_test(NAME xasm_fortran_layout COMMAND pw-xasm layout)
      add_test(NAME xasm_fortran_structs_demo_bundle
        COMMAND pw-xasm structs ${CMAKE_CURRENT_BINARY_DIR}/demo.pwxray --ir)
      set_tests_properties(xasm_fortran_structs_demo_bundle PROPERTIES DEPENDS cli_demo_bundle)
      find_program(PW_OBJDUMP objdump)
      if(PW_OBJDUMP)
        add_test(NAME xasm_objdump_crosscheck
          COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/xasm/objdump_crosscheck.sh
                  $<TARGET_FILE:pw-xasm> ${PW_XASM_CORPUS} ${CMAKE_CURRENT_BINARY_DIR}/xasm-objdump)
      endif()
    endif()
  endif()
endif()

# Holo tools (C23): rblob (Rust crate -> .rblob -> functors). Shared code:
# Python-re-compatible regex subset, json.dumps-compatible JSON, text/path
# helpers. libc + POSIX only.
option(PW_HOLO "Build the C23 holo tools (rblob)" ON)
if(PW_HOLO AND CMAKE_VERSION VERSION_LESS 3.21)
  message(STATUS "holo tools: need CMake >= 3.21 for C23, not built")
elseif(PW_HOLO)
  add_library(pw_holo_core STATIC
    holo/pw_re.c
    holo/pw_json.c
    holo/pw_text.c
    holo/pw_rblob.c)
  set_target_properties(pw_holo_core PROPERTIES C_STANDARD 23 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_include_directories(pw_holo_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/holo)
  target_compile_options(pw_holo_core PRIVATE ${PW_WARN})
  target_link_libraries(pw_holo_core PUBLIC pandawatch)

  add_executable(rblob holo/rblob_main.c)
  set_target_properties(rblob PROPERTIES C_STANDARD 23 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_compile_options(rblob PRIVATE ${PW_WARN})
  target_link_libraries(rblob PRIVATE pw_holo_core)
  install(TARGETS rblob RUNTIME DESTINATION bin)

  if(BUILD_TESTING)
    # Expected digest of the rust_ledger blob (same bytes as the reference
    # rust_ingestor run on this fixture).
    set(PW_RUST_LEDGER_SHA256 64223e263fc87a910d37954fc048e45766ba9d02dc159b9a3543d141f57ec76a)
    add_test(NAME rblob_rust_ledger_ingest_verify_disassemble
      COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/holo/rblob_cli.sh
              $<TARGET_FILE:rblob> ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/rust_ledger
              ${PW_RUST_LEDGER_SHA256} ${CMAKE_CURRENT_BINARY_DIR}/rblob-cli)
  endif()
endif()
