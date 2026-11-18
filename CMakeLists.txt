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
option(PW_HOLO "Build the C23 holo tools (rblob, bsm, holo-reverse)" ON)
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
    set(PW_RUST_LEDGER_SHA256 5f9c0bfe831dc8d4a0aae229941646f46925fa58e4dddd7b8d6a3c19fc89d506)
    add_test(NAME rblob_rust_ledger_ingest_verify_disassemble
      COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/holo/rblob_cli.sh
              $<TARGET_FILE:rblob> ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/rust_ledger
              ${PW_RUST_LEDGER_SHA256} ${CMAKE_CURRENT_BINARY_DIR}/rblob-cli)
  endif()

  # bsm: legacy inputs (C, COBOL, SQLite, assembly, ELF, Rust) -> .holo.wasm.
  # On x86-64 the ELF CFG comes from the asm decoder in asm/pw_x86_decode.S.
  set(PW_BSM_SOURCES
    holo/pw_bsm.c
    holo/pw_bsm_elf.c
    holo/pw_bsm_wasm.c
    holo/pw_sqlite.c)
  set(PW_BSM_X86 OFF)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$")
    enable_language(ASM)
    set(PW_BSM_X86 ON)
    list(APPEND PW_BSM_SOURCES asm/pw_x86_decode.S xasm/pw_x86_text.c)
  endif()
  add_library(pw_bsm_core STATIC ${PW_BSM_SOURCES})
  set_target_properties(pw_bsm_core PROPERTIES C_STANDARD 23 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_compile_options(pw_bsm_core PRIVATE $<$<COMPILE_LANGUAGE:C>:${PW_WARN}>)
  target_include_directories(pw_bsm_core PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/xasm)
  if(PW_BSM_X86)
    target_compile_definitions(pw_bsm_core PRIVATE PW_BSM_X86)
  endif()
  target_link_libraries(pw_bsm_core PUBLIC pw_holo_core)

  add_executable(bsm holo/bsm_main.c)
  set_target_properties(bsm PROPERTIES C_STANDARD 23 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_compile_options(bsm PRIVATE ${PW_WARN})
  target_link_libraries(bsm PRIVATE pw_bsm_core)
  install(TARGETS bsm RUNTIME DESTINATION bin)

  # holo-reverse: .holo.wasm -> C23 header, CompCert .v, Lean 4 HoloDSL.
  add_executable(holo-reverse holo/holo_reverse_main.c)
  set_target_properties(holo-reverse PROPERTIES C_STANDARD 23 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_compile_options(holo-reverse PRIVATE ${PW_WARN})
  target_link_libraries(holo-reverse PRIVATE pw_bsm_core)
  install(TARGETS holo-reverse RUNTIME DESTINATION bin)

  if(BUILD_TESTING)
    # Digests of the reference packer's modules for account.h, account.cpy,
    # ledger.sql and ledger.s (lp64 and wasm32 ABIs).
    set(PW_BSM_SHA256_LP64 cc66e468c56b3346d859eeb3059cdb75d26a443182da30d026ff2d2e4fb4ff6b)
    set(PW_BSM_SHA256_WASM32 d6190fa20e48cd76d58e9f206614fa20aa7c5621abd83eb33880edfacc530d1a)
    set(PW_BSM_ELF_CC -)
    if(PW_BSM_X86 AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
      set(PW_BSM_ELF_CC ${CMAKE_C_COMPILER})
    endif()
    find_program(PW_SQLITE3_CLI sqlite3)
    set(PW_BSM_SQLITE -)
    if(PW_SQLITE3_CLI)
      set(PW_BSM_SQLITE ${PW_SQLITE3_CLI})
    endif()
    add_test(NAME bsm_pack_inspect_fixtures
      COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/holo/bsm_cli.sh
              $<TARGET_FILE:bsm> ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/bsm
              ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/rust_ledger
              ${CMAKE_CURRENT_BINARY_DIR}/bsm-cli
              ${PW_BSM_SHA256_LP64} ${PW_BSM_SHA256_WASM32}
              ${PW_BSM_ELF_CC} ${PW_BSM_SQLITE})
    # Digests of the reference reverse-compiler's outputs for that module.
    add_test(NAME holo_reverse_c23_compcert_lean
      COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/holo/holo_reverse_cli.sh
              $<TARGET_FILE:holo-reverse> $<TARGET_FILE:bsm>
              ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/bsm
              ${CMAKE_CURRENT_BINARY_DIR}/holo-reverse-cli ${CMAKE_C_COMPILER}
              410ee2877883d2aea10f35ce4be3e636df06ad62fd10c20656af86f347dd7961
              556cbd742c6c69aeef745116d74270900ac256b6be30002fcddaf682e1c36a53
              6d1991273afdc1a2e3c3ddfd8160efdf239db0e0d0bb17095e6adf5e7cc0cee3)
  endif()
endif()
