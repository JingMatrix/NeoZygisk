project(external)

option(LSPLT_BUILD_SHARED OFF)
add_subdirectory(lsplt/lsplt/src/main/jni)

if(NOT ANDROID_ABI STREQUAL "riscv64")
    set(BYTEHOOK_SRC ${CMAKE_CURRENT_SOURCE_DIR}/bytehook/bytehook/src/main/cpp)
    file(GLOB BYTEHOOK_SOURCES ${BYTEHOOK_SRC}/*.c)
    add_library(bytehook STATIC ${BYTEHOOK_SOURCES})
    target_compile_definitions(bytehook PRIVATE
        bytesig_init=bytehook_bytesig_init
        bytesig_protect=bytehook_bytesig_protect
        bytesig_unprotect=bytehook_bytesig_unprotect
    )
    target_include_directories(bytehook PUBLIC
        ${BYTEHOOK_SRC}/include
    )
    target_include_directories(bytehook PRIVATE
        ${BYTEHOOK_SRC}
        ${BYTEHOOK_SRC}/third_party/bsd
        ${BYTEHOOK_SRC}/third_party/lss
    )
    target_compile_options(bytehook PRIVATE -w)
endif()

# Dobby has no riscv64 backend; inline hook is unavailable there.
if(NOT ANDROID_ABI STREQUAL "riscv64")
    option(DOBBY_BUILD_SHARED OFF)
    option(DOBBY_GENERATE_SHARED OFF)
    add_subdirectory(dobby)
else()
    add_subdirectory(rv64hook)
endif()

add_subdirectory(lzma)
