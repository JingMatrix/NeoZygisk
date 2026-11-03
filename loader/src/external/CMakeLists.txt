project(external)

option(LSPLT_BUILD_SHARED OFF)
add_subdirectory(lsplt/lsplt/src/main/jni)

if(NOT ANDROID_ABI STREQUAL "riscv64")
    add_subdirectory(bhook)
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
