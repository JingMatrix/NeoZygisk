cmake_minimum_required(VERSION 3.22.1)
project(lzma C)

add_library(lzma STATIC
    xz_dec_lzma2.c
    xz_dec_stream.c
    xz_dec_bcj.c
)
target_include_directories(lzma PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(lzma PRIVATE
    XZ_DEC_DYNALLOC=1
    XZ_DEC_ANY_CHECK=1
    XZ_INTERNAL_CRC32=1
    NOINLINE=noinline_for_stack
)
target_compile_options(lzma PRIVATE -Wno-unused -Wno-sign-compare)


