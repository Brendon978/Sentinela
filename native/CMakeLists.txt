cmake_minimum_required(VERSION 3.22)
project(sentinela C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Todo .c de src/ entra no motor, menos a ponte JNI, que só existe no Android.
file(GLOB SN_FONTES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)
list(FILTER SN_FONTES EXCLUDE REGEX ".*/jni\\.c$")

set(SN_AVISOS -Wall -Wextra -Werror -Wshadow -Wconversion -Wno-sign-conversion)

if(ANDROID)
    add_library(sentinela SHARED ${SN_FONTES} ${CMAKE_CURRENT_SOURCE_DIR}/src/jni.c)
    target_include_directories(sentinela PRIVATE include)
    target_compile_options(sentinela PRIVATE ${SN_AVISOS})
    target_compile_definitions(sentinela PRIVATE _GNU_SOURCE)
    target_link_libraries(sentinela log)
else()
    # Testes no PC, com AddressSanitizer e UndefinedBehaviorSanitizer.
    file(GLOB SN_TESTES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.c)
    add_executable(testes ${SN_FONTES} ${SN_TESTES})
    target_include_directories(testes PRIVATE include tests)
    target_compile_options(testes PRIVATE ${SN_AVISOS} -g -O1 -fno-omit-frame-pointer
        -fsanitize=address,undefined -fno-sanitize-recover=all)
    target_compile_definitions(testes PRIVATE _GNU_SOURCE
        SN_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures")
    target_link_options(testes PRIVATE -fsanitize=address,undefined)
    target_link_libraries(testes pthread)
endif()
