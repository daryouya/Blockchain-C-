cmake_minimum_required(VERSION 3.14)
project(LANGUAGES C)

include_directories(./include)
include_directories(./lib)
link_directories(lib)

file(GLOB FILES "src/*.c")
find_package(OpenSSL REQUIRED)
set(FLAGS -g -fsanitize=address)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(blockchain ${FILES})
target_compile_options(blockchain PUBLIC ${FLAGS})
target_link_options(blockchain PUBLIC ${FLAGS})
target_link_libraries(blockchain PUBLIC check-aarch64.so OpenSSL::Crypto)
