cmake_minimum_required(VERSION 3.15)

project(SecureBlockchain VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

add_executable(secure-blockchain
    src/main.cpp
    src/crypto_utils.cpp
    src/transaction.cpp

)

target_include_directories(secure-blockchain PRIVATE src)

target_link_libraries(secure-blockchain PRIVATE OpenSSL::Crypto)
