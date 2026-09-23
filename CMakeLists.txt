cmake_minimum_required(VERSION 3.21)

project(PrismKey VERSION 0.1.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTORCC ON)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(GTest CONFIG REQUIRED)
find_package(Qt6 REQUIRED COMPONENTS Widgets)

include(CTest)

add_library(prismkey_crypto
    src/core/ProjectStorage.cpp
    src/crypto/HashService.cpp
    src/crypto/BatchService.cpp
    src/crypto/DownloadService.cpp
    src/crypto/KeyService.cpp
    src/crypto/SignatureService.cpp
)

target_include_directories(prismkey_crypto PUBLIC include)

target_link_libraries(prismkey_crypto PUBLIC OpenSSL::Crypto CURL::libcurl)

add_executable(prismkey
    src/main.cpp
)

target_link_libraries(prismkey PRIVATE prismkey_crypto)

add_executable(prismkey_gui WIN32
    src/gui/main.cpp
    src/gui/MainWindow.cpp
    assets/prismkey.qrc
)

target_link_libraries(prismkey_gui PRIVATE prismkey_crypto Qt6::Widgets)

if(WIN32)
    target_sources(prismkey_gui PRIVATE assets/prismkey.rc)
endif()

if(MSVC)
    target_compile_options(prismkey_crypto PRIVATE /utf-8 /W4)
    target_compile_options(prismkey PRIVATE /utf-8 /W4)
    target_compile_options(prismkey_gui PRIVATE /utf-8 /W4)
endif()

if(BUILD_TESTING)
    add_executable(prismkey_tests tests/CryptoServicesTests.cpp)
    target_link_libraries(prismkey_tests PRIVATE prismkey_crypto GTest::gtest_main OpenSSL::SSL)
    if(WIN32)
        target_link_libraries(prismkey_tests PRIVATE ws2_32)
    endif()
    include(GoogleTest)
    gtest_discover_tests(prismkey_tests)
endif()
