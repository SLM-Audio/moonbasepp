cmake_minimum_required(VERSION 3.5)
project(moonbasepp VERSION 0.0.1)
set(CMAKE_CXX_STANDARD 20)
include(FetchContent)
if (APPLE) # Or linux
    set(CPR_USE_SYSTEM_CURL ON)
    FetchContent_Declare(fmt
            GIT_REPOSITORY https://github.com/fmtlib/fmt.git
            GIT_TAG 12.0.0
            GIT_SHALLOW ON
    )
    FetchContent_MakeAvailable(fmt)
    set(MOONBASEPP_EXTRA_LIBRARIES fmt::fmt)

else ()
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    set(CPR_USE_SYSTEM_LIB_PSL OFF)
    include(cmake/meson.cmake)
    set(MOONBASEPP_EXTRA_LIBRARIES iphlpapi)
endif ()
set(BUILD_SHARED_LIBS OFF)

FetchContent_Declare(mbedtls
        URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.4/mbedtls-3.6.4.tar.bz2
        URL_HASH SHA256=ec35b18a6c593cf98c3e30db8b98ff93e8940a8c4e690e66b41dfc011d678110
)
FetchContent_MakeAvailable(mbedtls)

FetchContent_Declare(cpr
        GIT_REPOSITORY https://github.com/libcpr/cpr.git
        GIT_TAG 1.12.0
        GIT_SHALLOW ON
)
FetchContent_MakeAvailable(cpr)
FetchContent_Declare(cpp-base64
        GIT_REPOSITORY git@github.com:SLM-Audio/cpp-base64.git
        GIT_TAG master
        GIT_SHALLOW ON
)
FetchContent_MakeAvailable(cpp-base64)

FetchContent_Declare(json
        URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
        URL_HASH SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d
        GIT_SHALLOW ON
)
FetchContent_MakeAvailable(json)

add_library(moonbasepp STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/source/moonbasepp_DeviceFingerprint.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/source/moonbasepp_Licensing.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/source/moonbasepp_JWT.cpp
)

add_library(slma::moonbasepp ALIAS moonbasepp)

target_include_directories(moonbasepp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(moonbasepp PRIVATE cpr::cpr cpp-base64 nlohmann_json MbedTLS::mbedtls ${MOONBASEPP_EXTRA_LIBRARIES})

