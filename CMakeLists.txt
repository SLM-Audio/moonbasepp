cmake_minimum_required(VERSION 3.5)
project(moonbasepp VERSION 0.0.1)
include(FetchContent)
set(CPR_USE_SYSTEM_CURL ON)
set(BUILD_SHARED_LIBS OFF)
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

FetchContent_Declare(jwt-cpp
        GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
        GIT_TAG v0.7.1
        GIT_SHALLOW ON
)
set(JWT_BUILD_EXAMPLES OFF)
set(JWT_BUILD_TESTS OFF)
set(JWT_DISABLE_PICOJSON ON)
FetchContent_MakeAvailable(jwt-cpp)

FetchContent_Declare(fmt
        GIT_REPOSITORY https://github.com/fmtlib/fmt.git
        GIT_TAG 12.0.0
        GIT_SHALLOW ON
)
FetchContent_MakeAvailable(fmt)

add_library(moonbasepp STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/source/moonbasepp_DeviceFingerprint.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/source/moonbasepp_Licensing.cpp
)

add_library(slma::moonbasepp ALIAS moonbasepp)

target_include_directories(moonbasepp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(moonbasepp PRIVATE cpr::cpr cpp-base64 jwt-cpp nlohmann_json fmt::fmt)

