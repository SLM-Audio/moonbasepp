project(FIND_MESON VERSION 1.0.0)
include(FindPython3)
find_package(Python3 COMPONENTS Interpreter Development.Module)
if(NOT ${Python3_FOUND})
    message(FATAL_ERROR "Python3 is required")
endif()
execute_process(
    COMMAND pip show meson
    RESULT_VARIABLE FIND_MESON_EXIT_CODE
    OUTPUT_QUIET
)
if(${FIND_MESON_EXIT_CODE} EQUAL 0)
    message(STATUS "Meson install already found!")
else()
    execute_process(
        COMMAND pip install meson
        RESULT_VARIABLE INSTALL_MESON_EXIT_CODE
        OUTPUT_QUIET
    )
    if(${INSTALL_MESON_EXIT_CODE} NOT EQUAL 0)
        message(FATAL_ERROR "Could not install meson!")
    else()
        message(STATUS "Meson installed!")
    endif()
endif()