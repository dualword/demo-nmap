cmake_minimum_required(VERSION 3.16)
project(demo-nmap LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
    cli11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11
    GIT_TAG        v2.7.2
)
FetchContent_MakeAvailable(cli11)

add_executable(demo-nmap main.cpp ScannerEngine.hpp NetworkSocket.hpp)
target_include_directories(demo-nmap PRIVATE include)
target_link_libraries(demo-nmap PRIVATE CLI11::CLI11)

