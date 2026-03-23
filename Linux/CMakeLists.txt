cmake_minimum_required(VERSION 3.10)

# We renamed it to Detector!
project(Detector CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find libzip
find_package(PkgConfig REQUIRED)
pkg_check_modules(ZIP REQUIRED libzip)

# Find libyara
find_library(YARA_LIBRARY yara REQUIRED)
find_path(YARA_INCLUDE_DIR yara.h REQUIRED)

set (SOURCES
src/main.cpp
src/unzipper.cpp
src/scanner.cpp
)

add_executable(Detector ${SOURCES})

# INCLUDE directories go here (where the .h files live)
target_include_directories(Detector PRIVATE 
    ${YARA_INCLUDE_DIR}
    ${ZIP_INCLUDE_DIRS}
    include/
)

# LIBRARIES go here (the actual compiled code to link)
target_link_libraries(Detector PRIVATE 
    ${YARA_LIBRARY} 
    ${ZIP_LIBRARIES}
)