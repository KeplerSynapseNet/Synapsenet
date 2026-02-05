cmake_minimum_required(VERSION 3.16)
project(KeplerSynapseNet VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(USE_LLAMA_CPP "Enable llama.cpp GGML backend" ON)
option(USE_SECP256K1 "Use libsecp256k1 for signatures" ON)
option(BUILD_PRIVACY "Build with privacy layer" OFF)
option(BUILD_TESTS "Build tests" ON)
option(BUILD_IDE "Build SynapseNet terminal IDE (crush fork)" ON)

if(USE_LLAMA_CPP)
    if(EXISTS ${CMAKE_SOURCE_DIR}/third_party/llama.cpp/CMakeLists.txt)
        add_subdirectory(${CMAKE_SOURCE_DIR}/third_party/llama.cpp ${CMAKE_BINARY_DIR}/llama.cpp)
        if(TARGET llama)
            set(HAS_LLAMA ON)
        endif()
    else()
        include(FetchContent)
        FetchContent_Declare(
            llama_cpp
            GIT_REPOSITORY https://github.com/ggerganov/llama.cpp.git
            GIT_TAG master
        )
        FetchContent_MakeAvailable(llama_cpp)
        if(TARGET llama)
            set(HAS_LLAMA ON)
        endif()
    endif()
endif()

find_package(Threads REQUIRED)

set(HAS_SECP256K1 OFF)
if(USE_SECP256K1)
    if(EXISTS ${CMAKE_SOURCE_DIR}/third_party/secp256k1/CMakeLists.txt)
        add_subdirectory(${CMAKE_SOURCE_DIR}/third_party/secp256k1 ${CMAKE_BINARY_DIR}/secp256k1)
        if(TARGET secp256k1)
            set(HAS_SECP256K1 ON)
        endif()
    else()
        include(FetchContent)
        FetchContent_Declare(
            secp256k1
            GIT_REPOSITORY https://github.com/bitcoin-core/secp256k1.git
            GIT_TAG master
        )
        FetchContent_MakeAvailable(secp256k1)
        if(TARGET secp256k1)
            set(HAS_SECP256K1 ON)
        endif()
    endif()
endif()

# Find and require ncurses
find_package(Curses REQUIRED)
if(NOT CURSES_FOUND)
    message(FATAL_ERROR "ncurses library not found. Install with: 'brew install ncurses' (macOS) or 'apt-get install libncurses-dev' (Linux)")
endif()

# Find SQLite3 with better error handling
find_package(SQLite3 QUIET)
if(SQLite3_FOUND)
    set(SQLITE3_LIBRARY ${SQLite3_LIBRARIES})
else()
    find_library(SQLITE3_LIBRARY sqlite3)
    if(NOT SQLITE3_LIBRARY AND APPLE)
        find_library(SQLITE3_LIBRARY sqlite3
            PATHS /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib)
    endif()
    if(NOT SQLITE3_LIBRARY)
        message(WARNING "SQLite3 not found. Some database features may be disabled.")
        set(SQLITE3_LIBRARY "")
    endif()
endif()

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/src)
if(CURSES_FOUND)
    include_directories(${CURSES_INCLUDE_DIR})
endif()
if(USE_LLAMA_CPP)
    include_directories(${CMAKE_SOURCE_DIR}/third_party/llama.cpp/include)
endif()

# Source files
file(GLOB_RECURSE CORE_SOURCES "src/core/*.cpp")
file(GLOB_RECURSE TUI_SOURCES "src/tui/*.cpp")
file(GLOB_RECURSE MODEL_SOURCES "src/model/*.cpp")
file(GLOB_RECURSE NETWORK_SOURCES "src/network/*.cpp")
file(GLOB_RECURSE CRYPTO_SOURCES "src/crypto/*.cpp")
file(GLOB_RECURSE DATABASE_SOURCES "src/database/*.cpp")
file(GLOB_RECURSE PYTHON_SOURCES "src/python/*.cpp")
file(GLOB_RECURSE UTILS_SOURCES "src/utils/*.cpp")
file(GLOB_RECURSE INFRA_SOURCES "src/infrastructure/*.cpp")
file(GLOB_RECURSE WEB_SOURCES "src/web/*.cpp")
file(GLOB_RECURSE QUANTUM_SOURCES "src/quantum/*.cpp")
file(GLOB_RECURSE PRIVACY_SOURCES "src/privacy/*.cpp")

set(BASE_SOURCES
    ${CORE_SOURCES}
    ${TUI_SOURCES}
    ${MODEL_SOURCES}
    ${NETWORK_SOURCES}
    ${CRYPTO_SOURCES}
    ${DATABASE_SOURCES}
    ${PYTHON_SOURCES}
    ${UTILS_SOURCES}
    ${INFRA_SOURCES}
    ${WEB_SOURCES}
    ${QUANTUM_SOURCES}
    ${PRIVACY_SOURCES}
)

if(BUILD_PRIVACY)
    add_definitions(-DPRIVACY_ENABLED)
endif()

add_library(synapsed_core STATIC ${BASE_SOURCES})

target_link_libraries(synapsed_core PUBLIC
    Threads::Threads
    ${CURSES_LIBRARIES}
)

if(USE_SECP256K1 AND HAS_SECP256K1)
    target_compile_definitions(synapsed_core PUBLIC SYNAPSE_USE_SECP256K1=1)
    target_link_libraries(synapsed_core PUBLIC secp256k1)
endif()

if(SQLITE3_LIBRARY)
    target_link_libraries(synapsed_core PUBLIC ${SQLITE3_LIBRARY})
else()
    message(STATUS "SQLite3 support disabled (library not found)")
endif()

if(USE_LLAMA_CPP AND HAS_LLAMA)
    target_compile_definitions(synapsed_core PUBLIC USE_LLAMA_CPP=1)
    target_link_libraries(synapsed_core PUBLIC llama)
endif()

add_executable(synapsed src/main.cpp)
target_link_libraries(synapsed PRIVATE synapsed_core)

# SynapseNet IDE (Go / crush fork)
if(BUILD_IDE)
    find_program(GO_EXECUTABLE go)
    if(NOT GO_EXECUTABLE)
        message(WARNING "Go not found; SynapseNet IDE will not be built (install Go and reconfigure)")
    else()
        set(SYNAPSE_IDE_BIN "${CMAKE_BINARY_DIR}/synapseide")
        file(GLOB_RECURSE SYNAPSE_IDE_GO_SOURCES
            "${CMAKE_SOURCE_DIR}/crush-main/*.go"
            "${CMAKE_SOURCE_DIR}/crush-main/**/*.go"
        )
        add_custom_command(
            OUTPUT ${SYNAPSE_IDE_BIN}
            COMMAND ${GO_EXECUTABLE} build -o ${SYNAPSE_IDE_BIN}
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/crush-main
            DEPENDS
                ${CMAKE_SOURCE_DIR}/crush-main/go.mod
                ${CMAKE_SOURCE_DIR}/crush-main/go.sum
                ${SYNAPSE_IDE_GO_SOURCES}
        )
        add_custom_target(synapseide_build ALL DEPENDS ${SYNAPSE_IDE_BIN})
        install(PROGRAMS ${SYNAPSE_IDE_BIN} DESTINATION bin)
    endif()
endif()

# Tests
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Install
install(TARGETS synapsed DESTINATION bin)
