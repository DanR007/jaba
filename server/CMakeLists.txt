cmake_minimum_required (VERSION 3.20 FATAL_ERROR)

set(PROJECT_NAME jabber_server)
set(CMAKE_CXX_STANDARD 17)

project(${PROJECT_NAME})

set(SERVER
src/server/server.cpp
)

set(ADDITION
src/parser/xml.cpp
src/crypto/crypto.cpp
src/math/math.cpp
)

add_executable(${PROJECT_NAME} 
"src/main.cpp" 
${SERVER}
${ADDITION}
)

include_directories(/usr/include)

target_link_libraries(${PROJECT_NAME} /home/danr0/Documents/openssl-3.3.0/libcrypto.so /home/danr0/Documents/openssl-3.3.0/libssl.so)

set_target_properties(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/)