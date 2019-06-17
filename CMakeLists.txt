cmake_minimum_required(VERSION 3.12)
project(STraceConsumer)

set(CMAKE_CXX_STANDARD 14)

add_executable(STraceConsumer main.cpp IOHandler.h IOHandler.cpp straceHandler.cpp straceHandler.h)
add_executable(HelloWorldTest tests/HelloWorldTest.cpp)
add_executable(ReadFileTest tests/ReadFileTest.cpp)
add_executable(BasicForkTest tests/BasicForkTest.cpp)

TARGET_LINK_LIBRARIES(STraceConsumer z)
TARGET_LINK_LIBRARIES(STraceConsumer pthread)
TARGET_LINK_LIBRARIES(STraceConsumer util)