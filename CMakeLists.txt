cmake_minimum_required(VERSION 3.12)
project(DTraceConsumer)

set(CMAKE_CXX_STANDARD 14)

include_directories(/usr/src/cddl/compat/opensolaris/include)
include_directories(/usr/src/cddl/contrib/opensolaris/lib/libdtrace/common/)
include_directories(/usr/src/sys/cddl/compat/opensolaris)
include_directories(/usr/src/sys/cddl/contrib/opensolaris/uts/common/)

add_executable(DTraceConsumer main.cpp dtraceHandler.cpp dtraceHandler.h)
add_executable(HelloWorldTest tests/HelloWorldTest.cpp)
add_executable(ReadFileTest tests/ReadFIleTest.cpp)

TARGET_LINK_LIBRARIES(DTraceConsumer dtrace)
TARGET_LINK_LIBRARIES(DTraceConsumer proc)
TARGET_LINK_LIBRARIES(DTraceConsumer z)
TARGET_LINK_LIBRARIES(DTraceConsumer pthread)
TARGET_LINK_LIBRARIES(DTraceConsumer util)