# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.12

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /Applications/CLion.app/Contents/bin/cmake/mac/bin/cmake

# The command to remove a file.
RM = /Applications/CLion.app/Contents/bin/cmake/mac/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/thomaslynch/CLionProjects/DTraceConsumer

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/thomaslynch/CLionProjects/DTraceConsumer/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/ReadFileTest.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/ReadFileTest.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/ReadFileTest.dir/flags.make

CMakeFiles/ReadFileTest.dir/tests/ReadFileTest.cpp.o: CMakeFiles/ReadFileTest.dir/flags.make
CMakeFiles/ReadFileTest.dir/tests/ReadFileTest.cpp.o: ../tests/ReadFileTest.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/thomaslynch/CLionProjects/DTraceConsumer/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/ReadFileTest.dir/tests/ReadFileTest.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/ReadFileTest.dir/tests/ReadFileTest.cpp.o -c /Users/thomaslynch/CLionProjects/DTraceConsumer/tests/ReadFileTest.cpp

CMakeFiles/ReadFileTest.dir/tests/ReadFileTest.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/ReadFileTest.dir/tests/ReadFileTest.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/thomaslynch/CLionProjects/DTraceConsumer/tests/ReadFileTest.cpp > CMakeFiles/ReadFileTest.dir/tests/ReadFileTest.cpp.i

CMakeFiles/ReadFileTest.dir/tests/ReadFileTest.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/ReadFileTest.dir/tests/ReadFileTest.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/thomaslynch/CLionProjects/DTraceConsumer/tests/ReadFileTest.cpp -o CMakeFiles/ReadFileTest.dir/tests/ReadFileTest.cpp.s

# Object files for target ReadFileTest
ReadFileTest_OBJECTS = \
"CMakeFiles/ReadFileTest.dir/tests/ReadFileTest.cpp.o"

# External object files for target ReadFileTest
ReadFileTest_EXTERNAL_OBJECTS =

ReadFileTest: CMakeFiles/ReadFileTest.dir/tests/ReadFileTest.cpp.o
ReadFileTest: CMakeFiles/ReadFileTest.dir/build.make
ReadFileTest: CMakeFiles/ReadFileTest.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/thomaslynch/CLionProjects/DTraceConsumer/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ReadFileTest"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/ReadFileTest.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/ReadFileTest.dir/build: ReadFileTest

.PHONY : CMakeFiles/ReadFileTest.dir/build

CMakeFiles/ReadFileTest.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/ReadFileTest.dir/cmake_clean.cmake
.PHONY : CMakeFiles/ReadFileTest.dir/clean

CMakeFiles/ReadFileTest.dir/depend:
	cd /Users/thomaslynch/CLionProjects/DTraceConsumer/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/thomaslynch/CLionProjects/DTraceConsumer /Users/thomaslynch/CLionProjects/DTraceConsumer /Users/thomaslynch/CLionProjects/DTraceConsumer/cmake-build-debug /Users/thomaslynch/CLionProjects/DTraceConsumer/cmake-build-debug /Users/thomaslynch/CLionProjects/DTraceConsumer/cmake-build-debug/CMakeFiles/ReadFileTest.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/ReadFileTest.dir/depend

