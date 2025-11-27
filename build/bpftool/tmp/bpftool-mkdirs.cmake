# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION ${CMAKE_VERSION}) # this file comes with cmake

# If CMAKE_DISABLE_SOURCE_CHANGES is set to true and the source directory is an
# existing directory in our source tree, calling file(MAKE_DIRECTORY) on it
# would cause a fatal error, even though it would be a no-op.
if(NOT EXISTS "/home/runner/work/PacketFilter1.0/PacketFilter1.0/src/../bpftool/src")
  file(MAKE_DIRECTORY "/home/runner/work/PacketFilter1.0/PacketFilter1.0/src/../bpftool/src")
endif()
file(MAKE_DIRECTORY
  "/home/runner/work/PacketFilter1.0/PacketFilter1.0/build/bpftool/src/bpftool-build"
  "/home/runner/work/PacketFilter1.0/PacketFilter1.0/build/bpftool"
  "/home/runner/work/PacketFilter1.0/PacketFilter1.0/build/bpftool/tmp"
  "/home/runner/work/PacketFilter1.0/PacketFilter1.0/build/bpftool/src/bpftool-stamp"
  "/home/runner/work/PacketFilter1.0/PacketFilter1.0/build/bpftool/src"
  "/home/runner/work/PacketFilter1.0/PacketFilter1.0/build/bpftool/src/bpftool-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/runner/work/PacketFilter1.0/PacketFilter1.0/build/bpftool/src/bpftool-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/runner/work/PacketFilter1.0/PacketFilter1.0/build/bpftool/src/bpftool-stamp${cfgdir}") # cfgdir has leading slash
endif()
