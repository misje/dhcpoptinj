cmake_minimum_required(VERSION 3.0)
# Allow setting PROJECT_VERSION through project():
cmake_policy(SET CMP0048 NEW)

if(DEFINED CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE} CACHE STRING "Choose the type of build, Debug or Release")
else()
	SET(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build, Debug or Release")
endif()
if (DEFINED CMAKE_INSTALL_PREFIX)
	set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE} CACHE STRING "Choose install prefix")
else()
	set(CMAKE_INSTALL_PREFIX /usr CACHE STRING "Choose install prefix")
endif()

project(dhcpoptinj LANGUAGES C VERSION 0.3.0)
add_definitions(-DDHCPOPTINJ_VERSION="${PROJECT_VERSION}")
set(SOURCES
	src/config.c
	src/dhcp.c
	src/dhcpoptinj.c
	src/ipv4.c
	src/options.c
	)
set(HEADERS
	src/config.h
	src/dhcp.h
	src/ipv4.h
	src/options.h
	src/udp.h
	)
add_executable(dhcpoptinj ${SOURCES} ${HEADERS})
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -pedantic -std=c99 -D_POSIX_SOURCE -D_DEFAULT_SOURCE")
find_library(NFQ_LIB netfilter_queue REQUIRED)
target_link_libraries(dhcpoptinj ${NFQ_LIB})
install(TARGETS dhcpoptinj DESTINATION sbin)
# Add uninstall target, since cmake does not:
configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
	"${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
	IMMEDIATE @ONLY)
add_custom_target(uninstall
	COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
