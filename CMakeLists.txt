cmake_minimum_required(VERSION 3.0)
# Allow setting PROJECT_VERSION through project():
cmake_policy(SET CMP0048 NEW)

# Don't bother writing the project name all the time:
set(PROJECT dhcpoptinj)

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

project(
	${PROJECT}
	VERSION 0.5.2
	DESCRIPTION "DHCP option injector"
	LANGUAGES C
	)
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
add_executable(${PROJECT} ${SOURCES} ${HEADERS})
set_property(TARGET ${PROJECT} PROPERTY C_STANDARD 99)
target_compile_options(${PROJECT} PRIVATE
	-Wall
	-Wextra
	-pedantic
	-Wcast-align
	-Wcast-qual
	-Wdisabled-optimization
	-Wformat=2
	-Winit-self
	-Wmissing-declarations
	-Wmissing-include-dirs
	-Wredundant-decls
	-Wshadow
	-Wsign-conversion
	-Wstrict-overflow=5
	-Wno-error=strict-overflow
	-Wswitch-default
	-Wundef
	-Werror
	-Wno-unused
	-Wmissing-prototypes
	-Wstrict-prototypes
	-Wold-style-definition
	-fstack-protector
	-Wwrite-strings
	-Wmissing-field-initializers
	-D_POSIX_SOURCE
	-D_DEFAULT_SOURCE
	-D_FORTIFY_SOURCE=2
	)
# Only add -Wlogical-op if using gcc; clang does not support this warning option:
if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
	target_compile_options(${PROJECT} PRIVATE "-Wlogical-op")
endif()
 
find_library(NFQ_LIB netfilter_queue REQUIRED)
target_link_libraries(${PROJECT} ${NFQ_LIB})

install(TARGETS ${PROJECT} DESTINATION sbin)
# Add uninstall target, since cmake does not:
configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
	"${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
	IMMEDIATE @ONLY)
add_custom_target(uninstall
	COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
