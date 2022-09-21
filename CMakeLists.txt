CMAKE_MINIMUM_REQUIRED(VERSION 3.0.0) 

# 定义解决方案名称
SET(NAME vgw)
PROJECT(${NAME} C CXX) # CMAKE_CURRENT_SOURCE_DIR

# C/CXX编译器配置
SET(CMAKE_C_FLAGS "-fPIC -fvisibility=hidden")
SET(CMAKE_CXX_FLAGS "-fPIC -fvisibility=hidden")

# 配置预定义编译宏
ADD_DEFINITIONS(-DLINUX)
ADD_DEFINITIONS(-DHAVE_PF_RING)

# C
IF(BT MATCHES "Debug" OR CMAKE_BUILD_TYPE STREQUAL Debug)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_DEBUG -g")
ELSE()
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
ENDIF()

# C/CXX
IF(BT MATCHES "Debug" OR CMAKE_BUILD_TYPE STREQUAL Debug)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_DEBUG -g")
ELSE()
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
ENDIF()
SET(CMAKE_EXE_LINKER_FLAGS "-static-libstdc++ -rdynamic -Wl,-Bstatic") # -rdynamic -Wl,-Bstatic -Wl,-Bdynamic -lstdc++ -lpthread -ldl -lz -lrt

# 检查C/CXX编译器支持
INCLUDE(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
CHECK_CXX_COMPILER_FLAG("-std=c++0x" COMPILER_SUPPORTS_CXX0X)

# CXX11
IF(COMPILER_SUPPORTS_CXX11)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
ELSEIF(COMPILER_SUPPORTS_CXX0X)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
ELSE()
    MESSAGE(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use a different C++ compiler.")
ENDIF()

SET(PROJECT_REFERENCES_ROOT $ENV{BUILD_ROOT}/Ppx/trunk)

# 设置编译的头文件搜索目录
INCLUDE_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}/vgw
    ${PROJECT_SOURCE_DIR}/libpcap-linux
    ${PROJECT_SOURCE_DIR}/libtcpip
    ${PROJECT_SOURCE_DIR}/libtcpip/lwip/my
    ${PROJECT_SOURCE_DIR}/libtcpip/lwip/include
    ${PROJECT_REFERENCES_ROOT}/src
    ${PROJECT_REFERENCES_ROOT}/inc
)

# 设置搜索的第三库连接目录
LINK_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}/lib
    ${PROJECT_SOURCE_DIR}/libpcap-linux
    ${PROJECT_REFERENCES_ROOT}/lib
)

# 设置编译的源文件搜索目录
FILE(GLOB_RECURSE SOURCE_FILES libtcpip/lwip/my/*.c libtcpip/lwip/core/*.c libtcpip/lwip/api/*.c libtcpip/lwip/netif/*.c)

# 添加编译输出的静态库文件
# liblwip.a
ADD_LIBRARY(lwip STATIC ${SOURCE_FILES})

# 设置编译的源文件搜索目录
AUX_SOURCE_DIRECTORY(libtcpip LTCPIP_SOURCE_FILES)

# 添加编译输出的静态库文件
# libtcpip.a
ADD_LIBRARY(tcpip STATIC ${LTCPIP_SOURCE_FILES} ${SOURCE_FILES})

# 设置编译的源文件搜索目录
AUX_SOURCE_DIRECTORY(vgw               VGW_SOURCE_FILES)
AUX_SOURCE_DIRECTORY(vgw/io            VGW_IO_SOURCE_FILES)
AUX_SOURCE_DIRECTORY(vgw/packet        VGW_PACKET_SOURCE_FILES)
AUX_SOURCE_DIRECTORY(vgw/packet/native VGW_PACKET_NATIVE_SOURCE_FILES)

# 添加编译输出的二进制文件
ADD_EXECUTABLE(${NAME} ${VGW_SOURCE_FILES} ${VGW_IO_SOURCE_FILES} ${VGW_PACKET_SOURCE_FILES} ${VGW_PACKET_NATIVE_SOURCE_FILES})

# 设置编译输出执行文件路径
SET(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)

# 设置编译输出文件路径
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

# 设置与依赖库之间的库连接
TARGET_LINK_LIBRARIES(${NAME} libc.a pcap pfring lwip tcpip dl pthread boost_system boost_coroutine boost_thread boost_context) 