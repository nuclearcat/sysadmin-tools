# Copyright (C) 2024 Fedoryshchenko Denys <nuclearcat@nuclearcat.com>
# This file is part of trafw.
#
# trafw is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
CMAKE_MINIMUM_REQUIRED(VERSION 3.5)
PROJECT(trafw)

# require pcap-dev
FIND_PACKAGE(PkgConfig REQUIRED)
PKG_CHECK_MODULES(PCAP REQUIRED libpcap)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -g -Wall -Wextra")
SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -g -Wall -Wextra")
SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -g -Wall -Wextra")

INCLUDE_DIRECTORIES(/usr/local/include)
LINK_DIRECTORIES(/usr/local/lib)

ADD_EXECUTABLE(trafw trafw.c)
TARGET_LINK_LIBRARIES(trafw pcap)



