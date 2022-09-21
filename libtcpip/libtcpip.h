#pragma once

#include <stdint.h>

typedef bool(*LIBTCPIP_IPV4_OUTPUT)(void* packet, int size);

#ifndef LIBTCPIP_API
#ifdef __cplusplus 
#ifdef _WIN32
#ifdef _LIBTCPIP_EXPORTS
#define LIBTCPIP_API extern "C" __declspec(dllexport)
#else
#pragma comment(lib, "libtcpip.lib")

#define LIBTCPIP_API extern "C" __declspec(dllimport)
#endif
#else
#define LIBTCPIP_API extern "C" __attribute__((visibility("default")))
#endif
#else
#define LIBTCPIP_API
#endif
#endif

LIBTCPIP_API
bool libtcpip_input(void* packet, int size);

LIBTCPIP_API
bool libtcpip_loopback(uint32_t ip, uint32_t gw, uint32_t mask, LIBTCPIP_IPV4_OUTPUT outputfn);