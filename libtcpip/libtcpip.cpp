#include "libtcpip.h"
#include "netstack.h"

LIBTCPIP_API
bool libtcpip_loopback(uint32_t ip, uint32_t gw, uint32_t mask, LIBTCPIP_IPV4_OUTPUT outputfn) {
    if (ip == INADDR_ANY || ip == INADDR_NONE) {
        return false;
    }

    if (gw == INADDR_ANY || gw == INADDR_NONE) {
        return false;
    }

    if (mask == INADDR_ANY || !outputfn) {
        return false;
    }

    lwip::netstack::output = outputfn;
    lwip::netstack::IP = ip;
    lwip::netstack::GW = gw;
    lwip::netstack::MASK = mask;
    return lwip::netstack::open();
}

LIBTCPIP_API
bool libtcpip_input(void* packet, int size) {
    if (!packet || size < 1) {
        return false;
    }
    return lwip::netstack::input(packet, size);
}