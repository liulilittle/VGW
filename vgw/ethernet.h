#pragma once

#include "gw.h"
#include "env.h"

namespace vgw {
    bool                ethernet_release();
    int                 ethernet_output(struct eth_hdr* eth, int len);
    uint32_t            ethernet_get_interface(uint32_t dwIndex);
    #ifdef _WIN32
    bool                ethernet_loopback(struct eth_addr& mac, uint32_t ip, uint32_t ngw, uint32_t mask);
    #else
    bool                ethernet_loopback(struct eth_addr& mac, uint32_t ip, uint32_t ngw, uint32_t mask, bool lwip, int snat, int ncpu);
    #endif
}