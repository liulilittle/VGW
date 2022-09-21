#pragma once

#include "gw.h"

namespace vgw {
    uint32_t    etharp_get(const struct eth_addr& hwaddr);
    bool        etharp_get(uint32_t ip, struct eth_addr& hwaddr);
    bool        etharp_set(struct eth_addr& hwaddr, uint32_t ipaddr);
    bool        etharp_add(struct eth_addr& hwaddr, uint32_t ipaddr);
    void        etharp_init();
    void        etharp_release();
    void        etharp_input(struct eth_hdr* eth, struct etharp_hdr* arp, int len);
}