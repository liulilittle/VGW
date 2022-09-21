#pragma once

#include "gw.h"
#include "ethernet.h"
#include "./packet/IPFrame.h"

namespace vgw {
    void        ipv4_init();
    uint64_t    ipv4_time();
    void        ipv4_input(struct ip_hdr* ip, int len);
    bool        ipv4_output(struct ip_hdr* ip, int len);
    bool        ipv4_output_(const vgw::packet::IPFrame* packet);
}