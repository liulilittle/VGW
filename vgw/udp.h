#pragma once

#include "gw.h"
#include "ethernet.h"
#include "./packet/IPFrame.h"
#include "./packet/UdpFrame.h"

namespace vgw {
    void udp_init();
    bool udp_input(const std::shared_ptr<vgw::packet::IPFrame>& packet, const std::shared_ptr<vgw::packet::UdpFrame>& frame);
}