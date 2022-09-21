#pragma once

#include "gw.h"
#include "ethernet.h"
#include "./packet/IPFrame.h"
#include "./packet/IcmpFrame.h"

namespace vgw {
    bool icmp_input(const std::shared_ptr<vgw::packet::IPFrame>& packet, const std::shared_ptr<vgw::packet::IcmpFrame>& frame);
}