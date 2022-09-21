#pragma once

#include "../../env.h"
#include "../../gw.h"
#include "../../checksum.h"

namespace vgw {
    namespace packet {
        namespace native {
#pragma pack(push, 1)
            struct udp_hdr {
            public:
                unsigned short                  src;
                unsigned short                  dest;  /* src/dest UDP ports */
                unsigned short                  len;
                unsigned short                  chksum;

            public:
                static struct udp_hdr*          Parse(struct ip_hdr* iphdr, const void* packet, int size);
            };
#pragma pack(pop)
        }
    }
}