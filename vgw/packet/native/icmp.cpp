#include "icmp.h"

namespace vgw {
    namespace packet {
        namespace native {
            struct icmp_hdr* icmp_hdr::Parse(struct ip_hdr* iphdr, const void* packet, int size) {
                if (NULL == iphdr || size <= 0) {
                    return NULL;
                }

                struct icmp_hdr* icmphdr = (struct icmp_hdr*)packet;
                if (NULL == icmphdr) {
                    return NULL;
                }

                #ifdef VGW_CHECKSUM
                if (icmphdr->icmp_chksum != 0) {
                    unsigned short cksum = inet_chksum(icmphdr, size);
                    if (cksum != 0) {
                        return NULL;
                    }
                }
                #endif

                int len = size - sizeof(struct icmp_hdr);
                if (len < 0) {
                    return NULL;
                }
                return icmphdr;
            }
        }
    }
}