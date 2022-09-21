#include "udp.h"

namespace vgw {
    namespace packet {
        namespace native {
            struct udp_hdr* udp_hdr::Parse(struct ip_hdr* iphdr, const void* packet, int size) {
                if (NULL == iphdr || size <= 0) {
                    return NULL;
                }

                struct udp_hdr* udphdr = (struct udp_hdr*)packet;
                if (NULL == udphdr) {
                    return NULL;
                }

                if (size != __ntohs(udphdr->len)) { // 错误的数据报
                    return NULL;
                }

                int hdrlen_bytes = sizeof(struct udp_hdr);
                int len = size - hdrlen_bytes;
                if (len <= 0) {
                    return NULL;
                }

                #ifdef VGW_CHECKSUM
                if (udphdr->chksum != 0) {
                    unsigned int pseudo_checksum = inet_chksum_pseudo((unsigned char*)udphdr,
                        (unsigned int)IPPROTO_UDP,
                        (unsigned int)size,
                        iphdr->src,
                        iphdr->dest);
                    if (pseudo_checksum != 0) {
                        return NULL;
                    }
                }
                #endif
                return udphdr;
            }
        }
    }
}