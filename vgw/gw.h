#pragma once

#include <stdint.h>

namespace vgw {
    /** Internet protocol v4 */
    static const uint16_t ETHTYPE_IP = 0x0800U;
    /** Address resolution protocol */
    static const uint16_t ETHTYPE_ARP = 0x0806U;
    /** Wake on lan */
    static const uint16_t ETHTYPE_WOL = 0x0842U;
    /** RARP */
    static const uint16_t ETHTYPE_RARP = 0x8035U;
    /** Virtual local area network */
    static const uint16_t ETHTYPE_VLAN = 0x8100U;
    /** Internet protocol v6 */
    static const uint16_t ETHTYPE_IPV6 = 0x86DDU;
    /** PPP Over Ethernet Discovery Stage */
    static const uint16_t ETHTYPE_PPPOEDISC = 0x8863U;
    /** PPP Over Ethernet Session Stage */
    static const uint16_t ETHTYPE_PPPOE = 0x8864U;
    /** Jumbo Frames */
    static const uint16_t ETHTYPE_JUMBO = 0x8870U;
    /** Process field network */
    static const uint16_t ETHTYPE_PROFINET = 0x8892U;
    /** Ethernet for control automation technology */
    static const uint16_t ETHTYPE_ETHERCAT = 0x88A4U;
    /** Link layer discovery protocol */
    static const uint16_t ETHTYPE_LLDP = 0x88CCU;
    /** Serial real-time communication system */
    static const uint16_t ETHTYPE_SERCOS = 0x88CDU;
    /** Media redundancy protocol */
    static const uint16_t ETHTYPE_MRP = 0x88E3U;
    /** Precision time protocol */
    static const uint16_t ETHTYPE_PTP = 0x88F7U;
    /** Q-in-Q, 802.1ad */
    static const uint16_t ETHTYPE_QINQ = 0x9100U;
    /** Ethernet */
    static const uint16_t ETHARP_IANA_HWTYPE_ETHERNET = 1;
    /** Ethernet **/
    static const uint32_t ETHBUF_IANA_HWSNAP_ETHERNET = 65536;

    static const uint16_t ARP_REQUEST = 1;
    static const uint16_t ARP_REPLY = 2;

    #ifndef ETH_HWADDR_LEN
    #ifdef ETHARP_HWADDR_LEN
    #define ETH_HWADDR_LEN    ETHARP_HWADDR_LEN /* compatibility mode */
    #else
    #define ETH_HWADDR_LEN    6
    #endif
    #endif

    #pragma pack(push, 1)
    struct eth_addr {
        union {
            uint8_t                             s_data[ETH_HWADDR_LEN];
            struct {
                uint32_t                        dw;
                uint16_t                        w;
            } s_zero;
        };
    };

    struct eth_hdr {
        struct eth_addr                     dst;
        struct eth_addr                     src;
        uint16_t                            proto;
    };

    /** the ARP message, see RFC 826 ("Packet format") */
    struct etharp_hdr {
        uint16_t                            hwtype;
        uint16_t                            proto;
        uint8_t                             hwlen;
        uint8_t                             protolen;
        uint16_t                            opcode;
        struct eth_addr                     shwaddr;
        uint32_t                            sipaddr;
        struct eth_addr                     dhwaddr;
        uint32_t                            dipaddr;
    };

    struct ip_hdr {
    public:
        enum Flags {
            IP_RF = 0x8000,            /* reserved fragment flag */
            IP_DF = 0x4000,            /* dont fragment flag */
            IP_MF = 0x2000,            /* more fragments flag */
            IP_OFFMASK = 0x1fff,       /* mask for fragmenting bits */
        };

    public:
        /* version / header length / type of service */
        unsigned char                                                v_hl;
        /* type of service */
        unsigned char                                                tos;
        /* total length */
        unsigned short                                               len;
        /* identification */
        unsigned short                                               id;
        /* fragment offset field */
        unsigned short                                               flags;
        /* time to live */
        unsigned char                                                ttl;
        /* protocol */
        unsigned char                                                proto;
        /* checksum */
        unsigned short                                               chksum;
        /* source and destination IP addresses */
        unsigned int                                                 src;
        unsigned int                                                 dest;

    public:
        inline static int                                            IPH_V(struct ip_hdr* hdr) {
            return ((hdr)->v_hl >> 4);
        }
        inline static int                                            IPH_HL(struct ip_hdr* hdr) {
            return ((hdr)->v_hl & 0x0f);
        }
        inline static int                                            IPH_PROTO(struct ip_hdr* hdr) {
            return ((hdr)->proto & 0xff);
        }
        inline static int                                            IPH_OFFSET(struct ip_hdr* hdr) {
            return (hdr)->flags;
        }
        inline static int                                            IPH_TTL(struct ip_hdr* hdr) {
            return ((hdr)->ttl & 0xff);
        }

    public:
        static struct ip_hdr*                                        Parse(const void* packet, int size);
        static unsigned short                                        NewId();

    public:
        static const int                                             MTU = 1500;
        static const int                                             IP_HLEN;
        static const unsigned char                                   IP_VER = 4;
        static const unsigned int                                    IP_ADDR_ANY_VALUE = 0x00000000;
        static const unsigned int                                    IP_ADDR_BROADCAST_VALUE = 0xffffffff;
        static const int                                             TOS_ROUTIN_MODE = 0;
        static const unsigned char                                   IP_DFT_TTL = 64;
        static const unsigned char                                   IP_PROTO_IP = 0;
        static const unsigned char                                   IP_PROTO_ICMP = 1;
        static const unsigned char                                   IP_PROTO_UDP = 17;
        static const unsigned char                                   IP_PROTO_TCP = 6;
    };
    #pragma pack(pop)
}