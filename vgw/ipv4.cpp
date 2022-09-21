#include "gw.h"
#include "ipv4.h"
#include "checksum.h"
#include "etharp.h"
#include "ethernet.h"
#include "udp.h"
#include "icmp.h"
#include "./io/MemoryStream.h"
#include "./packet/IPEndPoint.h"
#include "./packet/IPFrame.h"
#include "./packet/UdpFrame.h"
#include "./packet/IcmpFrame.h"

using vgw::io::MemoryStream;
using vgw::packet::IPEndPoint;
using vgw::packet::IPFrame;
using vgw::packet::IPFlags;
using vgw::packet::UdpFrame;
using vgw::packet::IcmpFrame;
using vgw::packet::BufferSegment;

namespace vgw {
    struct Subpackage {
    public:
        typedef std::shared_ptr<IPFrame>                            IPFramePtr;
        typedef std::shared_ptr<Subpackage>                         Ptr;

    public:
        inline Subpackage() : FinalizeTime(ipv4_time() + Subpackage::MAX_FINALIZE_TIME) {}

    public:
        UInt64                                                      FinalizeTime;
        std::vector<IPFramePtr>                                     Frames;

    public:
        static const int                                            MAX_FINALIZE_TIME = 1;
    };
    typedef std::unordered_map<std::string, Subpackage::Ptr>        SubpackageTable;

    extern uint32_t                                                 ETHERNET_IP;
    extern uint32_t                                                 ETHERNET_MASK;
    extern eth_addr                                                 ETHERNET_MAC;
    extern boost::asio::io_context                                  ETHERNET_CONTEXT_;

    const int ip_hdr::IP_HLEN                                       = sizeof(struct ip_hdr);
    std::atomic<unsigned short>                                     IPV4_IP_AID_ = ATOMIC_VAR_INIT(0);
    static uint64_t                                                 IPV4_TIME_ = 0;
    static std::shared_ptr<boost::asio::deadline_timer>             IPV4_TICKTMR_;
    static SubpackageTable                                          IPV4_SUBPACKAGES_;

    inline static void                                              ipv4_input(const std::shared_ptr<IPFrame>& packet);
    inline static bool                                              ipv4_fragment(const std::shared_ptr<IPFrame>& packet);
    inline static bool                                              ipv4_update(uint64_t now);

    unsigned short ip_hdr::NewId() {
        unsigned short r = 0;
        do {
            r = ++IPV4_IP_AID_;
        } while (r == 0);
        return r;
    }

    struct ip_hdr* ip_hdr::Parse(const void* packet, int len) {
        struct ip_hdr* iphdr = (struct ip_hdr*)packet;
        if (NULL == iphdr) {
            return NULL;
        }

        int iphdr_ver = IPH_V(iphdr);
        if (iphdr_ver != ip_hdr::IP_VER) {
            return NULL;
        }

        int iphdr_hlen = IPH_HL(iphdr) << 2;
        if (iphdr_hlen >= len) {
            return NULL;
        }

        if (iphdr_hlen < IP_HLEN) {
            return NULL;
        }

        int ttl = IPH_TTL(iphdr);
        if (ttl <= 0) {
            return NULL;
        }

        if (len != __ntohs(iphdr->len)) {
            return NULL;
        }

        /* all ones (broadcast) or all zeroes (old skool broadcast) */
        if ((~iphdr->dest == IP_ADDR_ANY_VALUE) || (iphdr->dest == IP_ADDR_ANY_VALUE)) {
            return NULL;
        }

        if ((~iphdr->src == IP_ADDR_ANY_VALUE) || (iphdr->src == IP_ADDR_ANY_VALUE)) {
            return NULL;
        }

        // if ((IPH_OFFSET(iphdr) & __ntohs((UInt16)(ip_hdr::IP_OFFMASK | ip_hdr::IP_MF)))) {
        //     return NULL;
        // }

        #ifdef VGW_CHECKSUM
        if (iphdr->chksum != 0) {
            int cksum = inet_chksum(iphdr, iphdr_hlen);
            if (cksum != 0) {
                return NULL;
            }
        }
        #endif

        int ip_proto = IPH_PROTO(iphdr);
        if (ip_proto == IP_PROTO_UDP ||
            ip_proto == IP_PROTO_TCP ||
            ip_proto == IP_PROTO_ICMP) {
            return iphdr;
        }
        return NULL;
    }
    inline static void ipv4_loopback() {
        std::shared_ptr<boost::asio::deadline_timer> ticktmr_ = IPV4_TICKTMR_;
        if (!ticktmr_) {
            ticktmr_ = make_shared_object<boost::asio::deadline_timer>(ETHERNET_CONTEXT_);
            IPV4_TICKTMR_ = ticktmr_;
        }

        auto callbackf = [ticktmr_](const boost::system::error_code& ec) {
            if (!ec) {
                uint64_t now = ++IPV4_TIME_;
                ipv4_update(now);
                ipv4_loopback();
            }
        };
        ticktmr_->expires_from_now(boost::posix_time::seconds(1));
        ticktmr_->async_wait(callbackf);
    }

    uint64_t ipv4_time() {
        return IPV4_TIME_;
    }

    void ipv4_init() {
        udp_init();
        ipv4_loopback();
    }

    bool ipv4_output(struct ip_hdr* ip, int len) {
        if (!ip || len < 1) {
            return false;
        }

        struct eth_addr dst;
        if (!etharp_get(ip->dest, dst)) {
            return false;
        }

        char buff[sizeof(struct eth_hdr) + ETHBUF_IANA_HWSNAP_ETHERNET];
        int sz = sizeof(struct eth_hdr) + len;
        struct eth_hdr* pkg = (struct eth_hdr*)buff;
        pkg->src = ETHERNET_MAC;
        pkg->dst = dst;
        pkg->proto = htons(ETHTYPE_IP);
        memcpy(pkg + 1, ip, len);
        
        return ethernet_output(pkg, sz) == 0;
    }

    bool ipv4_output_(const IPFrame* packet) {
        typedef IPFrame::IPFramePtr              IPFramePtr;
        typedef std::shared_ptr<BufferSegment>   Buffer;

        if (!packet) {
            return false;
        }

        while (0 == packet->Id) {
            const_cast<IPFrame*>(packet)->Id = IPFrame::NewId();
        }

        std::vector<IPFramePtr> subpackages;
        int subpacketl = IPFrame::Subpackages(subpackages,
            std::shared_ptr<IPFrame>(const_cast<IPFrame*>(packet), [](const IPFrame*) {}));
        if (subpacketl <= 0) {
            return false;
        }

        for (int i = 0; i < subpacketl; i++) {
            IPFramePtr frame_ = subpackages[i];
            if (NULL == frame_) {
                return false;
            }

            Buffer message_ = frame_->ToArray();
            if (NULL == message_ || message_->Length <= 0) {
                return false;
            }

            bool written = ipv4_output((struct ip_hdr*)message_->Buffer.get(), message_->Length);
            if (!written) {
                return false;
            }
        }
        return true;
    }

    void ipv4_input(struct ip_hdr* ip, int len) {
        int proto = ip_hdr::IPH_PROTO(ip);
        switch (proto) {
        case ip_hdr::IP_PROTO_UDP:
            break;
        case ip_hdr::IP_PROTO_ICMP:
            break;
        default:
            return;
        };
        std::shared_ptr<IPFrame> packet = IPFrame::Parse(ip, len, false);
        if (packet) {
            ipv4_input(packet);
        }
    }

    inline static void ipv4_input(const std::shared_ptr<IPFrame>& packet) {
        if (packet->ProtocolType == ip_hdr::IP_PROTO_UDP) {
            if (!ipv4_fragment(packet)) {
                std::shared_ptr<UdpFrame> frame = UdpFrame::Parse(packet.get());
                if (NULL != frame) {
                    udp_input(packet, frame);
                }
            }
        }
        else if (packet->ProtocolType == ip_hdr::IP_PROTO_ICMP) {
            if (!ipv4_fragment(packet)) {
                std::shared_ptr<IcmpFrame> frame = IcmpFrame::Parse(packet.get());
                if (NULL != frame) {
                    icmp_input(packet, frame);
                }
            }
        }
    }

    inline static bool ipv4_fragment(const std::shared_ptr<IPFrame>& packet) {
        if ((packet->Flags & IPFlags::IP_MF) != 0 ||
            ((packet->Flags & IPFlags::IP_OFFMASK) != 0 && packet->GetFragmentOffset() > 0)) {
            std::shared_ptr<BufferSegment> payload = packet->Payload;
            if (NULL == payload || payload->Length <= 0) {
                return false;
            }
            Subpackage::IPFramePtr originNew;
            std::string key;
            {
                char sz[255];
                snprintf(sz, sizeof(sz), "%u->%u/%u", packet->Source, packet->Destination, packet->Id);
                key = sz;
            }
            do {
                std::shared_ptr<Subpackage> subpackage;
                {
                    SubpackageTable::iterator tail = IPV4_SUBPACKAGES_.find(key);
                    SubpackageTable::iterator endl = IPV4_SUBPACKAGES_.end();
                    if (tail != endl) {
                        subpackage = tail->second;
                    }
                    else {
                        subpackage = make_shared_object<Subpackage>();
                        IPV4_SUBPACKAGES_.insert(SubpackageTable::value_type(key, subpackage));
                    }
                }
                std::vector<Subpackage::IPFramePtr>& frames = subpackage->Frames;
                size_t index = frames.size();
                if (index <= 0) {
                    frames.push_back(packet);
                }
                else {
                    while (index > 0) {
                        Subpackage::IPFramePtr left = frames[index - 1];
                        if (packet->GetFragmentOffset() >= left->GetFragmentOffset()) {
                            break;
                        }
                        else {
                            index--;
                        }
                    }
                    frames.insert(frames.begin() + index, packet);
                }
                int nextFragementOffset = 0;
                bool fullFragementOffset = true;
                {
                    size_t count = frames.size();
                    for (index = 0; index < count; index++) {
                        Subpackage::IPFramePtr left = frames[index];
                        if (left->GetFragmentOffset() != nextFragementOffset) {
                            fullFragementOffset = false;
                            break;
                        }
                        nextFragementOffset = left->GetFragmentOffset() + left->Payload->Length;
                    }
                    if (fullFragementOffset) {
                        Subpackage::IPFramePtr left = frames[frames.size() - 1];
                        if ((packet->Flags & IPFlags::IP_MF) == 0 &&
                            (packet->Flags & IPFlags::IP_OFFMASK) != 0 && left->GetFragmentOffset() > 0) {
                            left = frames[0];
                            {
                                SubpackageTable::iterator tail = IPV4_SUBPACKAGES_.find(key);
                                SubpackageTable::iterator endl = IPV4_SUBPACKAGES_.end();
                                if (tail != endl) {
                                    IPV4_SUBPACKAGES_.erase(tail);
                                }
                            }
                            std::shared_ptr<Byte> buffer = make_shared_alloc<Byte>(nextFragementOffset);
                            MemoryStream ms(buffer, nextFragementOffset);
                            {
                                for (index = 0, count = frames.size(); index < count; index++) {
                                    std::shared_ptr<BufferSegment> payload = frames[index]->Payload;
                                    ms.Write(payload->Buffer.get(), 0, payload->Length);
                                }
                            }
                            originNew = make_shared_object<IPFrame>();
                            originNew->AddressesFamily = left->AddressesFamily;
                            originNew->ProtocolType = left->ProtocolType;
                            originNew->Source = left->Source;
                            originNew->Destination = left->Destination;
                            originNew->Payload = make_shared_object<BufferSegment>(buffer, nextFragementOffset);
                            originNew->Id = left->Id;
                            originNew->Options = left->Options;
                            originNew->Tos = left->Tos;
                            originNew->Ttl = left->Ttl;
                            originNew->Flags = IPFlags::IP_DF;
                            originNew->SetFragmentOffset(0);
                        }
                    }
                }
            } while (0);
            if (NULL != originNew) {
                ipv4_input(originNew);
            }
            return true;
        }
        else {
            return false;
        }
    }

    inline static bool ipv4_update(uint64_t now) {
        std::vector<std::string> releases;
        SubpackageTable::iterator endl = IPV4_SUBPACKAGES_.end();
        SubpackageTable::iterator tail = IPV4_SUBPACKAGES_.begin();
        for (; tail != endl; ++tail) {
            const Subpackage::Ptr& subpackage = tail->second;
            if (now >= subpackage->FinalizeTime || // 滴答时间是否发生数值溢出的现象？
                (subpackage->FinalizeTime > Subpackage::MAX_FINALIZE_TIME && now <= Subpackage::MAX_FINALIZE_TIME)) {
                releases.push_back(tail->first);
            }
        }
        for (size_t i = 0, l = releases.size(); i < l; i++) {
            const std::string& key = releases[i];
            SubpackageTable::iterator tail = IPV4_SUBPACKAGES_.find(key);
            if (tail != endl) {
                IPV4_SUBPACKAGES_.erase(tail);
            }
        }
        return true;
    }
}