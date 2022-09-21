#include "ipv4.h"
#include "etharp.h"
#include "ethernet.h"

namespace vgw {
    typedef std::mutex                                      MUTEX;
    typedef std::lock_guard<MUTEX>                          MUTEXSCOPE;

    extern uint32_t                                         ETHERNET_IP;
    extern uint32_t                                         ETHERNET_MASK;
    extern eth_addr                                         ETHERNET_MAC;
    extern boost::asio::io_context                          ETHERNET_CONTEXT_;

    static std::shared_ptr<boost::asio::deadline_timer>     ETHARP_TICKTMR_;
    static MUTEX                                            ETHARP_LOCK_;

    typedef struct etharp_arp_eth_addr_key {
        inline static int64_t                               hash(const struct eth_addr& key) {
            return (int64_t)key.s_zero.w << 32 | key.s_zero.dw;
        }
        inline std::size_t                                  operator()(const struct eth_addr& key) const {
            return std::hash<int64_t>()(hash(key));
        }
        inline bool                                         operator()(const struct eth_addr& left, const struct eth_addr& right) const {
            return hash(left) == hash(right);
        }
    }                                                       ETHARP_ARP_ETH_ADDR_KEY;
    typedef struct etharp_arp_entry {
        struct eth_addr                                     mac;
        uint32_t                                            ip;               // MAC-IP
        uint64_t                                            last;             // 上次更新时间
        uint64_t                                            sent;             // 上次广播时间
    }                                                       ETHARP_ARP_ENTRY; // 以太网ARP缓存条目
    typedef std::unordered_map<struct eth_addr,
        ETHARP_ARP_ENTRY,
        ETHARP_ARP_ETH_ADDR_KEY,
        ETHARP_ARP_ETH_ADDR_KEY>                            ETHARP_ET_TABLE;
    typedef std::unordered_map<uint32_t, struct eth_addr>   ETHARP_IP_TABLE;

    static ETHARP_ET_TABLE                                  ETHARP_ET_TABLE_;
    static ETHARP_IP_TABLE                                  ETHARP_IP_TABLE_;

    static const int                                        ETHARP_ARP_ENTRY_AGING_TIME = 60; // X秒以后老化ARP缓存条目
    static const int                                        ETHARP_ARP_ENTRY_ASK_TIME = 10; // X秒以后广播ARP请求

    inline static void etharp_raw(
        struct eth_addr& ethsrc_addr,
        struct eth_addr& ethdst_addr,
        struct eth_addr& hwsrc_addr, uint32_t ipsrc_addr,
        struct eth_addr& hwdst_addr, uint32_t ipdst_addrt,
        uint16_t opcode) {
#pragma pack(push, 1)
        struct {
            struct eth_hdr      eth;
            struct etharp_hdr   arp;
        } etharp_packet;
#pragma pack(pop)

        etharp_packet.eth.dst = ethdst_addr;
        etharp_packet.eth.src = ethsrc_addr;
        etharp_packet.eth.proto = htons(ETHTYPE_ARP);

        etharp_packet.arp.hwtype = htons(ETHARP_IANA_HWTYPE_ETHERNET);
        etharp_packet.arp.shwaddr = hwsrc_addr;
        etharp_packet.arp.dhwaddr = hwdst_addr;
        etharp_packet.arp.opcode = htons(opcode);
        etharp_packet.arp.sipaddr = ipsrc_addr;
        etharp_packet.arp.dipaddr = ipdst_addrt;
        etharp_packet.arp.proto = htons(ETHTYPE_IP);
        etharp_packet.arp.hwlen = ETH_HWADDR_LEN;
        etharp_packet.arp.protolen = sizeof(ipdst_addrt);

        ethernet_output(&etharp_packet.eth, sizeof(etharp_packet));
    }

    uint32_t etharp_get(const struct eth_addr& hwaddr) {
        MUTEXSCOPE __LOCK__(ETHARP_LOCK_);

        ETHARP_ET_TABLE::iterator tail_ = ETHARP_ET_TABLE_.find(hwaddr);
        ETHARP_ET_TABLE::iterator endl_ = ETHARP_ET_TABLE_.end();
        if (tail_ == endl_) {
            return 0;
        }
        return tail_->second.ip;
    }

    bool etharp_get(uint32_t ip, struct eth_addr& hwaddr) {
        MUTEXSCOPE __LOCK__(ETHARP_LOCK_);

        ETHARP_IP_TABLE::iterator tail_ = ETHARP_IP_TABLE_.find(ip);
        ETHARP_IP_TABLE::iterator endl_ = ETHARP_IP_TABLE_.end();
        if (tail_ == endl_) {
            return false;
        }

        hwaddr = tail_->second;
        return true;
    }

    inline static bool etharp_set(struct eth_addr& hwaddr, uint32_t ipaddr, bool set) {
        if (ipaddr == INADDR_ANY || ipaddr == INADDR_BROADCAST) {
            return false;
        }

        int64_t MAC = etharp_arp_eth_addr_key::hash(hwaddr);
        if (MAC == 0x000000000000 ||
            MAC == 0xFFFFFFFFFFFF) {
            return false;
        }

        bool add = set ? false : true;
        if (MAC == etharp_arp_eth_addr_key::hash(ETHERNET_MAC)) {
            return false;
        }

        uint64_t now = ipv4_time();
        if (add) {
            ETHARP_ET_TABLE::iterator tail = ETHARP_ET_TABLE_.find(hwaddr);
            ETHARP_ET_TABLE::iterator endl = ETHARP_ET_TABLE_.end();
            if (tail != endl) {
                return false;
            }
        }

        ETHARP_ARP_ENTRY& entry_ = ETHARP_ET_TABLE_[hwaddr];
        entry_.ip = ipaddr;
        entry_.mac = hwaddr;
        entry_.last = now;
        if (add) {
            entry_.sent = now;
        }
        ETHARP_IP_TABLE_[ipaddr] = hwaddr;
        return true;
    }

    bool etharp_set(struct eth_addr& hwaddr, uint32_t ipaddr) {
        return etharp_set(hwaddr, ipaddr, true);
    }

    bool etharp_add(struct eth_addr& hwaddr, uint32_t ipaddr) {
        return etharp_set(hwaddr, ipaddr, false);
    }

    inline static void etharp_update_all_arps(uint64_t now) {
        std::vector<struct eth_addr> release_;
        {
            MUTEXSCOPE __LOCK__(ETHARP_LOCK_);
            ETHARP_ET_TABLE::iterator tail_ = ETHARP_ET_TABLE_.begin();
            ETHARP_ET_TABLE::iterator endl_ = ETHARP_ET_TABLE_.end();

            for (; tail_ != endl_; ++tail_) {
                ETHARP_ARP_ENTRY& entry_ = tail_->second;
                if (entry_.last > now || (now - entry_.last) >= ETHARP_ARP_ENTRY_AGING_TIME) {
                    release_.push_back(tail_->first);
                    continue;
                }

                uint64_t sent = entry_.sent;
                if (sent > now || (now - sent) >= ETHARP_ARP_ENTRY_ASK_TIME) {
                    static struct eth_addr BROADCAST_MAC = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
                    static struct eth_addr NONE_MAC = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

                    entry_.sent = now;
                    etharp_raw(ETHERNET_MAC, BROADCAST_MAC, 
                        ETHERNET_MAC, ETHERNET_IP, 
                        NONE_MAC, entry_.ip,
                        ARP_REQUEST);
                }
            }

            for (size_t i_ = 0, l_ = release_.size(); i_ < l_; i_++) {
                tail_ = ETHARP_ET_TABLE_.find(release_[i_]);
                if (tail_ != endl_) {
                    ETHARP_ET_TABLE_.erase(tail_);
                }
            }
        }
    }

    inline static void etharp_update_all_cips(uint64_t now) {
        std::vector<uint32_t> release_;
        {
            MUTEXSCOPE __LOCK__(ETHARP_LOCK_);
            ETHARP_IP_TABLE::iterator tail_ = ETHARP_IP_TABLE_.begin();
            ETHARP_IP_TABLE::iterator endl_ = ETHARP_IP_TABLE_.end();

            ETHARP_ET_TABLE::iterator EL_ = ETHARP_ET_TABLE_.end();
            for (; tail_ != endl_; ++tail_) {
                ETHARP_ET_TABLE::iterator TL_ = ETHARP_ET_TABLE_.find(tail_->second);
                if (TL_ == EL_) {
                    release_.push_back(tail_->first);
                }
            }

            for (size_t i_ = 0, l_ = release_.size(); i_ < l_; i_++) {
                tail_ = ETHARP_IP_TABLE_.find(release_[i_]);
                if (tail_ != endl_) {
                    ETHARP_IP_TABLE_.erase(tail_);
                }
            }
        }
    }

    inline static void etharp_update(uint64_t now) {
        etharp_update_all_arps(now);
        etharp_update_all_cips(now);
    }

    inline static void etharp_loopback() {
        MUTEXSCOPE __LOCK__(ETHARP_LOCK_);

        std::shared_ptr<boost::asio::deadline_timer> ticktmr_ = ETHARP_TICKTMR_;
        if (!ticktmr_) {
            ticktmr_ = make_shared_object<boost::asio::deadline_timer>(ETHERNET_CONTEXT_);
            ETHARP_TICKTMR_ = ticktmr_;
        }

        auto callbackf = [ticktmr_](const boost::system::error_code& ec) {
            if (!ec) {
                uint64_t now = ipv4_time();
                etharp_update(now);
                etharp_loopback();
            }
        };
        ticktmr_->expires_from_now(boost::posix_time::seconds(1));
        ticktmr_->async_wait(callbackf);
    }

    void etharp_init() {
        etharp_loopback();
    }

    void etharp_release() {
        MUTEXSCOPE __LOCK__(ETHARP_LOCK_);

        std::shared_ptr<boost::asio::deadline_timer> ticktmr_ = std::move(ETHARP_TICKTMR_);
        if (ticktmr_) {
            ETHARP_TICKTMR_ = NULL;
            try {
                boost::system::error_code ec_;
                ticktmr_->cancel(ec_);
            }
            catch (std::exception&) {}
        }
        ETHARP_ET_TABLE_.clear();
        ETHARP_IP_TABLE_.clear();
    }

    void etharp_input(struct eth_hdr* eth, struct etharp_hdr* arp, int len) {
        if ((arp->hwtype != htons(ETHARP_IANA_HWTYPE_ETHERNET)) ||
            (arp->hwlen != ETH_HWADDR_LEN) ||
            (arp->protolen != sizeof(uint32_t)) ||
            (arp->proto != htons(ETHTYPE_IP))) {
            return;
        }

        int for_us = 0;
        if (arp->dipaddr == ETHERNET_IP) {
            for_us = 1;
        }
        etharp_set(arp->shwaddr, arp->sipaddr);

        int hwtype = htons(arp->hwtype);
        switch (hwtype) {
        case ARP_REQUEST:
            /* ARP request for our address? */
            if (for_us) {
                /* send ARP response */
                etharp_raw(
                    ETHERNET_MAC, arp->shwaddr,
                    ETHERNET_MAC, ETHERNET_IP,
                    arp->shwaddr, arp->sipaddr,
                    ARP_REPLY);
            }
            break;
        case ARP_REPLY:
            break;
        };
    }
}