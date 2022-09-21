#if (!defined(_WIN32) || LINUX)

#include <pcap.h>
#include <libtcpip.h>
#include <mutex>
#include "gw.h"
#include "ipv4.h"
#include "checksum.h"
#include "etharp.h"
#include "ethernet.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <wait.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <boost/stacktrace.hpp>

#ifdef __cplusplus
extern "C" 
#endif
int                                                             pfring_send(void *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet);

namespace vgw {                     
    extern uint32_t                                             ETHERNET_IP;
    extern uint32_t                                             ETHERNET_NGW;
    extern uint32_t                                             ETHERNET_MASK;
    extern struct eth_addr                                      ETHERNET_MAC;
    extern std::string                                          ETHERNET_NAME_;

    class SUBNAT_CHANNEL {
    public:
        SUBNAT_CHANNEL(int snat, int direction);
        inline ~SUBNAT_CHANNEL() {
            Close();
        }

    public:
        inline bool                                             IsOpen() {
            return sockfd_ != -1;
        }
        inline void                                             Close() {
            int fd_ = sockfd_;
            if (fd_ != -1) {
                sockfd_ = -1;
                close(fd_);
            }
        }
        inline int                                              Read(void* buf, int len) {
            if (!buf || len < 1) {
                return -1;
            }

            int fd_ = sockfd_;
            if (fd_ == -1) {
                return -1;
            }

            struct sockaddr_un destinationEP;
            destinationEP.sun_family = AF_UNIX;

            socklen_t addrlen = sizeof(destinationEP);
            int err_ = recvfrom(fd_, buf, len, MSG_NOSIGNAL, (struct sockaddr*)&destinationEP, &addrlen);
            if (err_ < 0) { // ECONNREFUSED
                err_ = errno;
                if (err_ == EBADF || err_ == ENOENT) {
                    return -1;
                }
                return 0;
            }
            return err_;
        }
        inline int                                              Write(void* buf, int len) {
            if (!buf || len < 1) {
                return -1;
            }

            int fd_ = sockfd_;
            if (fd_ == -1) {
                return -1;
            }

            int err = sendto(fd_, buf, len, MSG_NOSIGNAL, (struct sockaddr*)tx_un, sizeof(*tx_un));
            if (err < 0) {
                int err_ = errno; // EPIPE
                if (err_ == EINTR || err_ == EAGAIN) {
                    return 0;
                }
                return -1;
            }
            return 1;
        }
        inline static SUBNAT_CHANNEL*                           New(int snat, int direction) {
            SUBNAT_CHANNEL* channel_ = new SUBNAT_CHANNEL(snat, direction);
            if (channel_->IsOpen()) {
                return channel_;
            }
            else {
                delete channel_;
                return NULL;
            }
        }
        inline int                                              Id() {
            return snat_;
        }

    private:                        
        int                                                     sockfd_;
        int                                                     snat_;
        struct sockaddr_un*                                     rx_un;
        struct sockaddr_un*                                     tx_un;
        struct sockaddr_un                                      as_un[2];
    };                      
    static SUBNAT_CHANNEL*                                      SUBNAT_NIC = NULL;
    static std::vector<SUBNAT_CHANNEL*>                         SUBNAT_CHANNEL_;
    struct SUBNAT_TX_DATA {
        void*                                                   RING;
        pcap_t*                                                 PCAP;
        uint64_t                                                CONN;
    };
    struct SUBNAT_NAT_ENTRY {           
        uint32_t                                                INDEX_;
        uint64_t                                                TIMEOUT_;
    };
    typedef std::unordered_map<uint64_t, SUBNAT_NAT_ENTRY>      SUBNAT_NAT_TABLE;

    static uint32_t const                                       SUBNAT_NAT_TIMEOUT_ = 72;
    static uint32_t const                                       SUBNAT_NAT_TICKTIME_ = 20;
    static std::vector<SUBNAT_TX_DATA>                          SUBNAT_TX;
    static SUBNAT_NAT_TABLE                                     SUBNAT_NAT_TABLE_;

    void*                                                       pfring_live_open_packet_device(const std::string& device, int rx_or_tx);
    pcap_t*                                                     pcap_live_open_packet_device(std::string device_);

    std::string                                                 subnat_stacktrace() {
        std::stringstream stacktrace_;
        stacktrace_ << boost::stacktrace::stacktrace();
        return stacktrace_.str();
    }

    bool                                                        subnat_setnonblocking(int fd, bool nonblocking) {
        if (fd == -1) {
            return false;
        }

        int flags = fcntl(fd, F_GETFD, 0);
        if (flags == -1) {
            return false;
        }

        if (nonblocking) {
            flags |= O_NONBLOCK;
        }
        else {
            flags &= ~O_NONBLOCK;
        }
        return fcntl(fd, F_SETFL, flags) != -1;
    }

    int                                                         subnat_snat(int index) {
        if (index < 0) {
            index = 0;
        }
        return 10000 + index + 1;
    }

    std::string                                                 subnat_path() {
        static std::string path = "/root/.vgw/snat";
        mkdir("/root/.vgw", 0777);
        return path;
    }

    bool                                                        subnat_exec(int snat) {
        char exe[260 + 1];
        int len = readlink("/proc/self/exe", exe, 260);
        exe[len] = '\x0';

        char ip[100];
        snprintf(ip, sizeof(ip), "--ip=%s", boost::asio::ip::address_v4(htonl(ETHERNET_IP)).to_string().data());

        char ngw[100];
        snprintf(ngw, sizeof(ngw), "--ngw=%s", boost::asio::ip::address_v4(htonl(ETHERNET_NGW)).to_string().data());

        char mask[100];
        snprintf(mask, sizeof(mask), "--mask=%s", boost::asio::ip::address_v4(htonl(ETHERNET_MASK)).to_string().data());

        char mac[100];
        snprintf(mac, sizeof(mac), "--mac=%02x:%02x:%02x:%02x:%02x:%02x", 
            ETHERNET_MAC.s_data[0],
            ETHERNET_MAC.s_data[1],
            ETHERNET_MAC.s_data[2],
            ETHERNET_MAC.s_data[3],
            ETHERNET_MAC.s_data[4],
            ETHERNET_MAC.s_data[5]);
        
        char subnat[1000];
        snprintf(subnat, sizeof(subnat), "--snat=%d", snat);
        
        pid_t pid = fork();
        if (0 == pid) {
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            char *const argv[] = {
                exe, 
                ip, 
                ngw, 
                mask, 
                mac,
                (char*)"--lwip=yes",
                (char*)"--ncpu=1",
                subnat,
                NULL,
            };
            char *const envp[] = {NULL};
            execve(argv[0], argv, envp);
            kill(getpid(), SIGKILL);
            _exit(127);
            return 0;
        }
        return pid < 0 ? false : true;
    }

    bool                                                        subnat_otx() {
        SUBNAT_TX_DATA stx = {NULL, NULL, 0};
        stx.RING = pfring_live_open_packet_device(ETHERNET_NAME_, 0);
        if (stx.RING) {
            SUBNAT_TX.push_back(stx);
            return true;
        }

        stx.PCAP = pcap_live_open_packet_device(ETHERNET_NAME_);
        if (stx.PCAP) {
            SUBNAT_TX.push_back(stx);
            return true;
        }
        return false;
    }

    bool                                                        subnat_wtx(int index, struct eth_hdr* eth, int len) {
        if (!eth || len < sizeof(*eth)) {
            return false;
        }

        if (index < 0 || index >= SUBNAT_TX.size()) {
            return false;
        }

        SUBNAT_TX_DATA& stx = SUBNAT_TX[index];
        if (stx.RING) {
            return pfring_send(stx.RING, (char*)eth, len, 1) == -1 ? -1 : 0; 
        }

        pcap_t* pcap = stx.PCAP;
        if (!pcap) {
            return false;
        }
        return pcap_inject(pcap, (u_char*)eth, len) == -1 ? -1 : 0;
    }

    void                                                        subnat_exit() {
        bool subprocess = NULL != SUBNAT_NIC;
        ethernet_release();
        if (subprocess) {
            kill(getppid(), SIGKILL);
        }
        kill(getpid(), SIGKILL);
        _exit(127);
    }

    bool                                                        subnat_rack(SUBNAT_CHANNEL* channel_) {
        std::shared_ptr<bool> success = make_shared_object<bool>(false);
        std::thread([success, channel_] {
            int snat = 0;
            int by = channel_->Read(&snat, sizeof(snat));
            if (by < 1) {
                return;
            }
            if (snat == channel_->Id()) {
                *success = true;
            }
        }).detach();
        for (int i = 0; i < 20; i++) {
            int err = 0;
            channel_->Write(&err, sizeof(err));
            if (*success) {
                break;
            }
            usleep(50 * 1000);
        }
        return *success;
    }

    bool                                                        subnat_loopwtx(int index_) {
        if (index_ < 0 || index_ >= SUBNAT_CHANNEL_.size()) {
            return false;
        }

        SUBNAT_CHANNEL* channel_ = SUBNAT_CHANNEL_[index_];
        if (!channel_) {
            return false;
        }

        std::thread([channel_, index_] {
            SetThreadPriorityToMaxLevel();

            char eth_[sizeof(struct eth_hdr) + ETHBUF_IANA_HWSNAP_ETHERNET];
            char* buff = &eth_[sizeof(struct eth_hdr)];
            for (; ;) {
                int len = channel_->Read(buff, ETHBUF_IANA_HWSNAP_ETHERNET);
                if (len < 0) {
                    break;
                }

                if (len < ip_hdr::IP_HLEN) {
                    continue;
                }

                struct ip_hdr* ip = (struct ip_hdr*)buff;
                struct eth_addr dst;
                if (!etharp_get(ip->dest, dst)) {
                    continue;
                }

                struct eth_hdr* pkg = (struct eth_hdr*)eth_;
                pkg->src = ETHERNET_MAC;
                pkg->dst = dst;
                pkg->proto = htons(ETHTYPE_IP);
                subnat_wtx(index_, pkg, sizeof(struct eth_hdr) + len);
            }
            subnat_exit();
        }).detach();
        return true;
    }

    int                                                         subnat_listen(int concurrent) {
        if (concurrent < 1) {
            concurrent = std::max<int>(1, std::thread::hardware_concurrency());
        }

        concurrent = std::min<int>(9999, concurrent - 1);
        if (concurrent < 1) {
            return 0;
        }

        for (int i = 0; i < concurrent; i++) {
            SUBNAT_CHANNEL* channel_ = SUBNAT_CHANNEL::New(subnat_snat(i), 0);
            if (!channel_) {
                return -1;
            }

            if (!subnat_exec(channel_->Id())) {
                return -1;
            }

            if (!subnat_rack(channel_)) {
                return -1;
            }

            if (!subnat_otx()) {
                return -1;
            }
            SUBNAT_CHANNEL_.push_back(channel_);
        }
        
        for (int index_ = 0; index_ < concurrent; index_++) {
            if (!subnat_loopwtx(index_)) {
                return -1;
            }
        }
        return 1;
    }

    bool                                                        sunat_cack(int snat) {
        std::shared_ptr<bool> success = make_shared_object<bool>(false);
        std::thread([success] {
            int err = 0;
            int by = SUBNAT_NIC->Read(&err, sizeof(err));
            if (by < 1) {
                subnat_exit();
                return;
            }
            if (err == 0) {
                *success = true;
            }
        }).detach();
        for (int i = 0; i < 20; i++) {
            int err = SUBNAT_NIC->Write(&snat, sizeof(snat));
            if (err < 0) {
                subnat_exit();
                return false;
            }
            if (*success) {
                break;
            }
            usleep(50 * 1000);
        }
        return *success;
    }

    bool                                                        subnat_loopback(int snat) {
        SUBNAT_NIC = SUBNAT_CHANNEL::New(snat, 1);
        if (!SUBNAT_NIC) {
            subnat_exit();
            return false;
        }

        if (!sunat_cack(snat)) {
            subnat_exit();
            return false;
        }

        if (!libtcpip_loopback(ETHERNET_IP, ETHERNET_IP, ETHERNET_MASK, [](void* packet, int size) {
            int status = SUBNAT_NIC->Write(packet, size);
            if (status > 0) {
                return true;
            }
            if (status == 0) {
                return false;
            }
            subnat_exit();
            return false;
        })) {
            subnat_exit();
            return false;
        }
    
        char buff[ETHBUF_IANA_HWSNAP_ETHERNET];
        for (; ;) {
            int len = SUBNAT_NIC->Read(buff, ETHBUF_IANA_HWSNAP_ETHERNET);
            if (len < 0) {
                break;
            }

            if (len < ip_hdr::IP_HLEN) {
                continue;
            }
            libtcpip_input((struct ip_hdr*)buff, len);
        }
        subnat_exit();
        return true;
    }

    bool                                                        subnat_clnat() {
        static const int MAX_RELEASE_COUNT_ = 10000;
        static uint64_t SUBNAT_LAST_ = 0;

        uint64_t NOWT_ = ipv4_time();
        uint64_t DIFF_ = NOWT_ - SUBNAT_LAST_;
        if (DIFF_ < SUBNAT_NAT_TICKTIME_) { 
            return false;
        }
        else {
            SUBNAT_LAST_ = NOWT_;
        }

        uint64_t releases_[MAX_RELEASE_COUNT_];
        uint32_t releases_count_ = 0;

        SUBNAT_NAT_TABLE::iterator tail_ = SUBNAT_NAT_TABLE_.begin();
        SUBNAT_NAT_TABLE::iterator endl_ = SUBNAT_NAT_TABLE_.end();
        for (; tail_ != endl_; tail_++) {
            SUBNAT_NAT_ENTRY& entry_ = tail_->second;
            DIFF_ = NOWT_ - entry_.TIMEOUT_;
            if (DIFF_ >= SUBNAT_NAT_TIMEOUT_) {
                if (releases_count_ >= MAX_RELEASE_COUNT_) {
                    break;
                }
                releases_[releases_count_++] = tail_->first;
            }
        }

        for (uint32_t i_ = 0; i_ < releases_count_; i_++) {
            SUBNAT_NAT_TABLE_.erase(releases_[i_]);
        }
        return true;
    }

    int                                                         subnat_wxnat(uint32_t address, uint32_t port) {
        uint32_t concurrent_ = SUBNAT_CHANNEL_.size();
        if (concurrent_ == 0) {
            return -1;
        }

        if (concurrent_ == 1) {
            return 0;
        }

        subnat_clnat();

        uint64_t key_ = (uint64_t)port << 32 | (uint64_t)address;
        SUBNAT_NAT_TABLE::iterator tail_ = SUBNAT_NAT_TABLE_.find(key_);
        SUBNAT_NAT_TABLE::iterator endl_ = SUBNAT_NAT_TABLE_.end();
        if (tail_ == endl_) {
            int k_ = 0;
            for (uint32_t i_ = 0; i_ < concurrent_; i_++) {
                if (SUBNAT_TX[k_].CONN > SUBNAT_TX[i_].CONN) {
                    k_ = i_;
                }
            }
            SUBNAT_NAT_ENTRY entry_ = {(uint32_t)k_, SUBNAT_NAT_TIMEOUT_};
            if (!SUBNAT_NAT_TABLE_.insert(std::make_pair(key_, entry_)).second) {
                return -1;
            }
            SUBNAT_TX[k_].CONN++;
            return k_;
        }
        else {
            SUBNAT_NAT_ENTRY& entry_ = tail_->second;
            entry_.TIMEOUT_ = SUBNAT_NAT_TIMEOUT_;
            return entry_.INDEX_;
        }
    }

    bool                                                        subnat_write(struct ip_hdr* iphdr, int iplen) {
        #pragma pack(push, 1)
        struct tcp_hdr {
            unsigned short                                              src;
            unsigned short                                              dest;
            unsigned int                                                seqno;
            unsigned int                                                ackno;
            unsigned short                                              hdrlen_rsvd_flags;
            unsigned short                                              wnd;
            unsigned short                                              chksum;
            unsigned short                                              urgp;
        };
        #pragma pack(pop)

        if (!iphdr || iplen < 1) {
            return false;
        }

        int ipproto = ip_hdr::IPH_PROTO(iphdr);
        if (ipproto != ip_hdr::IP_PROTO_TCP) {
            return false;
        }

        int iphdr_hlen = ip_hdr::IPH_HL(iphdr) << 2;
        int tcplen = iplen - iphdr_hlen;
        if (tcplen < 0) {
            return false;
        }

        char* payload = (char*)iphdr + iphdr_hlen;
        struct tcp_hdr* tcphdr = (struct tcp_hdr*)payload;
        if (!tcphdr) {
            return false;
        }

        int index = subnat_wxnat(iphdr->src, tcphdr->src);
        if (index < 0) {
            return false;
        }

        int status = SUBNAT_CHANNEL_[index]->Write((char*)iphdr, iplen);
        if (status > 0) {
            return true;
        }
        if (status == 0) {
            return false;
        }
        subnat_exit();
        return false;
    }

    SUBNAT_CHANNEL::SUBNAT_CHANNEL(int snat, int direction)
        : sockfd_(-1)
        , snat_(snat)
        , rx_un(&as_un[0])
        , tx_un(&as_un[1]) {
        std::string rx = subnat_path() + "." + std::to_string(snat);
        std::string tx = rx + ".";

        memset(rx_un, 0, sizeof(*rx_un));
        memset(tx_un, 0, sizeof(*tx_un));

        rx_un->sun_family = AF_UNIX;
        tx_un->sun_family = AF_UNIX;

        strncpy(rx_un->sun_path, rx.data(), sizeof(rx_un->sun_path) - 1);
        strncpy(tx_un->sun_path, tx.data(), sizeof(tx_un->sun_path) - 1);
        if (direction) {
            rx_un = &as_un[1];
            tx_un = &as_un[0];
        }
        else {
            rx_un = &as_un[0];
            tx_un = &as_un[1];
        }

        do {
            int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
            if (sock == -1) {
                break;
            }

            if (!subnat_setnonblocking(sock, false)) {
                close(sock);
                break;
            }

            unlink(rx_un->sun_path);
            if (bind(sock, (struct sockaddr*)rx_un, sizeof(*rx_un)) == -1) {
                close(sock);
                break;
            }

            sockfd_ = sock;
        } while (0);
    }
}
#endif