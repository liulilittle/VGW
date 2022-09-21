#if (!defined(_WIN32) || LINUX)
#include "gw.h"
#include "ipv4.h"
#include "checksum.h"
#include "ipv4.h"
#include "./packet/IPEndPoint.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>

#include <netpacket/packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <net/route.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <mutex>
#include <atomic>

namespace vgw {
    #pragma pack(push, 1)
    /*
     * typedef struct _tcp_hdr  
     * {  
     *     unsigned short src_port;                                //源端口号   
     *     unsigned short dst_port;                                //目的端口号   
     *     unsigned int seq_no;                                    //序列号   
     *     unsigned int ack_no;                                    //确认号   
     *     #if LITTLE_ENDIAN                               
     *     unsigned char reserved_1:4;                             //保留6位中的4位首部长度   
     *     unsigned char thl:4;                                    //tcp头部长度   
     *     unsigned char flag:6;                                   //6位标志   
     *     unsigned char reseverd_2:2;                             //保留6位中的2位   
     *     #else                               
     *     unsigned char thl:4;                                    //tcp头部长度   
     *     unsigned char reserved_1:4;                             //保留6位中的4位首部长度   
     *     unsigned char reseverd_2:2;                             //保留6位中的2位   
     *     unsigned char flag:6;                                   //6位标志    
     *     #endif                                  
     *     unsigned short wnd_size;                                //16位窗口大小   
     *     unsigned short chk_sum;                                 //16位TCP检验和   
     *     unsigned short urgt_p;                                  //16为紧急指针   
     * }tcp_hdr;                               
     */                                
    struct tcp_hdr {                               
    public:                            
        enum TcpFlags {                            
            TCP_FIN                                                 = 0x01,
            TCP_SYN                                                 = 0x02,
            TCP_RST                                                 = 0x04,
            TCP_PSH                                                 = 0x08,
            TCP_ACK                                                 = 0x10,
            TCP_UGR                                                 = 0x20,
            TCP_ECE                                                 = 0x40,
            TCP_CWR                                                 = 0x80,
            TCP_FLAGS                                               = 0x3f
        };                                 
                                    
    public:                            
        unsigned short                                              src;
        unsigned short                                              dest;
        unsigned int                                                seqno;
        unsigned int                                                ackno;
        unsigned short                                              hdrlen_rsvd_flags;
        unsigned short                                              wnd;
        unsigned short                                              chksum;
        unsigned short                                              urgp; // 应用层不可能出现“URGP/UGR or OPT”的协议；这类紧急协议数据报文直接RST链接即可。 
                            
    public:                            
        inline static unsigned short                                TCPH_HDRLEN(struct tcp_hdr* phdr) {
            return ((unsigned short)(__ntohs((phdr)->hdrlen_rsvd_flags) >> 12));
        }
        inline static unsigned char                                 TCPH_HDRLEN_BYTES(struct tcp_hdr* phdr) {
            return ((unsigned char)(TCPH_HDRLEN(phdr) << 2));
        }
        inline static unsigned char                                 TCPH_FLAGS(struct tcp_hdr* phdr) {
            return ((unsigned char)((__ntohs((phdr)->hdrlen_rsvd_flags) & (unsigned char)TCP_FLAGS)));
        }
        inline static unsigned short                                TCPH_HDRLEN_SET(struct tcp_hdr* phdr, int len) {
            int u = ((len) << 12) | TCPH_FLAGS(phdr);
            return (phdr)->hdrlen_rsvd_flags = __htons((unsigned short)u);
        }
        inline static unsigned short                                TCPH_HDRLEN_BYTES_SET(struct tcp_hdr* phdr, int len) {
            return TCPH_HDRLEN_SET(phdr, len >> 2);
        }
        inline static unsigned short                                PP_HTONS(int x) {
            return ((unsigned short)((((x) & (unsigned short)0x00ffU) << 8) | (((x) & (unsigned short)0xff00U) >> 8)));
        }
        inline static unsigned short                                TCPH_FLAGS_SET(struct tcp_hdr* phdr, int flags) {
            return (phdr)->hdrlen_rsvd_flags = (unsigned short)(((phdr)->hdrlen_rsvd_flags &
                PP_HTONS(~(unsigned short)TCP_FLAGS)) | __htons((unsigned short)flags));
        }
                            
    public:                            
        static struct tcp_hdr*                                      Parse(struct ip_hdr* iphdr, const void* packet, int size);  
                            
    public:                            
        static const int                                            TCP_HLEN;
    };
    #pragma pack(pop)

    typedef std::recursive_mutex                                    MUTEX;
    typedef std::lock_guard<MUTEX>                                  MUTEXSCOPE;
    typedef vgw::packet::IPEndPoint                                 IPEndPoint;

    const int tcp_hdr::TCP_HLEN                                     = sizeof(struct tcp_hdr);

    static uint32_t                                                 SYSNAT_IP = inet_addr("172.19.0.2");
    static uint32_t                                                 SYSNAT_GW = inet_addr("172.19.0.1");
    static uint32_t                                                 SYSNAT_MASK = inet_addr("255.255.255.252");
    static int                                                      SYSNAT_TUN = -1;
    static std::shared_ptr<boost::asio::posix::stream_descriptor>   SYSNAT_TUN_;
    static MUTEX                                                    SYSNAT_LOCK_;
    static IPEndPoint                                               SYSNAT_LOOPBACK_;
    static std::atomic<uint16_t>                                    SYSNAT_APORT_ = ATOMIC_VAR_INIT(IPEndPoint::MinPort);

    static const int                                                SYSNAT_MAX_FINAL_TIME = 5;
    static const int                                                SYSNAT_MAX_SYNAL_TIME = 20;
    static const int                                                SYSNAT_MAX_INACTIVITY_TIME = 72;

    class TapTcpClient; 

    struct TapTcpLink { 
    public:
        UInt32                                                      dstAddr;
        UInt16                                                      dstPort;
        UInt32                                                      srcAddr;
        UInt16                                                      srcPort;
        UInt16                                                      natPort;  
        std::atomic<bool>                                           fin;
        bool                                                        syn;
        std::shared_ptr<TapTcpClient>                               socket;
        UInt64                                                      activityTime;

    public: 
        TapTcpLink();   

    public: 
        void                                                        Act();
        void                                                        Fin();
        void                                                        Release();

    public:
        typedef std::shared_ptr<TapTcpLink>                         Ptr;
    };
    typedef std::unordered_map<std::string, TapTcpLink::Ptr>        LAN2WAN_LINK_TABLE;
    typedef std::unordered_map<int, TapTcpLink::Ptr>                WAN2LAN_LINK_TABLE;

    class TapTcpClient final : public std::enable_shared_from_this<TapTcpClient> {
    public:
        TapTcpClient(
            const boost::asio::ip::tcp::endpoint&                   localEP, /* 本地地址   */
            const boost::asio::ip::tcp::endpoint&                   remoteEP /* 远程地址   */);
        ~TapTcpClient();    

    public: 
        void                                                        Dispose();
        inline std::shared_ptr<TapTcpClient>                        GetPtr() {
            return this->shared_from_this();                    
        }
        inline const boost::asio::ip::tcp::endpoint&                GetLocalEndPoint() const {
            return this->_localEP;
        }
        inline const boost::asio::ip::tcp::endpoint&                GetNatEndPoint() const {
            return this->_natEP;
        }
        inline const boost::asio::ip::tcp::endpoint&                GetRemoteEndPoint() const {
            return this->_remoteEP;
        }
        inline bool                                                 IsDisposed() {
            return this->_disposed;
        }
        inline std::shared_ptr<boost::asio::io_context>             GetContext() const { 
            return this->_context;
        }

    public: 
        bool                                                        BeginAccept();
        bool                                                        EndAccept(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const boost::asio::ip::tcp::endpoint& natEP);
        inline std::shared_ptr<boost::asio::ip::tcp::socket>&       GetSocket() { return this->_socket; }

    private:    
        void                                                        Finalize();
        inline bool                                                 socket_to_destination(
            std::shared_ptr<boost::asio::ip::tcp::socket>           socket, 
            std::shared_ptr<boost::asio::ip::tcp::socket>           to,
            char*                                                   buf) {
            if (!socket || !to) {
                return false;
            }

            if (!socket->is_open()) {
                return false;
            }

            std::shared_ptr<TapTcpClient> self = this->GetPtr();
            socket->async_receive(boost::asio::buffer(buf, Mss), 
                [self, this, socket, to, buf](const boost::system::error_code& ec, uint32_t sz) {
                    int by = std::max<int>(-1, ec ? -1 : sz);
                    if (by < 1) {
                        this->Dispose();
                        return;
                    }

                    boost::asio::async_write(*to, boost::asio::buffer(buf, sz), 
                        [self, this, socket, to, buf](const boost::system::error_code& ec, uint32_t sz) {
                            if (ec) {
                                this->Dispose();
                            }
                            else {
                                this->socket_to_destination(socket, to, buf);
                            }
                        });
                });
            return true;
        }

    public: 
        static const int                                            Mss = 16 << 10;

    private:    
        std::atomic<bool>                                           _disposed;
        bool                                                        _baccept;
        std::shared_ptr<boost::asio::ip::tcp::socket>               _socket;
        std::shared_ptr<boost::asio::ip::tcp::socket>               _server;
        boost::asio::ip::tcp::endpoint                              _localEP;
        boost::asio::ip::tcp::endpoint                              _remoteEP;
        boost::asio::ip::tcp::endpoint                              _natEP;
        std::shared_ptr<boost::asio::io_context>                    _context;
        char                                                        _buffer[Mss];
    };

    static WAN2LAN_LINK_TABLE                                       SYSNAT_WAN2LAN;
    static LAN2WAN_LINK_TABLE                                       SYSNAT_LAN2WAN;
    static std::shared_ptr<boost::asio::io_context>                 SYSNAT_CONTEXT;

    TapTcpLink::TapTcpLink() {  
        this->dstAddr      = 0;
        this->dstPort      = 0;
        this->srcAddr      = 0;
        this->srcPort      = 0;
        this->natPort      = 0;
        this->fin          = false;
        this->syn          = true;
        this->socket       = NULL;
        this->activityTime = ipv4_time();
    }

    void                                                            TapTcpLink::Act() {
        if (!this->syn) {
            if (!this->fin) {
                this->activityTime = ipv4_time();
            }
        }
    }

    void                                                            TapTcpLink::Fin() {
        if (!this->fin.exchange(true)) {
            this->activityTime = ipv4_time();
        }
    }

    void                                                            TapTcpLink::Release() {
        std::shared_ptr<TapTcpClient> socket = std::move(this->socket);
        this->Fin();
        if (socket) {
            socket->Dispose();
        }
    }

    struct tcp_hdr*                                                 tcp_hdr::Parse(struct ip_hdr* iphdr, const void* packet, int size) {
        if (NULL == iphdr || size <= 0) {
            return NULL;
        }

        struct tcp_hdr* tcphdr = (struct tcp_hdr*)packet;
        if (NULL == tcphdr) {
            return NULL;
        }

        int hdrlen_bytes = TCPH_HDRLEN_BYTES(tcphdr);
        if (hdrlen_bytes < TCP_HLEN || hdrlen_bytes > size) { // 错误的数据报
            return NULL;
        }

        int len = size - hdrlen_bytes;
        if (len < 0) {
            return NULL;
        }

        #ifdef VGW_CHECKSUM
        if (tcphdr->chksum != 0) {
            unsigned int pseudo_checksum = inet_chksum_pseudo((unsigned char*)tcphdr,
                (unsigned int)IPPROTO_TCP,
                (unsigned int)size,
                iphdr->src,
                iphdr->dest);
            if (pseudo_checksum != 0) {
                return NULL;
            }
        }
        #endif
        return tcphdr;
    }

    inline static bool                                              ethernet_set_promisc(const std::string& device, int promisc) {
        if (device.empty()) {
            return false;
        }

        int sockfd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sockfd_ == -1) {
            return false;
        }

        struct ifreq ifr;
        strcpy(ifr.ifr_name, device.data());
        if (ioctl(sockfd_, SIOCGIFFLAGS, &ifr)){
            close(sockfd_);
            return false;
        }

        if (promisc) {
            ifr.ifr_flags |= IFF_PROMISC;
        }
        else {
            ifr.ifr_flags &= ~IFF_PROMISC;
        }

        if (ioctl(sockfd_, SIOCSIFFLAGS, &ifr)) {
            close(sockfd_);
            return false;
        }
        else {
            close(sockfd_);
            return true;
        }
    }

    inline static bool                                              ethernet_set_promisc(const std::string& device, int sockfd, int promisc) {
        if (device.empty() || sockfd == -1) {
            return false;
        }

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, device.data(), device.size());
        if (ioctl(sockfd, SIOGIFINDEX, &ifr)) {
            return false;
        }

        struct packet_mreq mreq;
        mreq.mr_ifindex = ifr.ifr_ifindex; /* if_nametoindex(device.data()); */
        mreq.mr_type = PACKET_MR_PROMISC;
        if (mreq.mr_ifindex == 0) {
            return false;
        }

        int action;
        if (promisc) {
            action = PACKET_ADD_MEMBERSHIP;
        }
        else {
            action = PACKET_DROP_MEMBERSHIP;
        }

        if (setsockopt(sockfd, SOL_PACKET, action, &mreq, sizeof(mreq)) != 0) {
            return false;
        }
        return true;
    }

    inline static int                                               ethernet_open_tun(const std::string& device, uint32_t ip, uint32_t mask) {
        if (device.empty()) {
            return -1;
        }

        int handle = open("/dev/tun", O_RDWR);
        if (handle == -1) {
            handle = open("/dev/net/tun", O_RDWR); 
            if (handle == -1) {
                return -1;
            }
        }

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));

        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        strncpy(ifr.ifr_name, device.data(), IFNAMSIZ);

        if (ioctl(handle, TUNSETIFF, &ifr)) {
            close(handle);
            return -1;
        }

        memset(&ifr, 0, sizeof(ifr));
        if (ioctl(handle, TUNGETIFF, &ifr)) {
            close(handle);
            return -1;
        }

        int sockctl_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sockctl_ == -1) {
            close(handle);
            return -1;
        }

        ifr.ifr_flags |= IFF_UP;
        if (ioctl(sockctl_, SIOCSIFFLAGS, &ifr)) {
            close(handle);
            close(sockctl_);
            return -1;
        }

        ifr.ifr_mtu = ip_hdr::MTU;
        if (ioctl(sockctl_, SIOCSIFMTU, &ifr)) {
            close(handle);
            close(sockctl_);
            return -1;
        }
        else {
            memset(&ifr, 0, sizeof(ifr));
            strcpy(ifr.ifr_name, device.data());
    
            // 设置IP地址
            struct sockaddr_in* addr = (struct sockaddr_in*)&(ifr.ifr_addr);
            addr->sin_family = AF_INET;
            addr->sin_addr.s_addr = ip;
            if (ioctl(sockctl_, SIOCSIFADDR, &ifr)) {
                close(handle);
                close(sockctl_);
                return -1;
            }
            else {
                // 设置网络掩码
                memset(&ifr.ifr_addr, 0, sizeof(ifr.ifr_addr));

                struct sockaddr_in maskAddr;
                memset(&maskAddr, 0, sizeof(maskAddr));

                maskAddr.sin_family = AF_INET;
                maskAddr.sin_addr.s_addr = mask;

                memcpy(&ifr.ifr_netmask, &maskAddr, sizeof(ifr.ifr_netmask));
                if (ioctl(sockctl_, SIOCSIFNETMASK, &ifr)) {
                    close(handle);
                    close(sockctl_);
                    return -1;
                }
            }

            // 设置MAC地址
            ifr.ifr_addr.sa_family = ARPHRD_ETHER;
            strcpy(ifr.ifr_name, device.data());
            
            memset(ifr.ifr_hwaddr.sa_data, 0, ETH_ALEN);
            ioctl(sockctl_, SIOCSIFHWADDR, &ifr); // TUN点对点无法设置MAC地址
        }
        close(sockctl_);
        return handle;
    }

    std::shared_ptr<boost::asio::io_context>                        sysnat_loopback_context();
    inline static bool                                              sysnat_ipv4_input(struct ip_hdr* iphdr, int iplen, int rx);
    inline static bool                                              sysnat_ipv4_output(struct ip_hdr* iphdr, int iplen);
    inline static bool                                              sysnat_tcp_input(struct ip_hdr* iphdr, struct tcp_hdr* pkg, int len, int rx);
    inline static bool                                              sysnat_ipv4_loopback();
    inline static bool                                              sysnat_listen_localhost();
    inline static bool                                              sysnat_listen_loopback(std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor_);
    inline static bool                                              sysnat_listen_accept(std::shared_ptr<boost::asio::ip::tcp::socket> socket_);
    inline static void                                              sysnat_close_socket(int fd);
    inline static void                                              sysnat_close_socket(const boost::asio::ip::tcp::socket& socket_);
    inline static void                                              sysnat_close_socket(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket_);
    inline static void                                              sysnat_close_socket(const std::shared_ptr<boost::asio::ip::tcp::acceptor>& socket_);
    inline static bool                                              sysnat_tcp_rst(struct ip_hdr* iphdr, struct tcp_hdr* pkg, int len, int rx);
    inline static bool                                              sysnat_tcp_opt(int lan2wan, struct ip_hdr* iphdr, struct tcp_hdr* pkg, int len, int rx);
    inline static bool                                              sysnat_tick(uint64_t now_);
    inline static void                                              sysnat_tick_loopback(std::shared_ptr<boost::asio::deadline_timer> ticktmr_);
    inline static std::string                                       sysnat_mapkey(uint32_t src, int srcport, uint32_t dst, int dstport);
    inline static uint16_t                                          sysnat_alloc_tcp_port();
    inline static std::shared_ptr<TapTcpLink>                       sysnat_find_tcp_link(int key);
    inline static std::shared_ptr<TapTcpLink>                       sysnat_find_tcp_link(const std::string& key);
    inline static std::shared_ptr<TapTcpLink>                       sysnat_alloc_tcp_link(uint32_t src, int srcport, uint32_t dst, int dstport);
    inline static bool                                              sysnat_close_tcp_link(const std::shared_ptr<TapTcpLink>& link, bool fin = false);
    inline static void                                              sysnat_release_tcp_link(int key);
    inline static void                                              sysnat_release_tcp_link(uint32_t src, int srcport, uint32_t dst, int dstport);

    bool                                                            sysnat_ipv4_init() {
        MUTEXSCOPE __LOCK__(SYSNAT_LOCK_);
        if (SYSNAT_TUN != -1) {
            return false;
        }

        SYSNAT_TUN = ethernet_open_tun("vgw", SYSNAT_IP, SYSNAT_MASK); // tun%d
        if (SYSNAT_TUN == -1) {
            return false;
        }

        if (!SYSNAT_CONTEXT) {
            SYSNAT_CONTEXT = sysnat_loopback_context();
        }

        SYSNAT_TUN_ = make_shared_object<boost::asio::posix::stream_descriptor>(*SYSNAT_CONTEXT, SYSNAT_TUN);
        if (!SYSNAT_TUN_) {
            return false;
        }
        
        return sysnat_listen_localhost() && sysnat_ipv4_loopback();
    }

    bool                                                            sysnat_ipv4_input(struct ip_hdr* iphdr, int iplen) { 
        return sysnat_ipv4_input(iphdr, iplen, 1);
    }

    inline static bool                                              sysnat_ipv4_input(struct ip_hdr* iphdr, int iplen, int rx) {
        iphdr = ip_hdr::Parse(iphdr, iplen);
        if (!iphdr) {
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
        struct tcp_hdr* tcphdr = tcp_hdr::Parse(iphdr, payload, tcplen);
        if (!tcphdr) {
            return false;
        }
        return sysnat_tcp_input(iphdr, tcphdr, tcplen, rx);
    }

    inline static bool                                              sysnat_ipv4_output(struct ip_hdr* iphdr, int iplen) {
        if (!iphdr || iplen < 1) {
            return false;
        }

        int handle = SYSNAT_TUN;
        if (handle == -1) {
            return false;
        }

        std::shared_ptr<boost::asio::posix::stream_descriptor> tun_ = SYSNAT_TUN_;
        if (!tun_ || !tun_->is_open()) {
            return false;
        }
        
        std::shared_ptr<char> packet = make_shared_alloc<char>(iplen);
        if (!packet) { 
            return false;
        }
        else {
            memcpy(packet.get(), iphdr, iplen);
        }

        tun_->async_write_some(boost::asio::buffer(packet.get(), iplen), [packet](const boost::system::error_code&, size_t){});
        return true;
    }

    inline static bool                                              sysnat_ipv4_loopback() { 
        MUTEXSCOPE __LOCK__(SYSNAT_LOCK_);
        if (!SYSNAT_TUN_ || !SYSNAT_TUN_->is_open()) {
            return false;
        }
        
        std::shared_ptr<char> packet = make_shared_alloc<char>(ip_hdr::MTU);
        if (!packet) { 
            return false;
        }

        SYSNAT_TUN_->async_read_some(boost::asio::buffer(packet.get(), ip_hdr::MTU), [packet](const boost::system::error_code& ec_, size_t sz) {
            if (ec_) {
                return;
            }

            if (sz > 0) {
                struct ip_hdr* iphdr = (struct ip_hdr*)packet.get();
                sysnat_ipv4_input(iphdr, sz, 0);
            }
            sysnat_ipv4_loopback();
        });
        return true;
    }

    inline static bool                                              sysnat_listen_localhost() {
        std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor_ = make_shared_object<boost::asio::ip::tcp::acceptor>(*SYSNAT_CONTEXT);
        if (!acceptor_) {
            return false;
        }

        boost::system::error_code ec_;
        acceptor_->open(boost::asio::ip::tcp::v4(), ec_);
        if (ec_) {
            sysnat_close_socket(acceptor_);
            return false;
        }

        boost::asio::ip::tcp::endpoint bindEP = IPEndPoint::WrapAddress<boost::asio::ip::tcp>(SYSNAT_IP, 0);
        acceptor_->bind(bindEP, ec_);
        if (ec_) {
            sysnat_close_socket(acceptor_);
            return false;
        }

        boost::asio::ip::tcp::endpoint localEP = acceptor_->local_endpoint(ec_);
        if (ec_) {
            sysnat_close_socket(acceptor_);
            return false;
        }

        acceptor_->listen(UINT16_MAX, ec_);
        if (ec_) {
            sysnat_close_socket(acceptor_);
            return false;
        }

        std::shared_ptr<boost::asio::deadline_timer> ticktmr = make_shared_object<boost::asio::deadline_timer>(*SYSNAT_CONTEXT);
        if (!ticktmr) {
            sysnat_close_socket(acceptor_);
            return false;
        }
        else {
            sysnat_tick_loopback(ticktmr);
        }

        SYSNAT_LOOPBACK_ = IPEndPoint(SYSNAT_IP, localEP.port());
        return sysnat_listen_loopback(acceptor_);
    }

    inline static bool                                              sysnat_listen_loopback(std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor_) {
        if (!acceptor_) {
            return false;
        }
    
        std::shared_ptr<boost::asio::ip::tcp::socket> socket_ = make_shared_object<boost::asio::ip::tcp::socket>(*SYSNAT_CONTEXT);
        if (!socket_) {
            sysnat_close_socket(acceptor_);
            return false;
        }

        acceptor_->async_accept(*socket_, [acceptor_, socket_] (const boost::system::error_code& ec) {
            if (ec || !sysnat_listen_accept(socket_)) {
                sysnat_close_socket(*socket_);
            }
            sysnat_listen_loopback(acceptor_);
        });
        return true;
    }

    inline static void                                              sysnat_close_socket(int fd) {
        if (fd != -1) {
            int how;
            #ifdef _WIN32
            how = SD_SEND;
            #else
            how = SHUT_WR;
            #endif

            shutdown(fd, how);

            #ifdef _WIN32
            closesocket(fd);
            #else   
            close(fd);
            #endif
        }
    }

    inline static void                                              sysnat_close_socket(const boost::asio::ip::tcp::socket& socket_) {
        boost::asio::ip::tcp::socket& socket__ = const_cast<boost::asio::ip::tcp::socket&>(socket_);
        if (socket__.is_open()) {
            boost::system::error_code ec;
            try {
                socket__.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
            }
            catch (std::exception&) {}
            try {
                socket__.close(ec);
            }
            catch (std::exception&) {}
        }
    }

    inline static void                                              sysnat_close_socket(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket_) {
        if (socket_) {
            sysnat_close_socket(*socket_);
        }
    }

    inline static void                                              sysnat_close_socket(const std::shared_ptr<boost::asio::ip::tcp::acceptor>& socket_) {
        if (socket_ && socket_->is_open()) {
            boost::system::error_code ec;
            try {
                socket_->close(ec);
            }
            catch (std::exception&) {}
        }
    }

    std::shared_ptr<boost::asio::io_context>                        sysnat_loopback_context() {
        std::shared_ptr<boost::asio::io_context> context_ = make_shared_object<boost::asio::io_context>();
        if (!context_) {
            return NULL;
        }

        auto loopbackf = [context_] {
            SetThreadPriorityToMaxLevel();

            boost::system::error_code ec_;
            boost::asio::io_context::work work_(*context_);
            context_->run(ec_);
        };
        std::thread(loopbackf).detach();
        return std::move(context_);
    }

    inline static bool                                              sysnat_listen_accept(std::shared_ptr<boost::asio::ip::tcp::socket> socket_) {
        // 获取转换地址
        boost::asio::ip::tcp::endpoint natEP = IPEndPoint::AnyAddress<boost::asio::ip::tcp>(0);
        boost::system::error_code ec;
        try {
            natEP = socket_->remote_endpoint(ec);
            if (ec) {
                return false;
            }
        }
        catch (std::exception&) {
            return false;
        }

        // 检索虚拟链路
        std::shared_ptr<TapTcpLink> link = sysnat_find_tcp_link(ntohs(natEP.port()));
        if (!link) {
            return false;
        }

        // 建立虚套接字
        std::shared_ptr<TapTcpClient> pcb = link->socket;
        if (!pcb) {
            link->Fin();
            return false;
        }

        if (!pcb->EndAccept(socket_, natEP)) {
            link->Release();
            return false;
        }
        else {
            link->syn = false;
            link->Act();
            return true;
        }
    }

    inline static bool                                              sysnat_tcp_input(struct ip_hdr* iphdr, struct tcp_hdr* pkg, int len, int rx) {
        typedef tcp_hdr::TcpFlags TcpFlags;

        int lan2wan = 1;
        std::shared_ptr<TapTcpLink> link;
        TcpFlags flags = (TcpFlags)tcp_hdr::TCPH_FLAGS(pkg);

        if (iphdr->dest == SYSNAT_GW) { // V->Local 
            if (iphdr->src != SYSNAT_IP) {
                sysnat_tcp_rst(iphdr, pkg, len, rx);
                return false;
            }

            link = sysnat_find_tcp_link(pkg->dest);
            if (!link) {
                sysnat_tcp_rst(iphdr, pkg, len, rx);
                return false;
            }
            else {
                rx = 1; 
                lan2wan = 0;
            }

            link->Act();
            iphdr->src  = link->dstAddr;
            pkg->src    = link->dstPort;
            iphdr->dest = link->srcAddr;
            pkg->dest   = link->srcPort;
        }
        else if (flags & TcpFlags::TCP_SYN) { // SYN
            if (!rx) {
                return false;
            }

            link = sysnat_alloc_tcp_link(iphdr->src, pkg->src, iphdr->dest, pkg->dest);
            if (!link) {
                sysnat_tcp_rst(iphdr, pkg, len, rx);
                return false;
            }

            if (link->fin || !link->syn) {
                sysnat_close_tcp_link(link);
                return sysnat_tcp_input(iphdr, pkg, len, rx);
            }

            boost::asio::ip::tcp::endpoint localEP  = IPEndPoint::WrapAddress<boost::asio::ip::tcp>(iphdr->src, ntohs(pkg->src));
            boost::asio::ip::tcp::endpoint remoteEP = IPEndPoint::WrapAddress<boost::asio::ip::tcp>(iphdr->dest, ntohs(pkg->dest));
            
            std::shared_ptr<TapTcpClient> socket = make_shared_object<TapTcpClient>(localEP, remoteEP);
            if (!socket) {
                sysnat_close_tcp_link(link);
                return false;
            }

            if (!socket->BeginAccept()) {
                sysnat_close_tcp_link(link);
                return false;
            }
            else {
                rx = 0; 
            }
            
            link->socket = std::move(socket);
            iphdr->src   = SYSNAT_GW;
            pkg->src     = link->natPort;
            iphdr->dest  = SYSNAT_IP;
            pkg->dest    = ntohs(SYSNAT_LOOPBACK_.Port);
        }
        else { // Local->V
            link = sysnat_find_tcp_link(sysnat_mapkey(iphdr->src, pkg->src, iphdr->dest, pkg->dest));
            if (!link) {
                sysnat_tcp_rst(iphdr, pkg, len, rx);
                return false;
            }
            else {
                rx = 0; 
            }

            link->Act();
            iphdr->src  = SYSNAT_GW;
            pkg->src    = link->natPort;
            iphdr->dest = SYSNAT_IP;
            pkg->dest   = ntohs(SYSNAT_LOOPBACK_.Port);
        }

        if (flags & (TcpFlags::TCP_FIN | TcpFlags::TCP_RST)) {
            if (link) {
                link->Fin();
            }
        }
        return sysnat_tcp_opt(lan2wan, iphdr, pkg, len, rx);
    }

    inline static bool                                              sysnat_tcp_rst(struct ip_hdr* iphdr, struct tcp_hdr* pkg, int len, int rx) { assert(iphdr && pkg);
        typedef tcp_hdr::TcpFlags TcpFlags;

        uint32_t dstAddr       = iphdr->dest;
        uint16_t dstPort       = pkg->dest;
        uint32_t srcAddr       = iphdr->src;
        uint16_t srcPort       = pkg->src;
        uint32_t seqNo         = pkg->seqno;
        uint32_t ackNo         = pkg->ackno;

        uint32_t hdrlen_bytes  = tcp_hdr::TCPH_HDRLEN_BYTES(pkg);
        uint32_t tcplen        = len - hdrlen_bytes;
        if (tcp_hdr::TCPH_FLAGS(pkg) & (TcpFlags::TCP_FIN | TcpFlags::TCP_SYN)) {
            tcplen++;
        }

        len                    = tcp_hdr::TCP_HLEN;
        iphdr->src             = dstAddr;
        pkg->src               = dstPort;
        iphdr->dest            = srcAddr;
        pkg->dest              = srcPort;
        pkg->ackno             = seqNo + tcplen;
        pkg->seqno             = ackNo;
        pkg->hdrlen_rsvd_flags = 0;
        pkg->urgp              = 0;

        tcp_hdr::TCPH_HDRLEN_BYTES_SET(pkg, len);
        tcp_hdr::TCPH_FLAGS_SET(pkg, TcpFlags::TCP_RST | TcpFlags::TCP_ACK);
        return sysnat_tcp_opt(0, iphdr, pkg, len, rx);
    }

    inline static bool                                              sysnat_tcp_opt(int lan2wan, struct ip_hdr* iphdr, struct tcp_hdr* pkg, int len, int rx) { assert(iphdr && pkg);
        pkg->chksum = 0;
        pkg->chksum = inet_chksum_pseudo((unsigned char*)pkg,
                    (unsigned int)ip_hdr::IP_PROTO_TCP,
                    (unsigned int)len,
                    iphdr->src,
                    iphdr->dest);
        if (pkg->chksum == 0) {
            pkg->chksum = 0xffff;
        }

        int iphdr_len = (char*)pkg - (char*)iphdr;
        iphdr->chksum = 0;
        iphdr->chksum = inet_chksum(iphdr, iphdr_len);
        if (iphdr->chksum == 0) {
            iphdr->chksum = 0xffff;
        }

        int ippkg_len = ((char*)pkg + len) - (char*)iphdr;
        if (rx) {
            return ipv4_output(iphdr, ippkg_len);
        }
        return sysnat_ipv4_output(iphdr, ippkg_len);
    }

    inline static void                                              sysnat_tick_loopback(std::shared_ptr<boost::asio::deadline_timer> ticktmr_) {
        if (!ticktmr_) {
            return;
        }
        auto callbackf = [ticktmr_](const boost::system::error_code& ec) {
            if (!ec) {
                uint64_t now = ipv4_time();
                sysnat_tick(now);
                sysnat_tick_loopback(ticktmr_);
            }
        };
        ticktmr_->expires_from_now(boost::posix_time::seconds(1));
        ticktmr_->async_wait(callbackf);
    }

    inline static bool                                              sysnat_tick(uint64_t now_) {
        typedef std::shared_ptr<TapTcpLink> TapTcpLinkPtr;

        std::vector<TapTcpLinkPtr> releases;
        do {
            MUTEXSCOPE __LOCK__(SYSNAT_LOCK_);
            WAN2LAN_LINK_TABLE::iterator tail = SYSNAT_WAN2LAN.begin();
            WAN2LAN_LINK_TABLE::iterator endl = SYSNAT_WAN2LAN.end();

            uint64_t now = ipv4_time();
            uint64_t maxFinTime = SYSNAT_MAX_FINAL_TIME;
            uint64_t maxSynTime = SYSNAT_MAX_SYNAL_TIME;
            uint64_t maxInactivityTime = SYSNAT_MAX_INACTIVITY_TIME;

            for (; tail != endl; ++tail) {
                const std::shared_ptr<TapTcpLink>& link = tail->second;
                assert(link);

                uint64_t deltaTime = now - link->activityTime;
                if (link->fin) {
                    if (deltaTime >= maxFinTime) {
                        releases.push_back(link);
                    }
                }
                else if (link->syn) {
                    if (deltaTime >= maxSynTime) { 
                        releases.push_back(link);
                    }
                } 
                else {
                    if (deltaTime >= maxInactivityTime) { // 连接发生老化
                        releases.push_back(link);
                    }
                }
            }
        } while (0);
        for (size_t i = 0, l = releases.size(); i < l; i++) {
            const std::shared_ptr<TapTcpLink>& link = releases[i];
            if (link) {
                sysnat_close_tcp_link(link);
            }
        }
    }

    inline static std::string                                       sysnat_mapkey(uint32_t src, int srcport, uint32_t dst, int dstport) {
        char szKey[UINT8_MAX];
        char szSrc[INET_ADDRSTRLEN];
        char szDst[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &src, szSrc, sizeof(szSrc));
        inet_ntop(AF_INET, &dst, szDst, sizeof(szDst));

        snprintf(szKey, sizeof(szKey), "%s:%d -> %s:%d", szSrc, srcport, szDst, dstport);
        return szKey;
    }

    inline static bool                                              sysnat_close_tcp_link(const std::shared_ptr<TapTcpLink>& link, bool fin) {
        if (!link) {
            return false;
        }
        if (!fin) {
            MUTEXSCOPE __LOCK__(SYSNAT_LOCK_);
            {
                WAN2LAN_LINK_TABLE::iterator tail = SYSNAT_WAN2LAN.find(link->natPort);
                if (tail != SYSNAT_WAN2LAN.end()) {
                    SYSNAT_WAN2LAN.erase(tail);
                }
            }
            std::string key = sysnat_mapkey(link->srcAddr, link->srcPort, link->dstAddr, link->dstPort);
            {
                LAN2WAN_LINK_TABLE::iterator tail = SYSNAT_LAN2WAN.find(key);
                if (tail != SYSNAT_LAN2WAN.end()) {
                    SYSNAT_LAN2WAN.erase(tail);
                }
            }
        }
        link->Release();
        return true;
    }

    inline static uint16_t                                          sysnat_alloc_tcp_port() {
        for (; ;) {
            uint16_t port = SYSNAT_APORT_++;
            if (port != IPEndPoint::MinPort) {
                return port;
            }
        }
    }

    inline static std::shared_ptr<TapTcpLink>                       sysnat_find_tcp_link(int key) {
        MUTEXSCOPE __LOCK__(SYSNAT_LOCK_);
        WAN2LAN_LINK_TABLE& map = SYSNAT_WAN2LAN;
        WAN2LAN_LINK_TABLE::iterator tail = map.find(key);
        WAN2LAN_LINK_TABLE::iterator endl = map.end();
        if (tail == endl) {
            return NULL;
        }
        return tail->second;
    }

    inline static std::shared_ptr<TapTcpLink>                       sysnat_find_tcp_link(const std::string& key) {
        MUTEXSCOPE __LOCK__(SYSNAT_LOCK_);
        LAN2WAN_LINK_TABLE& map = SYSNAT_LAN2WAN;
        LAN2WAN_LINK_TABLE::iterator tail = map.find(key);
        LAN2WAN_LINK_TABLE::iterator endl = map.end();
        if (tail == endl) {
            return NULL;
        }
        return tail->second;
    }

    inline static std::shared_ptr<TapTcpLink>                       sysnat_alloc_tcp_link(uint32_t src, int srcport, uint32_t dst, int dstport) {
        MUTEXSCOPE __LOCK__(SYSNAT_LOCK_);
        std::string key = sysnat_mapkey(src, srcport, dst, dstport);
        std::shared_ptr<TapTcpLink> link = sysnat_find_tcp_link(key);
        if (link) {
            return link;
        }

        int newPort = 0;
        for (int traversePort = IPEndPoint::MinPort; traversePort < IPEndPoint::MaxPort; traversePort++) {
            newPort = sysnat_alloc_tcp_port();
            if (newPort == IPEndPoint::MinPort) {
                break;
            }

            if (sysnat_find_tcp_link(newPort)) {
                continue;
            }

            link = make_shared_object<TapTcpLink>();
            link->dstAddr = dst;
            link->dstPort = dstport;
            link->srcAddr = src;
            link->srcPort = srcport;
            link->natPort = newPort;

            SYSNAT_LAN2WAN[key] = link;
            SYSNAT_WAN2LAN[newPort] = link;
            break;
        }

        if (link) {
            link->Act();
        }
        return link;
    }

    inline static void                                              sysnat_release_tcp_link(int key) {
        std::shared_ptr<TapTcpLink> link = sysnat_find_tcp_link(key);
        if (link) {
            std::shared_ptr<boost::asio::io_context> context = SYSNAT_CONTEXT;
            boost::asio::post(*context.get(), [context, link] {
                link->Release();
            });
        }
    }

    inline static void                                              sysnat_release_tcp_link(uint32_t src, int srcport, uint32_t dst, int dstport) {
        std::string key = sysnat_mapkey(src, srcport, dst, dstport);
        std::shared_ptr<TapTcpLink> link = sysnat_find_tcp_link(key);
        if (link) {
            std::shared_ptr<boost::asio::io_context> context = SYSNAT_CONTEXT;
            boost::asio::post(*context.get(), [context, link] {
                link->Release();
            });
        }
    }

    TapTcpClient::TapTcpClient( 
        const boost::asio::ip::tcp::endpoint&                       localEP, /* 本地地址   */
        const boost::asio::ip::tcp::endpoint&                       remoteEP /* 远程地址   */) 
        : _disposed(false)
        , _baccept(false) {
        this->_localEP = localEP;
        this->_remoteEP = remoteEP;
        this->_context = SYSNAT_CONTEXT;
    }

    TapTcpClient::~TapTcpClient() { 
        this->Finalize();
    }

    void                                                            TapTcpClient::Dispose() {
        std::shared_ptr<TapTcpClient> self = this->GetPtr();
        boost::asio::post(*this->_context, std::bind(&TapTcpClient::Finalize, self));
    }

    bool                                                            TapTcpClient::BeginAccept() {
        if (this->_disposed) {
            return false;
        }

        if (this->_baccept) {
            return false;
        }

        if (!this->_context) {
            return false;
        }
        this->_baccept = true;
        return true;
    }

    void                                                            TapTcpClient::Finalize() {
        if (!this->_disposed.exchange(true)) {
            sysnat_close_socket(this->_socket);
            sysnat_close_socket(this->_server);
        }

        IPEndPoint localEP = IPEndPoint::ToEndPoint(this->_localEP);
        IPEndPoint remoteEP = IPEndPoint::ToEndPoint(this->_remoteEP);
        sysnat_release_tcp_link(localEP.GetAddress(), ntohs(localEP.Port), remoteEP.GetAddress(), ntohs(remoteEP.Port));
    }

    bool                                                            TapTcpClient::EndAccept(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const boost::asio::ip::tcp::endpoint& natEP) {
        if (!socket) {
            return false;
        }

        this->_socket     = socket;
        this->_natEP      = natEP;

        std::shared_ptr<boost::asio::ip::tcp::socket> server = make_shared_object<boost::asio::ip::tcp::socket>(*this->_context);
        if (!server) {
            return false;
        }

        boost::system::error_code ec_;
        server->open(this->_remoteEP.protocol(), ec_);
        if (ec_) {
            return true;
        }

        std::shared_ptr<TapTcpClient> self = this->GetPtr();
        server->async_connect(this->_remoteEP, [self, this](const boost::system::error_code& ec_) {
            if (ec_ || !this->_baccept) {
                this->Dispose();
                return;
            }

            if (this->_disposed) {
                return;
            }

            this->socket_to_destination(this->_socket, this->_server, this->_buffer);
            this->socket_to_destination(this->_server, this->_socket, this->_buffer);
        });
        this->_server     = std::move(server);
        return true;
    }
}   
#endif