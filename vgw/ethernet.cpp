#include <pcap.h>
#include <libtcpip.h>
#ifdef _WIN32
#include <iphlpapi.h>
#else
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
#endif

#include "gw.h"
#include "ipv4.h"
#include "etharp.h"
#include "ethernet.h"

#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

#ifdef HAVE_PF_RING
// #include <pfring.h>
// #include <linux/pf_ring.h>

/* ********************************* */

#define PF_RING_ZC_SYMMETRIC_RSS       (1 <<  0) /**< pfring_open() flag: Set the hw RSS function to symmetric mode (both directions of the same flow go to the same hw queue). Supported by ZC drivers only. This option is also available with the PF_RING-aware libpcap via the PCAP_PF_RING_ZC_RSS environment variable. */
#define PF_RING_REENTRANT              (1 <<  1) /**< pfring_open() flag: The device is open in reentrant mode. This is implemented by means of semaphores and it results is slightly worse performance. Use reentrant mode only for multithreaded applications. */
#define PF_RING_LONG_HEADER            (1 <<  2) /**< pfring_open() flag: If uset, PF_RING does not fill the field extended_hdr of struct pfring_pkthdr. If set, the extended_hdr field is also properly filled. In case you do not need extended information, set this value to 0 in order to speedup the operation. */
#define PF_RING_PROMISC                (1 <<  3) /**< pfring_open() flag: The device is open in promiscuous mode. */
#define PF_RING_TIMESTAMP              (1 <<  4) /**< pfring_open() flag: Force PF_RING to set the timestamp on received packets (usually it is not set when using zero-copy, for optimizing performance). */
#define PF_RING_HW_TIMESTAMP           (1 <<  5) /**< pfring_open() flag: Enable hw timestamping, when available. */
#define PF_RING_RX_PACKET_BOUNCE       (1 <<  6) /**< pfring_open() flag: Enable fast forwarding support (see pfring_send_last_rx_packet()). */
#define PF_RING_ZC_FIXED_RSS_Q_0       (1 <<  7) /**< pfring_open() flag: Set hw RSS to send all traffic to queue 0. Other queues can be selected using hw filters (ZC cards with hw filtering only). */
#define PF_RING_STRIP_HW_TIMESTAMP     (1 <<  8) /**< pfring_open() flag: Strip hw timestamp from the packet. */
#define PF_RING_DO_NOT_PARSE           (1 <<  9) /**< pfring_open() flag: Disable packet parsing also when 1-copy is used. (parsing already disabled in zero-copy) */
#define PF_RING_DO_NOT_TIMESTAMP       (1 << 10) /**< pfring_open() flag: Disable packet timestamping also when 1-copy is used. (sw timestamp already disabled in zero-copy) */
#define PF_RING_CHUNK_MODE             (1 << 11) /**< pfring_open() flag: Enable chunk mode operations. This mode is supported only by specific adapters and it's not for general purpose. */
#define PF_RING_IXIA_TIMESTAMP	       (1 << 12) /**< pfring_open() flag: Enable ixiacom.com hardware timestamp support+stripping. */
#define PF_RING_USERSPACE_BPF	       (1 << 13) /**< pfring_open() flag: Force userspace bpf even with standard drivers (not only with ZC). */
#define PF_RING_ZC_NOT_REPROGRAM_RSS   (1 << 14) /**< pfring_open() flag: Do not touch/reprogram hw RSS */ 
#define PF_RING_VSS_APCON_TIMESTAMP    (1 << 15) /**< pfring_open() flag: Enable apcon.com/vssmonitoring.com hardware timestamp support+stripping. */
#define PF_RING_ZC_IPONLY_RSS	       (1 << 16) /**< pfring_open() flag: Compute RSS on src/dst IP only (not 4-tuple) */ 
#define PF_RING_FLOW_OFFLOAD	       (1 << 17) /**< pfring_open() flag: Enable hw flow table support when available */ 
#define PF_RING_FLOW_OFFLOAD_NOUPDATES (1 << 18) /**< pfring_open() flag: Do not send flow updates with PF_RING_FLOW_OFFLOAD (enable support for flows shunting only) */
#define PF_RING_FLOW_OFFLOAD_NORAWDATA (1 << 19) /**< pfring_open() flag: Do not send raw packets with PF_RING_FLOW_OFFLOAD */
#define PF_RING_L7_FILTERING	       (1 << 20) /**< pfring_open() flag: Enable L7 filtering support based on PF_RING FT (Flow Table with nDPI support) */
#define PF_RING_DO_NOT_STRIP_FCS       (1 << 21) /**< pfring_open() flag: Do not strip the FCS (CRC), when not stripped out by the adapter (on standard adapters use this in combination with 'ethtool -K DEV rx-fcs on rx-all on') */
#define PF_RING_TX_BPF	               (1 << 22) /**< pfring_open() flag: Evaluate bpf also for transmitted packets (this also force userspace bpf). */
#define PF_RING_FLOW_OFFLOAD_TUNNEL    (1 << 23) /**< pfring_open() flag: Enable tunnel dissection with flow offload */
#define PF_RING_DISCARD_INJECTED_PKTS  (1 << 24) /**< pfring_open() flag: Discard packets injected through the stack module (this avoid loops in MITM applications) */
#define PF_RING_ARISTA_TIMESTAMP       (1 << 25) /**< pfring_open() flag: Enable Arista 7150 hardware timestamp support and stripping */
#define PF_RING_METAWATCH_TIMESTAMP    (1 << 26) /**< pfring_open() flag: Enable Arista 7130 MetaWatch hardware timestamp support and stripping */

/* ********************************* */

#ifdef __cplusplus
extern "C" {
#endif
    typedef enum {
      rx_and_tx_direction = 0,
      rx_only_direction,
      tx_only_direction
    } packet_direction;
    
    typedef enum {
      send_and_recv_mode = 0,
      send_only_mode,
      recv_only_mode
    } socket_mode;

    typedef void (*pfringProcesssPacket)(struct pcap_pkthdr *h, u_char *p, u_char *user_bytes);

    int   pfring_loop(void *ring, pfringProcesssPacket looper, u_char *user_bytes, u_int8_t wait_for_packet);
    void* pfring_open(const char *device_name, u_int32_t caplen, u_int32_t flags);
    void  pfring_close(void *ring);
    void  pfring_config(u_short cpu_percentage);
    void  pfring_breakloop(void *ring);
    int   pfring_set_direction(void *ring, packet_direction direction);
    int   pfring_set_socket_mode(void *ring, socket_mode mode);
    int   pfring_enable_ring(void *ring);
    int   pfring_disable_ring(void *ring);
    int   pfring_set_bpf_filter(void *ring, const char *filter_buffer);
    int   pfring_remove_bpf_filter(void *ring);
    int   pfring_set_application_name(void *ring, const char *name);
    int   pfring_send(void *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet);
    int   pfring_set_poll_watermark(void *ring, u_int16_t watermark);
    int   pfring_get_bound_device_ifindex(void *ring, int *if_index);
    int   pfring_send_last_rx_packet(void *ring, int tx_interface_id);

    // pcap-int.h
    #define pcap_get_pfring(p) (p ? *(void**)((char*)p + 648u) : NULL) /* bpf_filter */
    #define pcap_fld_initialized(p) (*(uint8_t*)((char*)p))
    #define pcap_fld_enabled(p) (*(uint8_t*)((char*)p + sizeof(uint8_t)))
#ifdef __cplusplus
}
#endif
#endif

namespace vgw {
    uint32_t                                                ETHERNET_IP = INADDR_ANY;
    uint32_t                                                ETHERNET_NGW = INADDR_ANY;
    uint32_t                                                ETHERNET_MASK = INADDR_ANY;
    struct eth_addr                                         ETHERNET_MAC;
    boost::asio::io_context                                 ETHERNET_CONTEXT_;
    Byte                                                    ETHERNET_BUFFER_[ETHBUF_IANA_HWSNAP_ETHERNET];
    boost::asio::ip::udp::endpoint                          ETHERNET_ENDPOINT_;
    uint32_t                                                ETHERNET_IFINDEX_;
    std::string                                             ETHERNET_NAME_;

    #ifdef HAVE_PF_RING
    static void*                                            ETHERNET_RING = NULL;
    #endif
    static pcap_t*                                          ETHERNET_NIC = NULL;
    static bool                                             ETHERNET_FIN = false;
    #ifndef _WIN32
    static bool                                             ETHERNET_LWIP = false;
    static bool                                             ETHERNET_SNAT = false;
    #endif

    #ifdef _WIN32
    inline static std::string pcap_live_get_packet_device(const std::string& device) {
        if (device.empty()) {
            return NULL;
        }

        std::string device_ = device;
        std::transform(device_.begin(), device_.end(), device_.begin(), tolower);

        struct pcap_if* alldevs;
        char errbuf[PCAP_ERRBUF_SIZE];

        int err = pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf);
        if (err < 0) {
            return NULL;
        }

        for (struct pcap_if* d = alldevs; d != NULL; d = d->next) {
            std::string description;
            if (d->description) {
                description = d->description;
            }

            if (description.empty()) {
                continue;
            }

            std::transform(description.begin(), description.end(), description.begin(), tolower);
            if (description.find(device_) != std::string::npos) {
                std::string name = d->name;
                pcap_freealldevs(alldevs);
                return name;
            }
        }
        pcap_freealldevs(alldevs);
        return NULL;
    }

    inline static void ethernet_gc_collect() {
        static std::shared_ptr<boost::asio::deadline_timer> t = make_shared_object<boost::asio::deadline_timer>(ETHERNET_CONTEXT_);
        auto callbackf = [](const boost::system::error_code& ec) {
            SetProcessWorkingSetSize(GetCurrentProcess(), UINT_MAX, UINT_MAX);
            ethernet_gc_collect();
        };
        t->expires_from_now(boost::posix_time::seconds(10));
        t->async_wait(callbackf);
    }
    #endif

    #ifdef HAVE_PF_RING
    void*                                                   pfring_live_open_packet_device(const std::string& device, int rx_or_tx) {
        pfring_config(99);

        void* ring = pfring_open(device.data(), ETHBUF_IANA_HWSNAP_ETHERNET, PF_RING_PROMISC | PF_RING_DO_NOT_TIMESTAMP | PF_RING_DO_NOT_PARSE);
        if (!ring) {
            return NULL;
        }

        // https://www.ntop.org/guides/pf_ring_api/pfring_8h.html#a175b6d8450f04848226a9aac99fefbe5
        if (pfring_set_application_name(ring, "vgw")) {
            pfring_close(ring);
            return NULL;
        }

        if (pfring_set_poll_watermark(ring, 1 /* watermark */)) {
            pfring_close(ring);
            return NULL;
        }

        if (pfring_set_direction(ring, rx_only_direction)) {
            pfring_close(ring);
            return NULL;
        }

        if (pfring_set_socket_mode(ring, rx_or_tx ? send_and_recv_mode : send_only_mode)) {
            pfring_close(ring);
            return NULL;
        }

        char rules[1000];
        sprintf(rules, "ether dst %02x:%02x:%02x:%02x:%02x:%02x or ether dst ff:ff:ff:ff:ff:ff",
            ETHERNET_MAC.s_data[0],
            ETHERNET_MAC.s_data[1],
            ETHERNET_MAC.s_data[2],
            ETHERNET_MAC.s_data[3],
            ETHERNET_MAC.s_data[4],
            ETHERNET_MAC.s_data[5]);

        if (pfring_set_bpf_filter(ring, rules)) {
            pfring_close(ring);
            return NULL;
        }

        if (pfring_enable_ring(ring)) {
            pfring_close(ring);
            return NULL;
        }
        return ring;
    }
    #endif

    #ifndef _WIN32
    bool                                                    subnat_loopback(int snat);
    int                                                     subnat_listen(int concurrent);
    bool                                                    subnat_write(struct ip_hdr* iphdr, int iplen);
    bool                                                    sysnat_ipv4_init();
    bool                                                    sysnat_ipv4_input(struct ip_hdr* iphdr, int iplen);
    #endif
    
    pcap_t* pcap_live_open_packet_device(std::string device_) {
        char errbuf[PCAP_ERRBUF_SIZE];
        #ifdef _WIN32
        device_ = pcap_live_get_packet_device(device_);
        if (device_.empty()) {
            return NULL;
        }

        pcap_t* device = pcap_open_live(
            device_.data(), // name of the device
            ETHBUF_IANA_HWSNAP_ETHERNET, // portion of the packet to capture
                   // 65536 guarantees that the whole packet
                   // will be captured on all the link layers
            PCAP_OPENFLAG_PROMISCUOUS | // promiscuous mode
            PCAP_OPENFLAG_MAX_RESPONSIVENESS,
            0, // read timeout
            errbuf); // error buffer
        #else
        if (device_.empty()) {
            return NULL;
        }

        pcap_t* device = pcap_open_live(
            device_.data(), // name of the device
            ETHBUF_IANA_HWSNAP_ETHERNET, // portion of the packet to capture
                   // 65536 guarantees that the whole packet
                   // will be captured on all the link layers
            1, // promiscuous mode
            0, // read timeout
            errbuf); // error buffer
        #endif
        if (!device) {
            return NULL;
        }

        /* Must is ethernet */
        int datalink = pcap_datalink(device);
        if (datalink != DLT_EN10MB && datalink != DLT_EN3MB) {
            pcap_close(device);
            return NULL;
        }

        /* Set promiscuous mode */ 
        pcap_set_promisc(device, 1);

        #ifdef _WIN32
        typedef PCAP_AVAILABLE_1_5 int(__cdecl *proc_pcap_set_immediate_mode)(pcap_t*, int);

        proc_pcap_set_immediate_mode pcap_set_immediate_mode_ = (proc_pcap_set_immediate_mode)
            GetProcAddress(GetModuleHandle(TEXT("wpcap.dll")), "pcap_set_immediate_mode");
        if (pcap_set_immediate_mode_) {
            pcap_set_immediate_mode_(device, 1);
        }
        #else
        /* Set immediate mode */
        pcap_set_immediate_mode(device, 1);
        #endif

        /* Only capture IN */
        pcap_setdirection(device, PCAP_D_IN);

        static const int MAX_BUFFER_SIZE = 1 * 1024 * 1024;
        #ifdef _WIN32
        /* We want any responses back ASAP */
        if (pcap_setmintocopy(device, 0)) {
            pcap_close(device);
            return NULL;
        }

        /* Set the buffer size for a not-yet-activated capture handle */
        pcap_setbuff(device, MAX_BUFFER_SIZE);
        #else
        /* Set the buffer size for a not-yet-activated capture handle */
        pcap_set_buffer_size(device, MAX_BUFFER_SIZE);
        #endif

        bpf_u_int32 netmask = ETHERNET_MASK;
        if (netmask == INADDR_ANY) {
            netmask = INADDR_NONE;
        }

        char rules[8096];
        sprintf(rules, "ether dst %02x:%02x:%02x:%02x:%02x:%02x or ether dst ff:ff:ff:ff:ff:ff",
            ETHERNET_MAC.s_data[0],
            ETHERNET_MAC.s_data[1],
            ETHERNET_MAC.s_data[2],
            ETHERNET_MAC.s_data[3],
            ETHERNET_MAC.s_data[4],
            ETHERNET_MAC.s_data[5]);

        /* Compile the filter */
        struct bpf_program fcode;
        if (pcap_compile(device, &fcode, rules, 1, netmask)) {
            pcap_close(device);
            return NULL;
        }

        /* Set the filter */
        if (pcap_setfilter(device, &fcode)) {
            pcap_close(device);
            return NULL;
        }
        return device;
    }

    inline static void ethernet_loopback() {
        auto loopbackf = [] {
            SetThreadPriorityToMaxLevel();

            boost::system::error_code ec_;
            boost::asio::io_context::work work_(ETHERNET_CONTEXT_);
            ETHERNET_CONTEXT_.run(ec_);
        };
        std::thread(loopbackf).detach();
    }

    #ifdef _WIN32
    inline static bool ethernet_init() {
    #else
    inline static bool ethernet_init(int ncpu) {
    #endif
        ETHERNET_FIN = false;
        ETHERNET_CONTEXT_.restart();

        ipv4_init();
        etharp_init();
        ethernet_loopback();

        #ifndef _WIN32
        if (!ETHERNET_LWIP) {
            return sysnat_ipv4_init();
        }

        int err = subnat_listen(ncpu);
        if (err < 0) {
            return false;
        }
        else if (err > 0) {
            ETHERNET_SNAT = true;
        }
        #endif
        return libtcpip_loopback(ETHERNET_IP, ETHERNET_IP, ETHERNET_MASK, (LIBTCPIP_IPV4_OUTPUT)ipv4_output);
    }

    inline static int64_t MAC2I64(struct eth_addr& addr) {
        return (int64_t)addr.s_zero.w << 32 | addr.s_zero.dw;
    }

    inline static void ethernet_input(struct eth_hdr* packet, int proto, std::shared_ptr<char>& buf, int len) {
        switch (proto)
        {
            case ETHTYPE_IP: // Internet Protocol, Version 4 (IPv4)
            {
                int iplen = len - sizeof(*packet);
                if (iplen < ip_hdr::IP_HLEN) {
                    break;
                }
    
                struct ip_hdr* iphdr = (struct ip_hdr*)(packet + 1);
                etharp_add(packet->src, iphdr->src); 
    
                int ipproto = ip_hdr::IPH_PROTO(iphdr);
                if (ipproto != ip_hdr::IP_PROTO_ICMP) {
                    if (iphdr->dest == ETHERNET_IP) {
                        break;
                    }
                }

                if (ipproto == ip_hdr::IP_PROTO_TCP) {
                    #ifndef _WIN32
                    if (!ETHERNET_LWIP) {
                        sysnat_ipv4_input(iphdr, iplen);
                        return;
                    }

                    if (ETHERNET_SNAT) {
                        subnat_write(iphdr, iplen);
                        return;
                    }
                    #endif
                    libtcpip_input(iphdr, iplen);
                    return;
                }
    
                iphdr = ip_hdr::Parse(iphdr, iplen);
                if (iphdr) {
                    ipv4_input(iphdr, iplen);
                }
                break;
            }
            case ETHTYPE_ARP: // Address Resolution Protocol (ARP)
            {
                etharp_input(packet, (struct etharp_hdr*)(packet + 1), len - sizeof(*packet));
                break;
            }
        }
    }

    inline static void pcap_live_loop_packet_device(u_char*, const struct pcap_pkthdr* pkg_hdr, const u_char* pkg_data) {
        struct eth_hdr* packet = (struct eth_hdr*)pkg_data;
        int len = pkg_hdr->len;
        int proto = ntohs(packet->proto);
        switch (proto) {
        case ETHTYPE_IP:
            if (MAC2I64(packet->dst) != MAC2I64(ETHERNET_MAC)) {
                return;
            }
            break;
        case ETHTYPE_ARP: {
            int64_t MAC = MAC2I64(packet->dst);
            if (MAC != 0xFFFFFFFFFFFF && MAC != MAC2I64(ETHERNET_MAC)) {
                return;
            }
            break;
        }
        default:
            return;
        };
        std::shared_ptr<char> buf = std::shared_ptr<char>((char*)malloc(len), free);
        memcpy(buf.get(), pkg_data, len);
        ETHERNET_CONTEXT_.post(std::bind(ethernet_input, packet, proto, buf, len));
    }

    inline static int ethernet_loop_packet_device() {
        #ifdef HAVE_PF_RING
        if (ETHERNET_RING) {
            static pfringProcesssPacket handler = [](struct pcap_pkthdr *h, u_char *p, u_char *user_bytes) {
                pcap_live_loop_packet_device(user_bytes, h, p);
            };
            return pfring_loop(ETHERNET_RING, handler, NULL, 1);
        }
        #endif

        if (ETHERNET_NIC) {
            return pcap_loop(ETHERNET_NIC, -1, pcap_live_loop_packet_device, NULL);
        }
        return -1;
    }

    inline static bool ethernet_open_packet_device(const std::string& device_) {
        #ifdef HAVE_PF_RING
        ETHERNET_RING = pfring_live_open_packet_device(device_, 1);
        if (ETHERNET_RING) {
            return true;
        }
        #endif
        
        ETHERNET_NIC = pcap_live_open_packet_device(device_);
        if (ETHERNET_NIC) {
            return true;
        }
        return false;
    }

    #ifdef _WIN32
    inline static bool ethernet_loopback(const std::string& device) {
    #else
    inline static bool ethernet_loopback(const std::string& device, int ncpu) {
    #endif
        ETHERNET_NAME_ = device;
        if (!ethernet_open_packet_device(device) || 
            #ifdef _WIN32
            !ethernet_init()
            #else
            !ethernet_init(ncpu)
            #endif
            ) {
            ethernet_release();
            return false;
        }
        
        fprintf(stdout, "Loopback:\r\nIP:    %s\r\nNgw:   %s\r\nMask:  %s\r\nMac:   %02x:%02x:%02x:%02x:%02x:%02x\r\nEther: %s\r\n",
            boost::asio::ip::address_v4(htonl(ETHERNET_IP)).to_string().data(),
            boost::asio::ip::address_v4(htonl(ETHERNET_NGW)).to_string().data(),
            boost::asio::ip::address_v4(htonl(ETHERNET_MASK)).to_string().data(),
            ETHERNET_MAC.s_data[0],
            ETHERNET_MAC.s_data[1],
            ETHERNET_MAC.s_data[2],
            ETHERNET_MAC.s_data[3],
            ETHERNET_MAC.s_data[4],
            ETHERNET_MAC.s_data[5],
            device.data());
        #ifdef _WIN32
        ethernet_gc_collect();
        #endif
        ethernet_loop_packet_device();
        ethernet_release();
        return true;
    }

    inline static struct sockaddr* ethernet_get_sockaddr_v4(struct pcap_addr* addresses) {
        if (!addresses) {
            return NULL;
        }
        for (;;) {
            struct sockaddr* address = addresses->addr;
            if (!address || address->sa_family != AF_INET) {
                if (!addresses->next) {
                    return NULL;
                }
                addresses = addresses->next;
            }
            else if (address->sa_family == AF_INET) {
                return address;
            }
        }
    }

    #ifdef _WIN32
    inline static PIP_ADAPTER_INFO ethernet_get_interface(uint32_t dwIndex, std::unique_ptr<char[]>& pAdapterPtr) {
        ULONG ulAdapterSize = 0;

        pAdapterPtr = std::make_unique<char[]>(sizeof(IP_ADAPTER_INFO));
        if (GetAdaptersInfo((PIP_ADAPTER_INFO)(pAdapterPtr.get()), &ulAdapterSize)) {
            pAdapterPtr.reset();
            pAdapterPtr = std::make_unique<char[]>(ulAdapterSize);
        }

        if (GetAdaptersInfo((PIP_ADAPTER_INFO)(pAdapterPtr.get()), &ulAdapterSize)) {
            return NULL;
        }

        auto pAdapter = (PIP_ADAPTER_INFO)pAdapterPtr.get();
        while (pAdapter) {
            if (*pAdapter->AdapterName == '\x0') {
                continue;
            }

            if (pAdapter->Index == dwIndex) {
                return pAdapter;
            }
            pAdapter = pAdapter->Next;
        }
        return NULL;
    }

    inline static std::string ethernet_get_interface_key(uint32_t dwIndex) {
        std::unique_ptr<char[]> pAdapterPtr;
        PIP_ADAPTER_INFO pi = ethernet_get_interface(dwIndex, pAdapterPtr);
        if (!pi) {
            return "";
        }
        return pi->Description;
    }

    uint32_t ethernet_get_interface(uint32_t dwIndex) {
        std::unique_ptr<char[]> pAdapterPtr;
        PIP_ADAPTER_INFO pi = ethernet_get_interface(dwIndex, pAdapterPtr);
        if (!pi) {
            return INADDR_ANY;
        }
        IP_ADDR_STRING* pa = &pi->IpAddressList;
        while (pa) {
            uint32_t dw = pa->Context;
            if (dw != INADDR_ANY && dw != INADDR_BROADCAST) {
                return dw;
            }
            pa = pa->Next;
        }
        return INADDR_ANY;
    }
    #else
    inline static uint32_t ethernet_interface_ip(uint32_t gw) {
        int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd == -1) {
            return INADDR_ANY;
        }
        int flags = fcntl(fd, F_GETFD, 0);
        if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
            close(fd);
            return INADDR_ANY;
        }
        struct sockaddr_in connect_addr;
        memset(&connect_addr, 0, sizeof(connect_addr));     
        connect_addr.sin_addr.s_addr = gw;
        connect_addr.sin_port = 53;
        connect_addr.sin_family = AF_INET;          
        int hr = connect(fd, (struct sockaddr*)&connect_addr, sizeof(connect_addr));
        if (hr == -1) {
            hr = errno;
            if (hr != EINPROGRESS) {
                close(fd);
                return INADDR_ANY;
            }
        }   
        struct sockaddr_in sock_addr;
        int sock_len = sizeof(sock_addr);
        memset(&sock_addr, 0, sizeof(sock_addr));   
        if (getsockname(fd, (struct sockaddr*)&sock_addr, (socklen_t*)&sock_len)) {
            close(fd);
            return INADDR_ANY;
        }
        else {
            close(fd);
        }
        if (sock_addr.sin_family != AF_INET) {
            return INADDR_ANY;
        }
        return sock_addr.sin_addr.s_addr;
    }

    inline static std::string ethernet_interface_name(uint32_t address) {
        if (address == INADDR_ANY || address == INADDR_NONE) {
            return "";
        }
        #if (!defined(ANDROID) || __ANDROID_API__ >= 24)
        struct ifaddrs* ifa = NULL;
        if (getifaddrs(&ifa) == -1) {
            return "";
        }
        struct ifaddrs* oifa = ifa;
        while (NULL != ifa) {
            struct sockaddr* addr = ifa->ifa_addr;
            if (NULL != addr) {
                switch (addr->sa_family) {
                    case AF_INET:
                    {
                        struct sockaddr_in* in4_addr = (struct sockaddr_in*)addr;
                        if (in4_addr->sin_addr.s_addr != address) {
                            break;
                        }
                        return ifa->ifa_name;
                    }
                };
            }
            ifa = ifa->ifa_next;
        }

        if (NULL != oifa) {
            freeifaddrs(oifa);
        }
        #endif
        return "";
    }
    
    inline static uint32_t ethernet_interface_index(const std::string& device) {
        if (device.empty()) {
            return UINT_MAX;
        }

        int sock_v4 = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (sock_v4 == -1) {
            return UINT_MAX;
        }

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, device.data(), device.size());
        if (ioctl(sock_v4, SIOGIFINDEX, &ifr) == -1) {
            close(sock_v4);
            return UINT_MAX;
        }
        else {
            close(sock_v4);
            return ifr.ifr_ifindex;
        }
    }
    #endif

    #ifdef _WIN32
    bool ethernet_loopback(struct eth_addr& mac, uint32_t ip, uint32_t ngw, uint32_t mask) {
    #else
    bool ethernet_loopback(struct eth_addr& mac, uint32_t ip, uint32_t ngw, uint32_t mask, bool lwip, int snat, int ncpu) {
    #endif
        if (ip == INADDR_ANY || ip == INADDR_NONE || ngw == INADDR_ANY || ngw == INADDR_NONE || mask == INADDR_ANY) {
            return false;
        }

        #ifndef _WIN32
        ETHERNET_LWIP = lwip;
        #endif
        ETHERNET_MAC = mac;
        ETHERNET_IP = ip;
        ETHERNET_NGW = ngw;
        ETHERNET_MASK = mask;

        struct pcap_if* alldevs;
        char errbuf[PCAP_ERRBUF_SIZE];

        #ifdef _WIN32
        if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) < 0) {
            return false;
        }

        DWORD dwIndex;
        if (GetBestInterface(ngw, &dwIndex) != ERROR_SUCCESS) {
            return false;
        }
        else {
            ETHERNET_IFINDEX_ = dwIndex;
        }

        std::string device = ethernet_get_interface_key(dwIndex);
        if (device.empty()) {
            return false;
        }
        return ethernet_loopback(device);
        #else
        int err = pcap_findalldevs(&alldevs, errbuf);
        if (err < 0) {
            return false;
        }

        std::string device = ethernet_interface_name(ethernet_interface_ip(ngw));
        if (device.empty()) {
            return false;
        }
        else {
            ETHERNET_IFINDEX_ = ethernet_interface_index(device);
        }

        if (snat) {
            return subnat_loopback(snat);
        }
        else {
            return ethernet_loopback(device, ncpu);
        }
        #endif
    }

    bool ethernet_release() {
        if (ETHERNET_FIN) {
            return false;
        }
        auto callbackf = [] {
            ETHERNET_FIN = true;

            static pcap_t* pcap = ETHERNET_NIC;
            if (pcap) {
                pcap_breakloop(pcap);
            }
            ETHERNET_NIC = NULL;

            #ifdef HAVE_PF_RING
            void* ring = ETHERNET_RING;
            if (ring) {
                pfring_breakloop(ring);
            }
            ETHERNET_RING = NULL;
            #endif
            
            etharp_release();
            ETHERNET_CONTEXT_.stop();
        };
        ETHERNET_CONTEXT_.post(callbackf);
        return true;
    }

    int ethernet_output(struct eth_hdr* eth, int len) {
        if (!eth || len < sizeof(*eth)) {
            return -1;
        }

        #ifdef HAVE_PF_RING
        void* ring = ETHERNET_RING;
        if (ring) {
            return pfring_send(ring, (char*)eth, len, 1) == -1 ? -1 : 0; 
        }
        #endif

        pcap_t* pcap = ETHERNET_NIC;
        if (!pcap) {
            return -1;
        }

        #ifdef _WIN32
        return pcap_sendpacket(pcap, (u_char*)eth, len);
        #else
        return pcap_inject(pcap, (u_char*)eth, len) == -1 ? -1 : 0;
        #endif
    }
}