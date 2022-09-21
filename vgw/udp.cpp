#include "udp.h"
#include "ipv4.h"
#include "./packet/IPEndPoint.h"
#include "./packet/IPFrame.h"
#include "./packet/UdpFrame.h"

using vgw::packet::AddressFamily;
using vgw::packet::IPEndPoint;
using vgw::packet::BufferSegment;
using vgw::packet::IPFrame;
using vgw::packet::UdpFrame;

namespace vgw {
    class DatagramPort;

    typedef std::shared_ptr<DatagramPort>                           DATAGRAM_PORT_PTR;
    typedef std::unordered_map<int64_t, DATAGRAM_PORT_PTR>          DATAGRAM_PORT_TABLE;

    extern uint32_t                                                 ETHERNET_IP;
    extern uint32_t                                                 ETHERNET_NGW;
    extern uint32_t                                                 ETHERNET_MASK;
    extern struct eth_addr                                          ETHERNET_MAC;
    extern boost::asio::io_context                                  ETHERNET_CONTEXT_;
    extern Byte                                                     ETHERNET_BUFFER_[ETHBUF_IANA_HWSNAP_ETHERNET];
    extern boost::asio::ip::udp::endpoint                           ETHERNET_ENDPOINT_;

    static std::shared_ptr<boost::asio::deadline_timer>             ETHERNET_UDP_TICKTMR_;
    static DATAGRAM_PORT_TABLE                                      ETHERNET_UDP_TABLE_;

    static const int                                                ETHERNET_UDP_DNS_PORT = 53;
    static const int                                                ETHERNET_UDP_DNS_TIMEOUT = 3;
    static const int                                                ETHERNET_UDP_PORT_TIMEOUT = 72;

    class DatagramPort : public std::enable_shared_from_this<DatagramPort> {
    public:
        inline DatagramPort(const IPEndPoint& sourceEP) 
            : onlydns_(0) 
            , last_(0)
            , source_(sourceEP)
            , socket_(ETHERNET_CONTEXT_) {
            
        }
        inline ~DatagramPort() {
            this->Close();
        }

    public:
        inline static int64_t                                       ToKey(const IPEndPoint& endpoint_) {
            if (endpoint_.GetAddressFamily() != AddressFamily::InterNetwork) {
                return 0;
            }
            return (int64_t)endpoint_.Port << 32 | endpoint_.GetAddress();
        }
        inline bool                                                 Run() {
            boost::system::error_code ec_;
            if (socket_.is_open()) {
                return false;
            }

            AddressFamily af_ = source_.GetAddressFamily();
            if (af_ == AddressFamily::InterNetwork) {
                socket_.open(boost::asio::ip::udp::v4(), ec_);
            }
            else if (af_ == AddressFamily::InterNetworkV6) {
                socket_.open(boost::asio::ip::udp::v6(), ec_);
            }
            else {
                return false;
            }
            if (ec_) {
                return false;
            }

            if (af_ == AddressFamily::InterNetwork) {
                socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::any(), 0), ec_);
            }
            else {
                socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::address_v6::any(), 0), ec_);
            }
            if (ec_) {
                return false;
            }

            this->last_ = ipv4_time();
            return this->Loopback();
        }
        inline bool                                                 IsPortAging(uint64_t now) {
            if (!socket_.is_open()) {
                return true;
            }

            UInt64 milliseconds = now - this->last_;
            UInt64 maxInactivityTime = 0;
            if (1 != this->onlydns_) {
                maxInactivityTime = ETHERNET_UDP_PORT_TIMEOUT;
            }
            else {
                maxInactivityTime = ETHERNET_UDP_DNS_TIMEOUT;
            }

            if (maxInactivityTime < 1) {
                maxInactivityTime = 1;
            }
            return milliseconds >= maxInactivityTime;
        }
        inline bool                                                 Input(const std::shared_ptr<BufferSegment>& messages_, const IPEndPoint& destinationEP) {
            if (!messages_ || IPEndPoint::IsInvalid(destinationEP)) {
                return false;
            }

            if (!socket_.is_open() || messages_->Length < 1) {
                return false;
            }

            std::shared_ptr<Byte>& buff_ = messages_->Buffer;
            if (!buff_) {
                return false;
            }

            boost::system::error_code ec_;
            socket_.send_to(boost::asio::buffer(buff_.get(), messages_->Length),
                IPEndPoint::ToEndPoint<boost::asio::ip::udp>(destinationEP), 0, ec_);
            if (ec_) {
                this->Close();
                return false;
            }

            if (destinationEP.Port != ETHERNET_UDP_DNS_PORT) {
                this->onlydns_ = 2;
            }
            else if (this->onlydns_ == 0) {
                this->onlydns_ = 1;
            }
            this->last_ = ipv4_time();
            return true;
        }
        inline void                                                 Close() {
            boost::system::error_code ec_;
            if (socket_.is_open()) {
                socket_.close(ec_);
            }
        }

    private:
        inline bool                                                 Loopback() {
            if (!socket_.is_open()) {
                return false;
            }
            std::shared_ptr<DatagramPort> self_ = shared_from_this();
            socket_.async_receive_from(boost::asio::buffer(ETHERNET_BUFFER_, sizeof(ETHERNET_BUFFER_)), ETHERNET_ENDPOINT_,
                [self_, this](const boost::system::error_code& ec_, size_t sz) {
                    if (ec_) {
                        this->Close();
                        return;
                    }
                    else if (sz > 0) {
                        std::shared_ptr<UdpFrame> packet_ = make_shared_object<UdpFrame>();
                        std::shared_ptr<Byte> messages_ = std::shared_ptr<Byte>(ETHERNET_BUFFER_, [](Byte*) {});

                        packet_->Destination = source_;
                        packet_->Source = IPEndPoint::ToEndPoint(ETHERNET_ENDPOINT_);
                        packet_->AddressesFamily = packet_->Source.GetAddressFamily();
                        packet_->Payload = make_shared_object<BufferSegment>(messages_, sz);
                        this->Output(packet_);
                    }
                    this->Loopback();
                });
            return true;
        }
        inline void                                                 Output(const std::shared_ptr<UdpFrame>& packet) {
            std::shared_ptr<IPFrame> ip = packet->ToIp();
            if (ip) {
                ipv4_output_(ip.get());
            }
        }

    private:
        int                                                         onlydns_;
        int64_t                                                     last_;
        IPEndPoint                                                  source_;
        boost::asio::ip::udp::socket                                socket_;
    };

    inline static void udp_update(uint64_t now) {
        std::vector<int64_t> release_;

        DATAGRAM_PORT_TABLE::iterator tail_ = ETHERNET_UDP_TABLE_.begin();
        DATAGRAM_PORT_TABLE::iterator endl_ = ETHERNET_UDP_TABLE_.end();

        for (; tail_ != endl_; tail_++) {
            const std::shared_ptr<DatagramPort>& socket_ = tail_->second;
            if (!socket_) {
                release_.push_back(tail_->first);
            }
            else if (socket_->IsPortAging(now)) {
                socket_->Close();
                release_.push_back(tail_->first);
            }
        }

        for (size_t i_ = 0, l_ = release_.size(); i_ < l_; i_++) {
            tail_ = ETHERNET_UDP_TABLE_.find(release_[i_]);
            if (tail_ != endl_) {
                ETHERNET_UDP_TABLE_.erase(tail_);
            }
        }
    }

    inline static void udp_loopback() {
        std::shared_ptr<boost::asio::deadline_timer> ticktmr_ = ETHERNET_UDP_TICKTMR_;
        if (!ticktmr_) {
            ticktmr_ = make_shared_object<boost::asio::deadline_timer>(ETHERNET_CONTEXT_);
            ETHERNET_UDP_TICKTMR_ = ticktmr_;
        }

        auto callbackf = [ticktmr_](const boost::system::error_code& ec) {
            if (!ec) {
                uint64_t now = ipv4_time();
                udp_update(now);
                udp_loopback();
            }
        };
        ticktmr_->expires_from_now(boost::posix_time::seconds(1));
        ticktmr_->async_wait(callbackf);
    }

    void udp_init() {
        udp_loopback();
    }

    bool udp_input(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<UdpFrame>& frame) {
        if (!packet || !frame) {
            return false;
        }

        int64_t srcKey_ = DatagramPort::ToKey(frame->Source);
        if (!srcKey_) {
            return false;
        }

        std::shared_ptr<DatagramPort> localPort_;
        DATAGRAM_PORT_TABLE::iterator tail_ = ETHERNET_UDP_TABLE_.find(srcKey_);
        DATAGRAM_PORT_TABLE::iterator endl_ = ETHERNET_UDP_TABLE_.end();
        if (tail_ != endl_) {
            localPort_ = tail_->second;
        }
        else {
            localPort_ = make_shared_object<DatagramPort>(frame->Source);
            if (!localPort_ || !localPort_->Run()) {
                return false;
            }
            ETHERNET_UDP_TABLE_[srcKey_] = localPort_;
        }
        return localPort_->Input(frame->Payload, frame->Destination);
    }
}