#ifdef _WIN32
#include <WS2tcpip.h>
#include <iphlpapi.h>
#endif

#include "ipv4.h"
#include "icmp.h"
#include "./packet/IPEndPoint.h"
#include "./packet/IPFrame.h"
#include "./packet/IcmpFrame.h"

using vgw::packet::AddressFamily;
using vgw::packet::IPEndPoint;
using vgw::packet::BufferSegment;
using vgw::packet::IPFrame;
using vgw::packet::IcmpFrame;
using vgw::packet::IcmpType;

namespace vgw {
    extern uint32_t                                                 ETHERNET_IP;
    extern uint32_t                                                 ETHERNET_NGW;
    extern uint32_t                                                 ETHERNET_MASK;
    extern struct eth_addr                                          ETHERNET_MAC;
    extern boost::asio::io_context                                  ETHERNET_CONTEXT_;
    extern Byte                                                     ETHERNET_BUFFER_[ETHBUF_IANA_HWSNAP_ETHERNET];
    extern uint32_t                                                 ETHERNET_IFINDEX_;
    extern boost::asio::ip::udp::endpoint                           ETHERNET_ENDPOINT_;
    static const int                                                MAX_ICMP_TIMEOUT_ = 3;

    inline static bool icmp_replay(const std::shared_ptr<IPFrame> ping, const std::shared_ptr<IcmpFrame>& request, const std::shared_ptr<IPFrame>& packet) {
        if (!packet) {
            return false;
        }

        std::shared_ptr<IcmpFrame> frame = IcmpFrame::Parse(packet.get());
        if (!frame) {
            return false;
        }

        if (frame->Type == IcmpType::ICMP_ER) { // Echo-replay 
            if (frame->Source != request->Destination) {
                return false;
            }

            std::shared_ptr<IPFrame> e = make_shared_object<IPFrame>();
            if (!e) {
                return false;
            }

            e->AddressesFamily = AddressFamily::InterNetwork;
            e->ProtocolType = ip_hdr::IP_PROTO_ICMP;
            e->Source = request->Destination;
            e->Destination = request->Source;
            e->Payload = packet->Payload;
            e->Id = packet->Id;
            e->Tos = packet->Tos;
            e->Ttl = packet->Ttl;
            e->Flags = packet->Flags;
            e->Options = packet->Options;
            e->SetFragmentOffset(packet->GetFragmentOffset());
            return ipv4_output_(e.get());
        }
        else if (frame->Type == IcmpType::ICMP_TE) {
            std::shared_ptr<BufferSegment> payload_ = frame->Payload;
            if (!payload_) {
                return false;
            }

            std::shared_ptr<IPFrame> raw = IPFrame::Parse(payload_->Buffer.get(), payload_->Length);
            if (!raw) {
                return false;
            }

            if (raw->Destination != request->Destination) {
                return false;
            }

            std::shared_ptr<IcmpFrame> out = make_shared_object<IcmpFrame>();
            if (!out) {
                return false;
            }

            out->AddressesFamily = AddressFamily::InterNetwork;
            out->Source = frame->Source;
            out->Destination = request->Source;
            out->Payload = raw->ToArray();
            out->Identification = frame->Identification;
            out->Code = frame->Code;
            out->Sequence = frame->Sequence;
            out->Ttl = frame->Ttl;
            out->Type = frame->Type;

            std::shared_ptr<IPFrame> e = out->ToIp();
            if (!e) {
                return false;
            }

            e->AddressesFamily = AddressFamily::InterNetwork;
            e->ProtocolType = ip_hdr::IP_PROTO_ICMP;
            e->Id = packet->Id;
            e->Tos = packet->Tos;
            e->Ttl = packet->Ttl;
            e->Flags = packet->Flags;
            e->Options = packet->Options;
            e->SetFragmentOffset(packet->GetFragmentOffset());
            return ipv4_output_(e.get());
        }
        return false;
    }

    inline static void icmp_closesocket(const std::shared_ptr<boost::asio::ip::udp::socket>& socket_, uint32_t sockfd_) {
        if (socket_) {
            if (socket_->is_open()) {
                boost::system::error_code ec_;
                socket_->close(ec_);
            }
        }
        #ifdef _WIN32
        if (sockfd_ != UINT_MAX) {
            closesocket(sockfd_);
        }
        #else
        if (sockfd_ != UINT_MAX) {
            close(sockfd_);
        }
        #endif
    }

    inline static bool icmp_echo(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame) {
        if (!packet || !frame) {
            return false;
        }

        uint32_t sockfd_ = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sockfd_ == UINT_MAX) {
            return false;
        }
        else {
            int TTL_ = packet->Ttl;
            if (setsockopt(sockfd_, IPPROTO_IP, IP_TTL, (char*)&TTL_, sizeof(TTL_))) {
                #ifdef _WIN32
                closesocket(sockfd_);
                #else
                close(sockfd_);
                #endif
                return false;
            }
            #ifdef _WIN32
            int sendTimeout_ = 1000;
            int recvTimeout_ = 3000;
            if (setsockopt(sockfd_, SOL_SOCKET, SO_SNDTIMEO, (char*)&sendTimeout_, sizeof(sendTimeout_))) {
                closesocket(sockfd_);
                return false;
            }
            if (setsockopt(sockfd_, SOL_SOCKET, SO_RCVTIMEO, (char*)&recvTimeout_, sizeof(recvTimeout_))) {
                closesocket(sockfd_);
                return false;
            }
            #else
            struct timeval sendTimeout_ = {1, 0};
            struct timeval recvTimeout_ = {3, 0};
            if (setsockopt(sockfd_, SOL_SOCKET, SO_SNDTIMEO, (char*)&sendTimeout_, sizeof(sendTimeout_))) {
                close(sockfd_);
                return false;
            }
            if (setsockopt(sockfd_, SOL_SOCKET, SO_RCVTIMEO, (char*)&recvTimeout_, sizeof(recvTimeout_))) {
                close(sockfd_);
                return false;
            }
            #endif
        }

        boost::system::error_code ec_;
        std::shared_ptr<boost::asio::ip::udp::socket> socket_ = make_shared_object<boost::asio::ip::udp::socket>(ETHERNET_CONTEXT_);
        if (!socket_) {
            #ifdef _WIN32
            closesocket(sockfd_);
            #else
            close(sockfd_);
            #endif
            return false;
        }

        socket_->assign(boost::asio::ip::udp::v4(), sockfd_, ec_);
        if (ec_) {
            icmp_closesocket(socket_, sockfd_);
            return false;
        }

        std::shared_ptr<BufferSegment> messages_ = packet->Payload;
        socket_->send_to(boost::asio::buffer(messages_->Buffer.get(), messages_->Length),
            IPEndPoint::WrapAddress<boost::asio::ip::udp>(packet->Destination, IPEndPoint::MaxPort), 0, ec_);
        if (ec_) {
            icmp_closesocket(socket_, sockfd_);
            return false;
        }

        struct icmp_echo_context {
            std::shared_ptr<IcmpFrame> frame_;
            std::shared_ptr<IPFrame> packet_;
            std::shared_ptr<boost::asio::ip::udp::socket> socket_;
            uint32_t sockfd_;
            uint64_t start_;
            std::function<void(const boost::system::error_code&, size_t )> callback_;
        };

        std::shared_ptr<icmp_echo_context> context_ = make_shared_object<icmp_echo_context>();
        context_->frame_ = frame;
        context_->packet_ = packet;
        context_->sockfd_ = sockfd_;
        context_->socket_ = socket_;
        context_->start_ = ipv4_time();
        context_->callback_ = [context_](const boost::system::error_code& ec_, size_t sz_) {
            bool cleanup_ = true;
            do {
                uint64_t now_ = ipv4_time();
                if (ec_ || context_->start_ > now_) {
                    break;
                }

                int64_t timeout_ = MAX_ICMP_TIMEOUT_ - (int64_t)(now_ - context_->start_);
                if (timeout_ < 1) {
                    break;
                }

                std::shared_ptr<IPFrame> response_ = IPFrame::Parse(ETHERNET_BUFFER_, sz_);
                if (response_) {
                    if (icmp_replay(context_->packet_, context_->frame_, response_)) {
                        break;
                    }
                }

                std::shared_ptr<boost::asio::ip::udp::socket> socket_ = context_->socket_;
                if (!socket_) {
                    break;
                }

                int recvTimeout_ = (int)timeout_;
                if (setsockopt(context_->sockfd_, SOL_SOCKET, SO_RCVTIMEO, (char*)&recvTimeout_, sizeof(recvTimeout_))) {
                    break;
                }

                cleanup_ = false;
                socket_->async_receive_from(boost::asio::buffer(ETHERNET_BUFFER_, sizeof(ETHERNET_BUFFER_)), ETHERNET_ENDPOINT_, context_->callback_);
            } while (0);
            if (cleanup_) {
                icmp_closesocket(context_->socket_, context_->sockfd_);
                context_->start_ = 0;
                context_->sockfd_ = UINT_MAX;
                context_->frame_ = NULL;
                context_->packet_ = NULL;
                context_->socket_ = NULL;
                context_->callback_ = NULL;
            }
        };
        socket_->async_receive_from(boost::asio::buffer(ETHERNET_BUFFER_, sizeof(ETHERNET_BUFFER_)), ETHERNET_ENDPOINT_, context_->callback_);
        return true;
    }

    bool icmp_input(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame) {
        if (!packet || !frame || frame->Type != IcmpType::ICMP_ECHO) {
            return false;
        }
        if (frame->Destination == ETHERNET_IP) {
            std::shared_ptr<IcmpFrame> e = make_shared_object<IcmpFrame>();
            e->AddressesFamily = AddressFamily::InterNetwork;
            e->Type = IcmpType::ICMP_ER;
            e->Code = frame->Code;
            e->Ttl = frame->Ttl;
            e->Sequence = frame->Sequence;
            e->Identification = frame->Identification;
            e->Source = frame->Destination;
            e->Destination = frame->Source;
            e->Payload = frame->Payload;
            return ipv4_output_(e->ToIp().get());
        }
        else if (frame->Ttl <= 1) {
            std::shared_ptr<IcmpFrame> e = make_shared_object<IcmpFrame>();
            e->AddressesFamily = AddressFamily::InterNetwork;
            e->Type = IcmpType::ICMP_TE;
            e->Code = 0;
            e->Ttl = UINT8_MAX;
            e->Sequence = 0;
            e->Identification = 0;
            e->Source = ETHERNET_IP;
            e->Destination = frame->Source;
            e->Payload = packet->ToArray();
            return ipv4_output_(e->ToIp().get());
        }
        else {
            packet->Ttl -= 1;
        }
        return icmp_echo(packet, frame);
    }
}