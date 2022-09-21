#pragma once

#include "../env.h"
#include "../gw.h"
#include "./native/udp.h"
#include "IPEndPoint.h"
#include "IPFrame.h"

namespace vgw {
    namespace packet {
        class IPFrame;
        class BufferSegment;

        class UdpFrame final {
        public:
            IPEndPoint                                      Source;
            IPEndPoint                                      Destination;
            AddressFamily                                   AddressesFamily;
            Byte                                            Ttl;
            std::shared_ptr<BufferSegment>                  Payload;

        public:
            inline UdpFrame()
                : AddressesFamily(AddressFamily::InterNetwork)
                , Ttl(IPFrame::DefaultTtl) {
            }

        public:
            inline static std::shared_ptr<IPFrame>          ToIp(const UdpFrame* frame) {
                if (NULL == frame) {
                    return NULL;
                }
                return const_cast<UdpFrame*>(frame)->ToIp();
            }
            std::shared_ptr<IPFrame>                        ToIp();
            static std::shared_ptr<UdpFrame>                Parse(const IPFrame* frame);
        };
    }
}