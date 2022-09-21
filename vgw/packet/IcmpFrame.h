#pragma once

#include "../env.h"
#include "../gw.h"
#include "./native/icmp.h"
#include "IPEndPoint.h"
#include "IPFrame.h"

namespace vgw {
    namespace packet {
        typedef vgw::packet::native::IcmpType                IcmpType;

        class IPFrame;
        class BufferSegment;

        class IcmpFrame final {
        public:
            IcmpType                                        Type;
            Byte                                            Code;
            UInt16                                          Identification;
            UInt16                                          Sequence;
            UInt32                                          Source;
            UInt32                                          Destination;
            Byte                                            Ttl;
            AddressFamily                                   AddressesFamily;
            std::shared_ptr<BufferSegment>                  Payload;

        public:
            inline IcmpFrame()
                : Type(IcmpType::ICMP_ECHO)
                , Code(0)
                , Identification(0)
                , Sequence(0)
                , Source(0)
                , Destination(0)
                , Ttl(IPFrame::DefaultTtl)
                , AddressesFamily(AddressFamily::InterNetwork) {
            }

        public:
            inline static std::shared_ptr<IPFrame>          ToIp(const IcmpFrame* frame) {
                if (NULL == frame) {
                    return NULL;
                }
                return const_cast<IcmpFrame*>(frame)->ToIp();
            }
            std::shared_ptr<IPFrame>                        ToIp();
            static std::shared_ptr<IcmpFrame>               Parse(const IPFrame* frame);
        };
    }
}