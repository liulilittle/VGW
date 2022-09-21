#pragma once

#include "../env.h"
#include <boost/asio/ip/basic_endpoint.hpp>

namespace vgw {
    namespace packet {
        enum AddressFamily {
            InterNetwork                                                        = AF_INET,
            InterNetworkV6                                                      = AF_INET6,
        };                      

        struct IPEndPoint {                      
        private:                        
            mutable Byte                                                        _AddressBytes[sizeof(struct in6_addr)]; // 16
            AddressFamily                                                       _AddressFamily;

        public:                                                 
            const int                                                           Port;

        public:                 
            static const int MinPort                                            = 0;
            static const int MaxPort                                            = UINT16_MAX;
            static const UInt32 NoneAddress                                     = INADDR_NONE;

        public:
            inline IPEndPoint()
                : IPEndPoint(NoneAddress, 0) {
            
            }
            inline IPEndPoint(UInt32 address, int port)
                : _AddressFamily(AddressFamily::InterNetwork)
                , Port(port) {
                *(UInt32*)this->_AddressBytes = address;
            }
            IPEndPoint(const char* address, int port);
            IPEndPoint(AddressFamily af, const void* address_bytes, int address_size, int port);

        public:
            inline bool                                                         IsNone() {
                if (AddressFamily::InterNetwork != this->_AddressFamily) {
                    return false;
                }
                else {
                    UInt32 dw = this->GetAddress();
                    return dw == IPEndPoint::NoneAddress;
                }
            }
            inline bool                                                         IsAny() {
                if (AddressFamily::InterNetwork != this->_AddressFamily) {
                    return false;
                }
                else {
                    UInt32 dw = this->GetAddress();
                    return dw == 0;
                }
            }
            inline std::string                                                  GetAddressBytes() const {
                int datalen;
                Byte* data = this->GetAddressBytes(datalen);
                return std::string((char*)data, datalen); 
            }  
            inline Byte*                                                        GetAddressBytes(int& len) const {
                if (this->_AddressFamily == AddressFamily::InterNetworkV6) {
                    len = sizeof(this->_AddressBytes);
                    return this->_AddressBytes;
                }
                else {
                    len = sizeof(UInt32);
                    return this->_AddressBytes;
                }
            }
            inline UInt32                                                       GetAddress() const {
                return *(UInt32*)this->_AddressBytes;
            }
            inline AddressFamily                                                GetAddressFamily() const {
                return this->_AddressFamily;
            }
            inline bool                                                         Equals(const IPEndPoint& value) const {
                IPEndPoint* right = (IPEndPoint*)&reinterpret_cast<const char&>(value);
                if ((IPEndPoint*)this == (IPEndPoint*)right) {
                    return true;
                }
                if ((IPEndPoint*)this == (IPEndPoint*)NULL || 
                    (IPEndPoint*)right == (IPEndPoint*)NULL || 
                    this->Port != value.Port) {
                    return false;
                }
                return *this == value;
            }
            inline bool                                                         operator == (const IPEndPoint& right) const {
                if (this->_AddressFamily != right._AddressFamily) {
                    return false;
                }

                Byte* x = this->_AddressBytes;
                Byte* y = right._AddressBytes;
                if (x == y) {
                    return true;
                }

                if (this->_AddressFamily == AddressFamily::InterNetworkV6) {
                    UInt64* qx = (UInt64*)x;
                    UInt64* qy = (UInt64*)y;
                    return qx[0] == qy[0] && qx[1] == qy[1];
                }
                return *(UInt32*)x == *(UInt32*)y;
            }
            inline bool                                                         operator != (const IPEndPoint& right) const {
                bool b = (*this) == right;
                return !b;
            }
            inline IPEndPoint&                                                  operator = (const IPEndPoint& right) { 
                this->_AddressFamily = right._AddressFamily;
                const_cast<int&>(this->Port) = right.Port;

                int address_bytes_size;
                Byte* address_bytes = right.GetAddressBytes(address_bytes_size);
                memcpy(this->_AddressBytes, address_bytes, address_bytes_size);

                return *this;
            }
            inline std::string                                                  ToAddressString() noexcept {
                int address_bytes_size;
                Byte* address_bytes = GetAddressBytes(address_bytes_size);
                return ToAddressString(this->_AddressFamily, address_bytes, address_bytes_size);
            }
            std::string                                                         ToString() noexcept;

        public:                 
            static std::string                                                  GetHostName() noexcept;
            static std::string                                                  ToAddressString(AddressFamily af, const Byte* address_bytes, int address_size) noexcept;
            inline static std::string                                           ToAddressString(UInt32 address) noexcept {
                return ToAddressString(AddressFamily::InterNetwork, (Byte*)&address, sizeof(address));
            }
            inline static std::string                                           ToAddressString(AddressFamily af, const std::string& address_bytes) noexcept {
                return ToAddressString(af, (Byte*)address_bytes.data(), address_bytes.size());
            }
            inline static UInt32                                                PrefixToNetmask(int prefix) {
                UInt32 mask = prefix ? (~0 << (32 - prefix)) : 0;
                return htonl(mask);
            }
            inline static int                                                   NetmaskToPrefix(UInt32 mask) {
                unsigned char* bytes    = (unsigned char*)&mask;
                unsigned int bitLength  = 0;
                unsigned int idx        = 0;

                // find beginning 0xFF
                for (; idx < sizeof(mask) && bytes[idx] == 0xff; idx++);
                bitLength = 8 * idx;

                if (idx < sizeof(mask)) {
                    switch (bytes[idx]) {
                        case 0xFE: bitLength += 7; break;
                        case 0xFC: bitLength += 6; break;
                        case 0xF8: bitLength += 5; break;
                        case 0xF0: bitLength += 4; break;
                        case 0xE0: bitLength += 3; break;
                        case 0xC0: bitLength += 2; break;
                        case 0x80: bitLength += 1; break;
                        case 0x00: break;
                        default: // invalid bitmask
                            return ~0;
                    }
                    // remainder must be 0x00
                    for (unsigned int j = idx + 1; j < sizeof(mask); j++) {
                        unsigned char x = bytes[j];
                        if (x != 0x00) {
                            return ~0;    
                        }
                    }
                }
                return bitLength;
            }
            inline static bool                                                  IsInvalid(const IPEndPoint* p) {
                IPEndPoint* __p = (IPEndPoint*)p;
                if (NULL == __p) {
                    return true;
                }
                if (__p->IsNone()) {
                    return true;
                }
                if (__p->IsAny()) {
                    return true;
                }
                return false;
            }
            inline static bool                                                  IsInvalid(const IPEndPoint& value) {
                return IPEndPoint::IsInvalid(std::addressof(value));
            }

        public:
            template<class TProtocol>
            inline static boost::asio::ip::basic_endpoint<TProtocol>            ToEndPoint(const IPEndPoint& endpoint) {
                AddressFamily af = endpoint.GetAddressFamily();
                if (af == AddressFamily::InterNetwork) {
                    return WrapAddress<TProtocol>(endpoint.GetAddress(), endpoint.Port);
                }
                else {
                    int len;
                    const Byte* address = endpoint.GetAddressBytes(len);
                    return WrapAddressV6<TProtocol>(address, len, endpoint.Port);
                }
            }
            template<class TProtocol>
            inline static IPEndPoint                                            ToEndPoint(const boost::asio::ip::basic_endpoint<TProtocol>& endpoint) {
                boost::asio::ip::address address = endpoint.address();
                if (address.is_v4()) {
                    return IPEndPoint(ntohl(address.to_v4().to_ulong()), endpoint.port());
                }
                else {
                    boost::asio::ip::address_v6::bytes_type bytes = address.to_v6().to_bytes();
                    return IPEndPoint(AddressFamily::InterNetworkV6, bytes.data(), bytes.size(), endpoint.port());
                }
            }
            template<class TProtocol>   
            inline static boost::asio::ip::basic_endpoint<TProtocol>            NewAddress(const char* address, int port) {
                if (NULL == address || *address == '\x0') {
                    address = "0.0.0.0";
                }

                if (port < IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                    port = IPEndPoint::MinPort;
                }

                boost::system::error_code ec;
                boost::asio::ip::address ba = boost::asio::ip::address::from_string(address, ec);
                if (ec) {
                    ba = boost::asio::ip::address_v4(IPEndPoint::NoneAddress);
                }

                boost::asio::ip::basic_endpoint<TProtocol> defaultEP(ba, port);
                return defaultEP;
            }
            template<class TProtocol>   
            inline static boost::asio::ip::basic_endpoint<TProtocol>            WrapAddress(UInt32 address, int port) {
                typedef boost::asio::ip::basic_endpoint<TProtocol> protocol_endpoint;

                return protocol_endpoint(boost::asio::ip::address_v4(ntohl(address)), port);
            }
            template<class TProtocol>               
            inline static boost::asio::ip::basic_endpoint<TProtocol>            WrapAddressV6(const void* address, int size, int port) {
                typedef boost::asio::ip::basic_endpoint<TProtocol> protocol_endpoint;

                if (size < 0) {
                    size = 0;
                }

                boost::asio::ip::address_v6::bytes_type address_bytes;
                unsigned char* p = &address_bytes[0];
                memcpy(p, address, size);
                memset(p, 0, address_bytes.size() - size);

                return protocol_endpoint(boost::asio::ip::address_v6(address_bytes), port);
            }
            template<class TProtocol>               
            inline static boost::asio::ip::basic_endpoint<TProtocol>            AnyAddress(int port) {
                 return NewAddress<TProtocol>("\x0", port);
            }
            template<class TProtocol>               
            inline static boost::asio::ip::basic_endpoint<TProtocol>            LocalAddress(boost::asio::ip::basic_resolver<TProtocol>& resolver, int port) {
                return GetAddressByHostName<TProtocol>(resolver, GetHostName(), port);
            }
            template<class TProtocol>               
            inline static boost::asio::ip::basic_endpoint<TProtocol>            GetAddressByHostName(boost::asio::ip::basic_resolver<TProtocol>& resolver, const std::string& hostname, int port) {
                typedef boost::asio::ip::basic_resolver<TProtocol> protocol_resolver;
                
                typename protocol_resolver::query q(hostname.c_str(), std::to_string(port).c_str());
#ifndef _WIN32
                typename protocol_resolver::iterator i = resolver.resolve(q);
                typename protocol_resolver::iterator l;

                if (i == l) {
                    return AnyAddress<TProtocol>(port);
                }
#else
                typename protocol_resolver::results_type results = resolver.resolve(q);
                if (results.empty()) {
                    return AnyAddress<TProtocol>(port);
                }

                typename protocol_resolver::iterator i = results.begin();
                typename protocol_resolver::iterator l = results.end();
#endif
                for (; i != l; ++i) {
                    boost::asio::ip::basic_endpoint<TProtocol> localEP = *i;
                    if (!localEP.address().is_v4()) {
                        continue;
                    }
    
                    return localEP;
                }
    
                return AnyAddress<TProtocol>(port);
            }
            template<class TProtocol>               
            inline static bool                                                  Equals(const boost::asio::ip::basic_endpoint<TProtocol>& x, const boost::asio::ip::basic_endpoint<TProtocol>& y) {
                if (x != y) {
                    return false;
                }

                if (x.address() != y.address()) {
                    return false;
                }

                return x.port() == y.port();
            }
        };
    }
}