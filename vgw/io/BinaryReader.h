#pragma once

#include "../env.h"
#include "Stream.h"

namespace vgw {
    namespace io {
        class BinaryReader {
        public:
            inline BinaryReader(Stream& stream) : _stream(stream) {}

        public:
            inline int                                      Read(const void* buffer, int offset, int length) {
                return _stream.Read(buffer, offset, length);
            }
            template<typename TValueType>   
            inline std::shared_ptr<TValueType>              ReadValues(int counts) {
                if (counts <= 0) {
                    return NULL;
                }

                std::shared_ptr<TValueType> buf = make_shared_alloc<TValueType>(counts);
                if (NULL == buf) {
                    return NULL;
                }

                int size = counts * sizeof(TValueType);
                int len = _stream.Read(buf.get(), 0, size);
                if (len < 0 || len != size) {
                    return NULL;
                }
                return buf;
            }
            inline std::shared_ptr<Byte>                    ReadBytes(int counts) {
                return ReadValues<Byte>(counts);
            }
            template<typename TValueType>   
            inline bool                                     TryReadValue(TValueType& out) {
                TValueType* p = (TValueType*)&reinterpret_cast<const char&>(out);
                int len = _stream.Read(p, 0, sizeof(TValueType));
                return (size_t)len == sizeof(TValueType);
            }
            template<typename TValueType>           
            inline TValueType                               ReadValue() {
                TValueType out;
                if (!TryReadValue(out)) {
                    throw std::runtime_error("Unable to read from stream to TValueType size values");
                }
                return out;
            }
            inline Stream&                                  GetStream() { return _stream; }

        public:
            inline Int16                                    ReadInt16() { return ReadValue<Int16>(); }
            inline Int32                                    ReadInt32() { return ReadValue<Int32>(); }
            inline Int64                                    ReadInt64() { return ReadValue<Int64>(); }
            inline UInt16                                   ReadUInt16() { return ReadValue<UInt16>(); }
            inline UInt32                                   ReadUInt32() { return ReadValue<UInt32>(); }
            inline UInt64                                   ReadUInt64() { return ReadValue<UInt64>(); }
            inline SByte                                    ReadSByte() { return ReadValue<SByte>(); }
            inline Byte                                     ReadByte() { return ReadValue<Byte>(); }
            inline Single                                   ReadSingle() { return ReadValue<Single>(); }
            inline Double                                   ReadDouble() { return ReadValue<Double>(); }
            inline bool                                     ReadBoolean() { return ReadValue<bool>(); }
            inline Char                                     ReadChar() { return ReadValue<Char>(); }

        public:     
            inline bool                                     TryReadInt16(Int16& out) { return TryReadValue(out); }
            inline bool                                     TryReadInt32(Int32& out) { return TryReadValue(out); }
            inline bool                                     TryReadInt64(Int64& out) { return TryReadValue(out); }
            inline bool                                     TryReadUInt16(UInt16& out) { return TryReadValue(out); }
            inline bool                                     TryReadUInt32(UInt32& out) { return TryReadValue(out); }
            inline bool                                     TryReadUInt64(UInt64& out) { return TryReadValue(out); }
            inline bool                                     TryReadSByte(SByte& out) { return TryReadValue(out); }
            inline bool                                     TryReadByte(Byte& out) { return TryReadValue(out); }
            inline bool                                     TryReadSingle(Single& out) { return TryReadValue(out); }
            inline bool                                     TryReadDouble(bool& out) { return TryReadValue(out); }
            inline bool                                     TryReadBoolean(bool& out) { return TryReadValue(out); }
            inline bool                                     TryReadChar(Char& out) { return TryReadValue(out); }

        private:            
            Stream&                                         _stream;
        };
    }
}