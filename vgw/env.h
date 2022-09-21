#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

#include <list>
#include <vector>
#include <functional>
#include <memory>
#include <string>
#include <algorithm>
#include <unordered_set>
#include <unordered_map>

#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#ifdef _WIN32
namespace boost { // boost::asio::posix::stream_descriptor
    namespace asio {
        namespace posix {
            typedef boost::asio::windows::stream_handle stream_descriptor;
        }
    }
}
#include <WinSock2.h>
#else
namespace boost {
    namespace asio {
        typedef io_service io_context;
    }
}
#endif

namespace vgw {
    typedef unsigned char                                               Byte;
    typedef signed char                                                 SByte;
    typedef signed short int                                            Int16;
    typedef signed int                                                  Int32;
    typedef signed long long                                            Int64;
    typedef unsigned short int                                          UInt16;
    typedef unsigned int                                                UInt32;
    typedef unsigned long long                                          UInt64;
    typedef double                                                      Double;
    typedef float                                                       Single;
    typedef bool                                                        Boolean;
    typedef signed char                                                 Char;

    int                                                                 GetHashCode(const char* s, int len);
    std::string                                                         StrFormatByteSize(int64_t size);
    bool                                                                GetCommandArgument(const char* name, int argc, const char** argv, bool defaultValue);
    std::string                                                         GetCommandArgument(const char* name, int argc, const char** argv);
    std::string                                                         GetCommandArgument(const char* name, int argc, const char** argv, const char* defaultValue);
    std::string                                                         GetCommandArgument(const char* name, int argc, const char** argv, const std::string& defaultValue);
    std::string                                                         LTrim(const std::string& s);
    std::string                                                         RTrim(const std::string& s);
    std::string                                                         ToUpper(const std::string& s);
    std::string                                                         ToLower(const std::string& s);
    std::string                                                         Replace(const std::string& s, const std::string& old_value, const std::string& new_value);
    std::string                                                         PaddingLeft(const std::string& s, int count, char padding_char);
    std::string                                                         PaddingRight(const std::string& s, int count, char padding_char);
    int                                                                 Split(const std::string& str, std::vector<std::string>& tokens, const std::string& delimiters);
    int                                                                 Tokenize(const std::string& str, std::vector<std::string>& tokens, const std::string& delimiters);
    void                                                                SetThreadPriorityToMaxLevel();
    void                                                                SetProcessPriorityToMaxLevel();
    #ifndef _WIN32
    uint64_t                                                            GetTickCount64();
    #endif

    template<typename T>    
    inline int                                                          FindIndexOf(int* next, T* src, int src_len, T* sub, int sub_len) {
        auto FindNextOf = [](int* next, T* sub, int sub_len) {
            int l = sub_len - 1;
            int i = 0;
            int j = -1;
            next[0] = -1;
            while (i < l) {
                if (j == -1 || sub[i] == sub[j]) {
                    j++;
                    i++;
                    if (sub[i] == sub[j]) {
                        next[i] = next[j];
                    }
                    else {
                        next[i] = j;
                    }
                }
                else {
                    j = next[j];
                }
            }
        };
        int i = 0;
        int j = 0;
        FindNextOf(next, sub, sub_len);
        while (i < src_len && j < sub_len) {
            if (j == -1 || src[i] == sub[j]) {
                i++;
                j++;
            }
            else {
                j = next[j];
            }
        }
        if (j >= sub_len) {
            return i - sub_len;
        }
        else {
            return -1;
        }
    }
    template<typename T>
    inline std::shared_ptr<T>                                           make_shared_alloc(int length) {
        static_assert(sizeof(T) > 0, "can't make pointer to incomplete type");

        // https://pkg.go.dev/github.com/google/agi/core/os/device
        // ARM64v8a: __ALIGN(8)
        // ARMv7a  : __ALIGN(4)
        // X86_64  : __ALIGN(8)
        // X64     : __ALIGN(4)
        if (length <= 0) {
            return NULL;
        }

        T* p = (T*)::malloc(length * sizeof(T));
        return std::shared_ptr<T>(p, ::free);
    }
    template<typename T, typename... A>
    inline std::shared_ptr<T>                                           make_shared_object(A&&... args) {
        return std::make_shared<T>(std::forward<A&&>(args)...);
    }
}