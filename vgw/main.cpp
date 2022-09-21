#include "gw.h"
#include "ethernet.h"
#ifndef _WIN32
#include <signal.h>
#include <boost/stacktrace.hpp>
#endif

#ifndef VGW_VERSION
#define VGW_VERSION ("1.0.0")
#endif

static std::string 
EXEF() {
    #ifdef _WIN32
    char exe[8096];
    GetModuleFileNameA(NULL, exe, sizeof(exe));
    return exe;
    #else
    char sz[260 + 1];
    int dw = readlink("/proc/self/exe", sz, 260);
    sz[dw] = '\x0';
    return dw <= 0 ? "" : std::string(sz, dw);
    #endif
}

static std::string 
CWDP() {
    #ifdef _WIN32
    char cwd[8096];
    GetCurrentDirectoryA(sizeof(cwd), cwd);
    return cwd;
    #else
    char sz[260 + 1];
    return getcwd(sz, 260);
    #endif
}

static std::string
EXEN() {
    std::string exe = EXEF();
    if (exe.empty()) {
        return "";
    }
    #ifdef _WIN32
    size_t sz = exe.find_last_of('\\');
    #else
    size_t sz = exe.find_last_of('/');
    #endif
    if (sz == std::string::npos) {
        return exe;
    }
    return exe.substr(sz + 1);
}

static struct vgw::eth_addr
MACX(int argc, const char* argv[]) {
    std::string mac = vgw::GetCommandArgument("--mac", argc, argv);
    do {
        if (mac.empty()) {
            break;
        }
        else {
            mac = vgw::ToLower(mac);
        }
        int addr[6];
        int count = sscanf(mac.data(), "%02x:%02x:%02x:%02x:%02x:%02x", 
            &addr[0],
            &addr[1],
            &addr[2],
            &addr[3],
            &addr[4],
            &addr[5]);
        if (count == 6) {
            if (addr[0] == 0xff && addr[1] == 0xff && addr[2] == 0xff && addr[3] == 0xff && addr[4] == 0xff && addr[5] == 0xff) {
                break;
            }
            if (addr[0] == 0x00 && addr[1] == 0x00 && addr[2] == 0x00 && addr[3] == 0x00 && addr[4] == 0x00 && addr[5] == 0x00) {
                break;
            }
            return { (uint8_t)addr[0], (uint8_t)addr[1], (uint8_t)addr[2], (uint8_t)addr[3], (uint8_t)addr[4], (uint8_t)addr[5] };
        }
    } while (0);
    return { 0x30, 0xfc, 0x68, 0x88, 0xb4, 0xa9 };
}

int main(int argc, const char* argv[]) {
    #ifdef _WIN32
    SetConsoleTitle(TEXT("PPP PRIVATE NETWORK LAN GATEWAY"));
    SetConsoleCtrlHandler([](DWORD CtrlType) {
        vgw::ethernet_release();
        return TRUE;
    }, TRUE);
    #else
    signal(SIGHUP,  SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    #if (_DEBUG || DEBUG)
    static auto SIG_EXT = [](int signo) {
        std::stringstream stacktrace_;
        stacktrace_ << boost::stacktrace::stacktrace();
        fprintf(stdout, "signo %d\r\n%s\r\n", signo, stacktrace_.str().data());
        kill(getpid(), SIGKILL);
        _exit(127);
    };
    signal(SIGILL,  SIG_EXT);
    signal(SIGTRAP, SIG_EXT);
    signal(SIGFPE,  SIG_EXT);
    signal(SIGSEGV, SIG_EXT);
    signal(SIGABRT, SIG_EXT);
    #endif
    #endif

    vgw::SetProcessPriorityToMaxLevel();
    vgw::SetThreadPriorityToMaxLevel();

    struct vgw::eth_addr mac = MACX(argc, argv);
    uint32_t ip = inet_addr(vgw::GetCommandArgument("--ip", argc, argv).data());
    uint32_t ngw = inet_addr(vgw::GetCommandArgument("--ngw", argc, argv).data());
    uint32_t mask = inet_addr(vgw::GetCommandArgument("--mask", argc, argv).data());
    #ifndef _WIN32
    bool lwip = vgw::GetCommandArgument("--lwip", argc, argv, true);
    int snat = atoi(vgw::GetCommandArgument("--snat", argc, argv).data());
    int ncpu = std::max<int>(1, atoi(vgw::GetCommandArgument("--ncpu", argc, argv).data()));
    if (snat != 0) {
        vgw::ethernet_loopback(mac, ip, ngw, mask, lwip, snat, ncpu);
        kill(getpid(), SIGKILL);
        return 0;
    }
    #endif
    if (ip == INADDR_ANY || ip == INADDR_NONE || ngw == INADDR_ANY || ngw == INADDR_NONE || mask == INADDR_ANY) {
        std::string messages = "Copyright (C) 2022 SupersocksR ORG. All rights reserved.\r\n";
        messages += "VGW(X) %s Version\r\n\r\n";
        messages += "Cwd:\r\n    " + CWDP() + "\r\n";
        messages += "Usage:\r\n";
        messages += "    1. .%s%s --ip=192.168.0.40 --ngw=192.168.0.1 --mask=255.255.255.0 \r\n";
        messages += "    2. .%s%s --ip=192.168.0.40 --ngw=192.168.0.1 --mask=255.255.255.0 --mac=30:fc:68:88:b4:a9 \r\n";
        #ifndef _WIN32
        messages += "    3. .%s%s --ip=192.168.0.40 --ngw=192.168.0.1 --mask=255.255.255.0 --mac=30:fc:68:88:b4:a9 --lwip=[yes|no] \r\n";
        messages += "    4. .%s%s --ip=192.168.0.40 --ngw=192.168.0.1 --mask=255.255.255.0 --mac=30:fc:68:88:b4:a9 --lwip=[yes|no] --ncpu=1 \r\n";
        #endif
        messages += "Contact us:\r\n";
        messages += "    https://t.me/supersocksr_group \r\n";
        std::string exen = EXEN();
        #ifdef _WIN32
        fprintf(stdout, messages.data(), VGW_VERSION, "\\", exen.data(), "\\", exen.data());
        system("pause");
        #else
        fprintf(stdout, messages.data(), VGW_VERSION, "/", exen.data(), "/", exen.data(), "/", exen.data(), "/", exen.data());
        #endif
        return -1;
    }

    fprintf(stdout, "%s\r\n", "Application started. Press Ctrl+C to shut down.");
    #ifdef _WIN32
    if (!vgw::ethernet_loopback(mac, ip, ngw, mask)) {
    #else
    if (!vgw::ethernet_loopback(mac, ip, ngw, mask, lwip, 0, ncpu)) {
    #endif
        #ifdef _WIN32
        fprintf(stdout, "%s\r\n", "Please install Npcap[https://npcap.com/#download] or WinPcap[https://www.winpcap.org/install/] on your Windows. If you have installed it correctly, please check whether the anti-virus software blocks it.");
        system("pause");
        #else
        fprintf(stdout, "%s\r\n", "Ethernet network adapter device cannot be attached in bypass mode. The possible cause is that the network adapter cannot be found or the promiscuous mode setting fails.");
        #endif
    }
    #ifdef _WIN32
    TerminateProcess(GetCurrentProcess(), 0);
    #else
    kill(getpid(), SIGKILL);
    #endif
    return 0;
}