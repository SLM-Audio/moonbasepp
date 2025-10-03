//
// Created by Syl Morrison on 17/09/2025.
//
#include <moonbasepp/moonbasepp_DeviceFingerprint.h>
#include <cpp-base64/base64.h>
#if __APPLE__
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netdb.h>
#include <net/if_dl.h>
#include <ifaddrs.h>
#include <net/if_types.h>
#include <mach-o/arch.h>
#else if defined(_MSC_VER)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <iphlpapi.h>
#endif
#include <iostream>
#include <cassert>
#include <optional>

namespace moonbasepp {

#if __APPLE__
    /// NB: Stolen pretty much wholesale from this stack overflow post:: https://stackoverflow.com/questions/16858782/how-to-obtain-almost-unique-system-identifier-in-a-cross-platform-way
    static auto getMachineName() -> std::string {
        static struct utsname u;
        if (uname(&u) < 0) {
            return "unknown";
        }
        return u.nodename;
    }

    auto hashMacAddress(std::string_view mac) -> std::uint8_t {
        std::uint8_t hash = 0;

        for (unsigned int i = 0; i < 6; i++) {
            hash += (mac[i] << ((i & 1) * 8));
        }
        return hash;
    }

    auto getMacAddress() -> std::uint16_t {
        std::uint8_t mac1{}, mac2{};
        ifaddrs* ifaphead{ nullptr };
        if (getifaddrs(&ifaphead) != 0) {
            return 0;
        }
        auto foundMac1{ false };
        for (ifaddrs* ifap = ifaphead; ifap; ifap = ifap->ifa_next) {
            if (auto* sdl = reinterpret_cast<sockaddr_dl*>(ifap->ifa_addr); sdl && sdl->sdl_family == AF_LINK && sdl->sdl_type == IFT_ETHER) {
                if (!foundMac1) {
                    foundMac1 = true;
                    mac1 = hashMacAddress(LLADDR(sdl));
                } else {
                    mac2 = hashMacAddress(LLADDR(sdl));
                    break;
                }
            }
        }
        freeifaddrs(ifaphead);
        if (mac1 > mac2) {
            std::swap(mac1, mac2);
        }
        std::uint16_t res{ 0x0 };
        res |= (mac1 << 8);
        res |= mac2;
        return res;
    }


    auto getVolumeHash() -> std::uint8_t {
        auto sysname = getMachineName();
        std::uint8_t hash{};
        for (auto i = 0; sysname[i]; ++i) {
            hash += (sysname[i] << ((i & 1) * 8));
        }
        return hash;
    }

    auto getCPUHash() -> std::uint8_t {
        const NXArchInfo* info = NXGetLocalArchInfo();
        std::uint8_t val = 0;
        val += static_cast<std::uint8_t>(info->cputype);
        val += static_cast<std::uint8_t>(info->cpusubtype);
        return val;
    }

    auto getFingerprint() -> DeviceFingerprint {
        const auto machineName = getMachineName();
        const auto cpuHash = getCPUHash();
        const auto volumeHash = getVolumeHash();
        const auto macAddrHash = getMacAddress();
        const auto fingerprint = [&]() -> std::uint32_t {
            std::uint32_t res{ 0x0 };
            res |= (cpuHash << 24);
            res |= (volumeHash << 16);
            res |= macAddrHash;
            return res;
        }();
        auto asbase64 = base64_encode(std::to_string(fingerprint));
        return {
            .deviceName = machineName,
            .cpuHash = cpuHash,
            .volumeHash = volumeHash,
            .macAddrHash = macAddrHash,
            .fingerprint = fingerprint,
            .base64 = asbase64
        };
    }

#elif defined(_MSC_VER)

    static auto getMachineName() -> std::string {
        static char computerName[1024];
        DWORD size{ 1024 };
        GetComputerName(computerName, &size);
        return std::string{ computerName, size };
    }

    static auto hashMacAddress() -> std::uint16_t {
        std::uint16_t mac1{}, mac2{};
        const auto hash = [](PIP_ADAPTER_INFO info) -> std::uint16_t {
            std::uint16_t res{ 0 };
            for (auto i = 0UL; i < info->AddressLength; ++i) {
                res += (info->Address[i] << ((i & 1) * 8));
            }
            return res;
        };
        // Because on windows a mac addr seems to be a uint16_t, rather than combining the two via shifts like on macOS, we're gonna bitwise& them as is
        IP_ADAPTER_INFO adapterInfo[32];
        DWORD dwBufLen = sizeof(adapterInfo);
        DWORD status = GetAdaptersInfo(adapterInfo, &dwBufLen);
        if (status != ERROR_SUCCESS) {
            assert(false);
            return {};
        }
        PIP_ADAPTER_INFO pAdapterInfo = adapterInfo;
        mac1 = hash(pAdapterInfo);
        if (pAdapterInfo->Next) {
            mac2 = hash(pAdapterInfo->Next);
        }
        const std::uint16_t combined = mac1 & mac2;
        return combined;
    }

    static auto getVolumeHash() -> std::uint8_t {
        // Also awkward, this gives us a uint16_t - we need u8 for macOS parity - soooo uhhhh what about just taking the bottom 8 ? <imp emoji goes here>
        DWORD serialNum{ 0 };
        GetVolumeInformation("c:\\", NULL, 0, &serialNum, NULL, NULL, NULL, 0);
        const auto hash = static_cast<std::uint8_t>((serialNum + (serialNum >> 8)) & 0xFF);
        return hash;
    }

    static auto getCPUHash() -> std::uint8_t {
        int cpuInfo[4] = { 0, 0, 0, 0 };
        __cpuid(cpuInfo, 0);
        std::uint16_t hash{ 0 };
        auto* ptr = reinterpret_cast<std::uint16_t*>(&cpuInfo[0]);
        for (auto i = 0; i < 8; ++i) {
            hash += ptr[i];
        }
        return hash & 0xFF;
    }

    auto getFingerprint() -> DeviceFingerprint {
        const auto machineName = getMachineName();
        const auto cpuHash = getCPUHash();
        const auto volumeHash = getVolumeHash();
        const auto macAddrHash = hashMacAddress();
        const auto fingerprint = [&]() -> std::uint32_t {
            std::uint32_t res{ 0x0 };
            res |= (cpuHash << 24);
            res |= (volumeHash << 16);
            res |= macAddrHash;
            return res;
        }();
        auto asbase64 = base64_encode(std::to_string(fingerprint));
        return {
            .deviceName = machineName,
            .cpuHash = cpuHash,
            .volumeHash = volumeHash,
            .macAddrHash = macAddrHash,
            .fingerprint = fingerprint,
            .base64 = asbase64
        };
    }


#else
    static_assert(false); // TODO: SUPPORT OTHER OPERATING SYSTEMS
#endif
    auto compareFingerprint(const DeviceFingerprint& cachedFingerprint, std::string base64ToCompare) -> bool {
        try {
            std::uint32_t decoded = std::stoi(base64_decode(base64ToCompare));
            const std::uint8_t decodedCpuHash = (decoded >> 24) & 0xFF;
            const std::uint8_t decodedVolumeHash = (decoded >> 16) & 0xFF;
            const std::uint16_t decodedMacAddrHash = decoded & 0xFFFF;
            // Say == if two of the 3 fields still match...
            const auto numMatches = [&]() -> int {
                int n{ 0 };
                if (decodedCpuHash == cachedFingerprint.cpuHash) {
                    ++n;
                }
                if (decodedVolumeHash == cachedFingerprint.volumeHash) {
                    ++n;
                }
                if (decodedMacAddrHash == cachedFingerprint.macAddrHash) {
                    ++n;
                }
                return n;
            }();
            return numMatches >= 2;
        } catch (...) {
            assert(false);
            return false;
        }
    }
} // namespace moonbasepp