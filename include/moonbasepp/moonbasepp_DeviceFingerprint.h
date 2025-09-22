//
// Created by Syl Morrison on 17/09/2025.
//

#ifndef MOONBASEPP_DEVICEFINGERPRINT_H
#define MOONBASEPP_DEVICEFINGERPRINT_H

#include <cstdint>
#include <string>

namespace moonbasepp {
    struct DeviceFingerprint final {
        std::string deviceName;
        std::uint8_t cpuHash;
        std::uint8_t volumeHash;
        std::uint16_t macAddrHash;
        std::uint32_t fingerprint;
        std::string base64;
    };
    auto getFingerprint() -> DeviceFingerprint;
    auto compareFingerprint(const DeviceFingerprint& cachedFingerprint, std::string base64ToCompare) -> bool;
} // namespace moonbasepp
#endif // MOONBASEPP_DEVICEFINGERPRINT_H
