//
// Created by Syl Morrison on 17/09/2025.
//
#include <moonbasepp/moonbasepp_Licensing.h>
#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <jwt-cpp/traits/nlohmann-json/traits.h>
#include <jwt-cpp/jwt.h>
#include <cpp-base64/base64.h>
#include <cpr/cpr.h>

#include <cassert>
#include <sstream>
#include <iostream>
#include <utility>

namespace moonbasepp {

    static auto pollRequestUrl(std::string_view url) -> std::optional<cpr::Response> {
        cpr::Url endpoint{ url };
        auto resp = cpr::Get(endpoint);
        const auto statusCode = resp.status_code;
        const auto isResponseValid = [statusCode]() -> bool {
            if (statusCode == 0 || statusCode == 204 || statusCode >= 400) {
                return false;
            }
            return true;
        }();
        if (!isResponseValid) {
            return {};
        }
        return resp;
    }

    Licensing::Licensing(Context context) : m_context(std::move(context)),
                                            m_activationUrl(fmt::format("{}/api/client/activations/{}/request", m_context.apiEndpointBase, m_context.productId)),
                                            m_validationUrl(fmt::format("{}/api/client/licenses/{}/validate", m_context.apiEndpointBase, m_context.productId)) {
        if (!std::filesystem::exists(m_context.expectedLicenseLocation)) {
            std::filesystem::create_directory(m_context.expectedLicenseLocation);
        }
        m_expectedLicenseFile = m_context.expectedLicenseLocation / "license-token.mb";
        m_fingerprint = getFingerprint();
    }

    static auto validate(std::string_view url, const std::filesystem::path& licenseFile, std::string_view token) -> bool {
        const cpr::Url endpoint{ url };
        const cpr::Header header{ { "Content-Type", "text/plain" } };
        const cpr::Body body{ token };
        const auto resp = cpr::Post(endpoint, header, body);
        if (resp.status_code == 0 || resp.status_code >= 400) {
            return false;
        }
        std::ofstream outStream{ licenseFile, std::ios::out };
        outStream << resp.text;
        outStream.flush();
        return true;
    }

    auto Licensing::check(const std::filesystem::path& toCheck) const -> bool {
        std::ifstream inStream{ toCheck, std::ios::in };
        std::string token{ std::istreambuf_iterator<char>(inStream), std::istreambuf_iterator<char>() };
        const auto decoded = jwt::decode<jwt::traits::nlohmann_json>(token);
        auto asJson = decoded.get_payload_json();
        const auto sig = asJson["sig"].get<std::string>();
        if (!compareFingerprint(m_fingerprint, sig)) { // more than 2 of the device fingerprint idents have changed
            return false;
        }
        const auto productId = asJson["p:id"].get<std::string>();
        if (productId != "tibia") { // license is for something other than tibia..
            return false;
        }
        const auto wasOnlineActivated = asJson["method"].get<std::string>() == "Online";
        if (!wasOnlineActivated) { // Can't revoke, so all good..
            return true;
        }
        const auto now = std::chrono::system_clock::now();
        if (asJson["trial"].get<bool>()) { // this is a trial, so we need to check expiration
            const auto trialExpiration = asJson["exp"].get<int>();
            const auto expTimePoint = std::chrono::system_clock::from_time_t(trialExpiration);
            if (expTimePoint < now) { // trial has expired...
                return false;
            }
        }
        const auto lastValidatedAt = asJson["validated"].get<int>();
        const auto lastValidatedSecondsSinceEpoch = std::chrono::system_clock::from_time_t(lastValidatedAt);
        const auto delta = std::chrono::duration_cast<std::chrono::days>(now - lastValidatedSecondsSinceEpoch);
        return [&]() -> bool {
            if (delta <= std::chrono::days{ m_context.validationThresholds.allowedDaysWithoutValidation }) {
                return true;
            }
            if (!validate(m_validationUrl, m_expectedLicenseFile, token)) {
                return delta <= std::chrono::days{ m_context.validationThresholds.gracePeriod };
            }
            return true;
        }();
    }

    auto Licensing::checkForExisting() -> bool {
        if (!std::filesystem::exists(m_expectedLicenseFile)) { // no license on disk
            m_isLicenseActive = false;
            return false;
        }
        m_isLicenseActive = check(m_expectedLicenseFile);
        return m_isLicenseActive;
    }

    auto Licensing::requestActivation(int numRetries, int secondsBetweenRetries) -> Licensing::ActivationResult {
        try {
            cpr::Url endpoint{ m_activationUrl };
            cpr::Header header{
                { "Content-Type", "application/json" }
            };
            const auto payload = [this]() -> std::string {
                const auto deviceName = m_fingerprint.deviceName;
                const auto deviceId = m_fingerprint.base64;
                nlohmann::json j;
                j["deviceName"] = deviceName;
                j["deviceSignature"] = deviceId;
                std::stringstream stream;
                stream << j;
                return stream.str();
            }();
            cpr::Body body{ payload };
            const auto response = cpr::Post(std::move(endpoint), std::move(header), std::move(body));
            if (response.status_code == 0 || response.status_code >= 400) {
                assert(false);
                return ActivationResult::Fail;
            }
            nlohmann::json j = nlohmann::json::parse(response.text);
            const auto requestAddr = j["request"].get<std::string>();
            const auto browserAddr = j["browser"].get<std::string>();
            const auto terminalCommand = fmt::format("open {}", browserAddr);
            system(terminalCommand.c_str());
            std::optional<cpr::Response> tokenResp;
            const auto numTries = numRetries / secondsBetweenRetries;
            auto attemptNumber{ 0 };
            while (!tokenResp && attemptNumber < numTries) {
                tokenResp = pollRequestUrl(requestAddr);
                std::this_thread::sleep_for(std::chrono::seconds{ 5 });
                ++attemptNumber;
            }
            if (!tokenResp) {
                return ActivationResult::Timeout;
            }
            const auto token = tokenResp->text;
            m_isLicenseActive.store(true);
            std::ofstream outStream{ m_expectedLicenseFile, std::ios::out };
            outStream << token;
            outStream.flush();
            return ActivationResult::Success;
        } catch (...) {
            assert(false);
            return ActivationResult::Fail;
        }
    }

    auto Licensing::generateOfflineDeviceToken(const std::filesystem::path& destDirectory) const -> bool {
        try {
            std::filesystem::path destFile = destDirectory / "OfflineActivationRequest.dt";
            nlohmann::json j;
            j["id"] = m_fingerprint.base64;
            j["name"] = m_fingerprint.deviceName;
            j["productId"] = "tibia";
            j["format"] = "JWT";
            std::stringstream stream;
            stream << j;
            const auto asBase64 = base64_encode(stream.str());
            std::ofstream outStream{ destFile, std::ios::out };
            outStream << asBase64;
            outStream.flush();
            return true;
        } catch (...) {
            return false;
        }
    }

    auto Licensing::receiveOfflineLicenseToken(const std::filesystem::path& licenseToken) const -> bool {
        std::filesystem::copy(licenseToken, m_expectedLicenseFile);
        return check(m_expectedLicenseFile);
    }

    auto Licensing::getIsLicenseActive() const -> bool {
        return m_isLicenseActive.load();
    }


} // namespace moonbasepp