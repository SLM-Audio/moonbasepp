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

    static auto decodeToken(const std::string& content) -> std::optional<std::map<std::string, nlohmann::basic_json<>, std::less<>>> {
        try {
            const auto decoded = jwt::decode<jwt::traits::nlohmann_json>(content);
            return decoded.get_payload_json();
        } catch (...) {
            return {};
        }
    };

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

    auto Licensing::check(const std::filesystem::path& toCheck) -> bool {
        std::ifstream inStream{ toCheck, std::ios::in };
        std::string token{ std::istreambuf_iterator<char>(inStream), std::istreambuf_iterator<char>() };
        auto asJsonOpt = decodeToken(token);
        if (!asJsonOpt) {
            return false;
        }

        auto& asJson = *asJsonOpt;
        // populate the easy ones here...
        m_licensingInfo.offlineActivated = asJson.at("method").get<std::string>() == "Offline";
        m_licensingInfo.trial = asJson.at("trial").get<bool>();
        m_licensingInfo.onlineValidationPending.store(false);
        m_licensingInfo.offlineGracePeriodExceeded.store(false);

        const auto sig = asJson.at("sig").get<std::string>();
        if (!compareFingerprint(m_fingerprint, sig)) { // more than 2 of the device fingerprint idents have changed
            return false;
        }
        const auto productId = asJson.at("p:id").get<std::string>();
        if (productId != m_context.productId) { // license is for something other than your product..
            return false;
        }
        if (m_licensingInfo.offlineActivated) { // Can't revoke, so all good..
            return true;
        }
        const auto now = std::chrono::system_clock::now();
        if (m_licensingInfo.trial) { // this is a trial, so we need to check expiration
            const auto trialExpiration = asJson.at("exp").get<int>();
            const auto expTimePoint = std::chrono::system_clock::from_time_t(trialExpiration);
            if (expTimePoint < now) { // trial has expired...
                m_licensingInfo.isLicenseActive.store(false);
                return false;
            }
        }
        const auto lastValidatedAt = asJson.at("validated").get<int>();
        const auto lastValidatedSecondsSinceEpoch = std::chrono::system_clock::from_time_t(lastValidatedAt);
        const auto delta = std::chrono::duration_cast<std::chrono::days>(now - lastValidatedSecondsSinceEpoch);
        return [&]() -> bool {
            if (delta <= std::chrono::days{ m_context.validationThresholds.allowedDaysWithoutValidation }) {
                return true;
            }
            if (!validate(m_validationUrl, m_expectedLicenseFile, token)) {
                const auto withinGracePeriod = delta <= std::chrono::days{ m_context.validationThresholds.gracePeriod };
                m_licensingInfo.offlineActivated.store(false);
                m_licensingInfo.onlineValidationPending.store(true);
                m_licensingInfo.offlineGracePeriodExceeded.store(!withinGracePeriod);
                return withinGracePeriod;
            }
            return true;
        }();
    }

    auto Licensing::checkForExisting() -> bool {
        if (!std::filesystem::exists(m_expectedLicenseFile)) { // no license on disk
            m_licensingInfo.isLicenseActive.store(false);
            return false;
        }
        m_licensingInfo.isLicenseActive = check(m_expectedLicenseFile);
        return m_licensingInfo.isLicenseActive;
    }

    auto Licensing::requestActivation(int numRetries, int secondsBetweenRetries) -> Licensing::ActivationResult {
        try {

            m_licensingInfo.offlineActivated.store(false);
            m_licensingInfo.onlineValidationPending.store(false);
            m_licensingInfo.offlineGracePeriodExceeded.store(false);

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
                std::this_thread::sleep_for(std::chrono::seconds{ secondsBetweenRetries });
                ++attemptNumber;
            }
            if (!tokenResp) {
                m_licensingInfo.isLicenseActive.store(false);
                return ActivationResult::Timeout;
            }
            const auto token = tokenResp->text;
            const auto decodedOpt = decodeToken(token);
            if (!decodedOpt) {
                m_licensingInfo.isLicenseActive.store(false);
                return ActivationResult::Fail;
            }
            m_licensingInfo.isLicenseActive = true;
            m_licensingInfo.trial = decodedOpt->at("trial").get<bool>();
            std::ofstream outStream{ m_expectedLicenseFile, std::ios::out };
            outStream << token;
            outStream.flush();
            return ActivationResult::Success;
        } catch (...) {
            assert(false);
            m_licensingInfo.isLicenseActive.store(false);
            return ActivationResult::Fail;
        }
    }

    auto Licensing::generateOfflineDeviceToken(const std::filesystem::path& destDirectory) const -> bool {
        try {
            std::filesystem::path destFile = destDirectory / "OfflineActivationRequest.dt";
            nlohmann::json j;
            j["id"] = m_fingerprint.base64;
            j["name"] = m_fingerprint.deviceName;
            j["productId"] = m_context.productId;
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

    auto Licensing::receiveOfflineLicenseToken(const std::filesystem::path& licenseToken) -> bool {
        std::filesystem::copy(licenseToken, m_expectedLicenseFile);
        return check(m_expectedLicenseFile);
    }

    auto Licensing::getLicenseInfo() const -> LicenseInfo {
        return {
            .active = m_licensingInfo.isLicenseActive.load(),
            .trial = m_licensingInfo.trial.load(),
            .offline = m_licensingInfo.offlineActivated.load(),
            .onlineValidationPending = m_licensingInfo.onlineValidationPending.load(),
            .offlineGracePeriodExceeded = m_licensingInfo.offlineGracePeriodExceeded.load()
        };
    }


} // namespace moonbasepp