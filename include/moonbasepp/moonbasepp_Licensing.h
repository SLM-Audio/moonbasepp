//
// Created by Syl Morrison on 17/09/2025.
//

#ifndef MOONBASEPP_LICENSING_H
#define MOONBASEPP_LICENSING_H
#include "moonbasepp_DeviceFingerprint.h"
#include <filesystem>
namespace moonbasepp {
    /**
     * Expected usage::
     * In ctor, check for existing -
     * User installs plugin for first time - gui has some sort of "activate" button
     * Clicking activate brings up a dialog that lets them either activate online, or generate an offline device token
     * In the case of online, call requestActivation - if ActivationResult::Success all is fine, in the case of timeout probably just show the user, and in the case of fail, report
     * In the case of offline activation, call generateOfflineDeviceToken - generates OfflineActivationRequest.dt in destDirectory:
     *     Support DnD (or just load) of resulting license-token.mb - once received, call checkForExisting again
     */
    class Licensing final {
    public:
        struct ValidationThresholds final {
            /// Within this time period, online validation won't even be attempted
            int allowedDaysWithoutValidation; // eg 2
            /// Within this time period, we do try to validate, but upon failure, don't report unlicensed until it's been exceeded
            int gracePeriod; // eg 30
        };

        struct Context final {
            /// The moonbase product id for this product, eg "my-plugin"
            std::string_view productId;
            /// eg https://your-company.api.moonbase.sh
            std::string_view apiEndpointBase;
            /// Path to the location you want your license to be stored at
            std::filesystem::path expectedLicenseLocation;
            ValidationThresholds validationThresholds;
        };

        enum class ActivationResult {
            Success,
            Timeout,
            Fail
        };

        struct LicenseStatus final {
            bool active;
            bool trial;
            bool offline;
            bool onlineValidationPending;
            bool offlineGracePeriodExceeded;
        };

        explicit Licensing(Context context);

        // [[ Background Thread ]]
        [[nodiscard]] auto checkForExisting() -> bool;
        /***
         * [[ Background Thread ]]
         * In-Browser activation flow - attempts to direct the user to their browser to activate their license,
         * and then polls the endpoint to receive the token once activation has been completed.
         * Make sure to call this on a background thread, as it invokes `std::this_thread::sleep_for()` during the retry loop
         * @param numRetries The amount of times to query the request endpoint after directing the user to their browser
         * @param secondsBetweenRetries The time in seconds between each retry
         * @return ActivationResult::Success if successful, ActivationResult::Timeout if numRetries was exceeded, and ActivationResult::Fail if activation flat out failed
         */
        [[nodiscard]] auto requestActivation(int numRetries, int secondsBetweenRetries) -> ActivationResult;

        [[nodiscard]] auto deactivate() -> bool;
        // [[ Main or Background Thread, doesn't matter ]]
        [[nodiscard]] auto generateOfflineDeviceToken(const std::filesystem::path& destDirectory) const -> bool;
        // [[ Background Thread ]]
        [[nodiscard]] auto receiveOfflineLicenseToken(const std::filesystem::path& licenseToken) -> bool;
        // [[ Any Thread ]]
        [[nodiscard]] auto getLicenseStatus() const -> LicenseStatus;

    private:
        // [[ Background Thread ]]
        auto check(const std::filesystem::path& toCheck) -> bool;
        Context m_context;
        DeviceFingerprint m_fingerprint;
        std::filesystem::path m_expectedLicenseFile;

        struct {
            std::atomic<bool> isLicenseActive{ false };
            std::atomic<bool> trial{ false };
            std::atomic<bool> offlineActivated{ false };
            std::atomic<bool> onlineValidationPending{ false };
            std::atomic<bool> offlineGracePeriodExceeded{ false };
        } m_licensingInfo;
        std::string m_activationUrl;
        std::string m_validationUrl;
        std::string m_deactivationUrl;
    };
} // namespace moonbasepp
#endif // MOONBASEPP_LICENSING_H
