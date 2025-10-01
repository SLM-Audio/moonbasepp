//
// Created by sylmo on 28/09/2025.
//


#include <moonbasepp/moonbasepp_JWT.h>
#include <ranges>
#include <cpp-base64/base64.h>
#include <mbedtls/sha256.h>
#include <mbedtls/pk.h>
#include <sstream>

namespace moonbasepp::jwt {
    class scope_exit final {
    public:
        explicit scope_exit(const std::function<void(void)>& toInvoke) : m_action(toInvoke) {
        }

        ~scope_exit() noexcept {
            m_action();
        }

    private:
        std::function<void(void)> m_action;
    };

    static auto split(std::string_view source, std::string_view delimiter) -> std::vector<std::string> {
        std::vector<std::string> res;
        for (const auto word : std::views::split(source, delimiter)) {
            auto token{ std::string_view{ word.data(), word.size() } };
            res.emplace_back(token);
        }
        return res;
    }

    static auto hash(const std::string& source, unsigned char* dest) -> bool {
        mbedtls_sha256_context ctx;
        scope_exit se{ [&ctx]() -> void { mbedtls_sha256_free(&ctx); } };
        mbedtls_sha256_init(&ctx);
        if (mbedtls_sha256(reinterpret_cast<const unsigned char*>(source.c_str()), source.length(), dest, 0) != 0) {
            return false;
        }
        return true;
    }

    auto decode(std::string_view encoded) -> std::optional<JWT> {
        try {
            const auto tokens = split(encoded, ".");
            if (tokens.size() != 3) {
                return {};
            }
            JWT res{};
            const auto header_str = base64_decode(tokens[0]);
            const auto body_str = base64_decode(tokens[1]);
            res.signature = base64_decode(tokens[2]);
            res.header = nlohmann::json::parse(header_str);
            res.body = nlohmann::json::parse(body_str);
            std::stringstream toHashStream;
            toHashStream << tokens[0] << "." << tokens[1];
            if (const auto toHash = toHashStream.str(); !hash(toHash, res.hash)) {
                return {};
            }
            return res;

        } catch (...) {
            return {};
        }
    }

    auto verifySignature(const std::string& publicKey, const JWT& toVerify) -> bool {
        mbedtls_pk_context ctx;
        scope_exit se{ [&ctx]() -> void { mbedtls_pk_free(&ctx); } };
        mbedtls_pk_init(&ctx);
        if (mbedtls_pk_parse_public_key(&ctx, reinterpret_cast<const unsigned char*>(publicKey.data()), publicKey.length() + 1) != 0) {
            return false;
        }
        if (mbedtls_pk_verify(&ctx, mbedtls_md_type_t::MBEDTLS_MD_SHA256, toVerify.hash, sizeof(toVerify.hash), reinterpret_cast<const unsigned char*>(toVerify.signature.c_str()), toVerify.signature.length()) != 0) {
            return false;
        }
        return true;
    }

} // namespace moonbasepp::jwt
