//
// Created by sylmo on 28/09/2025.
//

#ifndef MOONBASEPP_JWT_H
#define MOONBASEPP_JWT_H

#include "nlohmann/json.hpp"
#include <optional>


#include <string_view>
namespace moonbasepp::jwt {

    struct JWT final {
        nlohmann::json header;
        nlohmann::json body;
        std::string signature;
        unsigned char hash[32];
    };

    auto decode(std::string_view encoded) -> std::optional<JWT>;
    auto verifySignature(const std::string& publicKey, const JWT& toVerify) -> bool;

} // namespace moonbasepp::jwt
#endif // MOONBASEPP_JWT_H
