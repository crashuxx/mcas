#ifndef MCAS_EXTERNALAUTH_H
#define MCAS_EXTERNALAUTH_H


#include <string>
#include <vector>
#include "protocol/types.h"

namespace mcsa {

    struct verificationData_t {
        std::string username;
        char hash[24];
    };

    struct accountData_t {
        std::string id;
        std::string name;
        std::vector<mcas::protocol::property_t> properties;
    };

    accountData_t *external_hasJoined(const std::string &username, const std::string &hash);

}

#endif //MCAS_EXTERNALAUTH_H
