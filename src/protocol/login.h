#ifndef MCAS_LOGIN_H
#define MCAS_LOGIN_H

#include "common.h"

namespace protocol::login {

    const int MT_LOGIN_REQUEST = 0x00;
    const int MT_LOGIN_SUCCESS = 0x02;

    struct Login {
        std::string name;
        uint64_t uuidM;
        uint64_t uuidL;
    };

    struct EncryptionResponse {
        //int32_t secretLength;
        std::vector<char> secret;
        //int32_t tokenLength;
        std::vector<char> token;
    };

    std::vector<char> makeLoginSuccess(uint64_t uuidM, uint64_t uuidL, std::string& name);

    Login *decodeLogin(const std::vector<char>::iterator &begin,const std::vector<char>::iterator &end);

    EncryptionResponse* decodeEncryptionResponse(const std::vector<char>::iterator &begin,const std::vector<char>::iterator &end);

    std::vector<char> makeEncryptionRequest(std::string &serverId, std::vector<char> &publicKey, std::vector<char> &vt);

}


#endif //MCAS_LOGIN_H
