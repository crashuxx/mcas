#ifndef MCAS_LOGIN_H
#define MCAS_LOGIN_H

#include "common.h"

namespace mcas::protocol {

    const int MT_LOGIN_REQUEST = 0x00;
    const int MT_LOGIN_SUCCESS = 0x02;

    struct ptc_login_disconnect {
        std::string reason;
    };

    struct ptc_login_encryption_begin {
        std::string serverId;
        std::vector<char> publicKey;
        std::vector<char> verifyToken;
    };

    struct ptc_login_success {
        uuid_t uuid;
        std::string username;
        std::vector<property_t> properties;
    };

    struct ptc_login_compress {
        varint_t threshold;
    };

    struct ptc_login_login_plugin_request {
        varint_t messageId;
        std::string channel;
        std::vector<char> data;
    };

    struct pts_login_start {
        std::string username;
        uuid_t playerUUID;
    };

    struct pts_login_encryption_begin {
        std::vector<char> sharedSecret;
        std::vector<char> verifyToken;
    };

    struct pts_login_login_plugin_response {
        varint_t messageId;
        std::vector<char> data; //optional
    };

    struct pts_login_login_acknowledged {
    };

    ptrdiff_t serialize_properties(const std::vector<property_t> &data, std::vector<char> &buffer);

    ptrdiff_t serialize_pts_login_start(const pts_login_start &data, std::vector<char> &buffer);

    ptrdiff_t deserialize_pts_login_start(pts_login_start &data,
                                          const std::vector<char>::iterator &begin,
                                          const std::vector<char>::iterator &end);

    ptrdiff_t serialize_ptc_login_encryption_begin(const ptc_login_encryption_begin &data, std::vector<char> &buffer);

    ptrdiff_t deserialize_pts_login_encryption_begin(pts_login_encryption_begin &data,
                                                     const std::vector<char>::iterator &begin,
                                                     const std::vector<char>::iterator &end);

    ptrdiff_t serialize_ptc_login_success(const ptc_login_success &data, std::vector<char> &buffer);
}


#endif //MCAS_LOGIN_H
