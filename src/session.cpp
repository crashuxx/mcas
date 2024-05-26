#include <iostream>
#include "session.h"
#include "TcpConnection.h"
#include "protocol/protocol.h"
#include "protocol/handshake.h"
#include "protocol/login.h"
#include "encryption/RSAEncryption.h"
#include "leb128.h"
#include "hash.h"
#include "externalAuth.h"

namespace mcas {

    char rand_alnum() {
        char c;
        while (!std::isalnum(c = static_cast<char>(std::rand())));
        return c;
    }

    inline uint8_t hex2uint8(const char *hex) {
        uint8_t result = 0;
        for (const char *h = hex + 2; hex != h; ++hex) {
            result <<= 4;
            if (*hex >= '0' && *hex <= '9') result |= *hex - '0';
            else if (*hex >= 'a' && *hex <= 'f') result |= *hex - 'a' + 10;
            else if (*hex >= 'A' && *hex <= 'F') result |= *hex - 'A' + 10;
        }
        return result;
    }

    void login_handler(TcpConnection &connection, std::vector<char>::iterator &begin, std::vector<char>::iterator &end) {
        auto iterator = begin;

        int32_t messageId;
        auto bytes_read = protocol::pt_read_int32(iterator, end, messageId);
        assert(bytes_read > 0 && bytes_read <= 5);
        iterator = next(iterator, bytes_read);

        if (messageId == protocol::MT_LOGIN_REQUEST) {

            protocol::pts_login_start login;
            protocol::deserialize_pts_login_start(login, iterator, end);

            std::cout << "New login" << login.username << std::endl;

            protocol::ptc_login_encryption_begin encryptionBegin;
            encryptionBegin.serverId = "123456789012345";
            encryptionBegin.publicKey = connection.rsaEncryption().getPublicKey();
            generate_n(std::back_inserter(encryptionBegin.verifyToken), 4, std::rand);

            std::vector<char> message;
            protocol::serialize_ptc_login_encryption_begin(encryptionBegin, message);

            connection.send(message);

        } else if (messageId == 0x01) {

            protocol::pts_login_encryption_begin encryptionBegin;
            protocol::deserialize_pts_login_encryption_begin(encryptionBegin, iterator, end);

            std::vector<char> vt = {'v', 't', 'v', 't'};
            std::vector<char> decodedToken;
            std::vector<char> decodedSecret;

            connection.rsaEncryption().decrypt(decodedSecret, encryptionBegin.sharedSecret.data(), encryptionBegin.sharedSecret.size());
            connection.rsaEncryption().decrypt(decodedToken, encryptionBegin.verifyToken.data(), encryptionBegin.verifyToken.size());

            std::shared_ptr<encryption::AESEncryption> pEncryption(new encryption::AESEncryption(decodedSecret, decodedSecret));
            connection.aesEncryption(pEncryption);

            protocol::SignedSha1 hash;
            std::string serverId = "123456789012345";
            hash.update(serverId);
            hash.update(decodedSecret);
            hash.update(connection.rsaEncryption().getPublicKey());
            const std::string &string = hash.finalise();

            std::string username = "...";
            std::unique_ptr<mcsa::accountData_t> accData(mcsa::external_hasJoined(username, string));

            if (accData == nullptr) {
                return;
            }

            std::vector<char> out;
            protocol::ptc_login_success loginSuccess;
            loginSuccess.username = accData->name;
            auto uuid_ptr = (uint8_t *) loginSuccess.uuid;

            for (size_t i = 0, ptr_shift = 0; ptr_shift + 1 < accData->id.size() && i < sizeof(loginSuccess.uuid); i++, ptr_shift += 2) {
                uuid_ptr[i] = hex2uint8(accData->id.c_str() + ptr_shift);
            }

            //loginSuccess.properties = ;

            protocol::serialize_ptc_login_success(loginSuccess, out);

            std::cout << "id " << accData->id << std::endl;
            std::cout << "Hash " << string << std::endl;

            connection.send(out);
        }
    }

    void handshake_handler(TcpConnection &connection, std::vector<char>::iterator &begin, std::vector<char>::iterator &end) {
        auto iterator = begin;

        int32_t messageId;
        auto bytes_read = protocol::pt_read_int32(iterator, end, messageId);
        assert(bytes_read > 0 && bytes_read <= 5);
        iterator = next(iterator, bytes_read);

        if (messageId == protocol::MT_SWITCH_PROTOCOL) {
            std::unique_ptr<protocol::SwitchProtocol> switchProtocol(
                    protocol::decodeSwitchProtocol(iterator, end));

            std::cout << switchProtocol->hostname << std::endl;
            if (switchProtocol->intent == 2)
                connection.setMessageHandler(login_handler);
            else
                connection.closeAndUnregister();

        } else {
            //ignore others
            connection.closeAndUnregister();
        }
    }
}

//mcas::Session::Session(const std::weak_ptr<TcpConnection> &connection) : connection(connection) {}
