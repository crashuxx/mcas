#include <iostream>
#include "session.h"
#include "TcpConnection.h"
#include "protocol/protocol.h"
#include "protocol/handshake.h"
#include "protocol/login.h"
#include "encryption/RSAEncryption.h"
#include "leb128.h"
#include "hash.h"

namespace mcas {

    char rand_alnum() {
        char c;
        while (!std::isalnum(c = static_cast<char>(std::rand())));
        return c;
    }


    void login_handler(TcpConnection &connection, std::vector<char>::iterator &begin, std::vector<char>::iterator &end) {
        auto iterator = begin;

        int32_t messageId;
        auto bytes_read = protocol::pt_read_int32_t(iterator, end, &messageId);
        assert(bytes_read > 0 && bytes_read <= 5);
        iterator = next(iterator, bytes_read);

        if (messageId == protocol::MT_LOGIN_REQUEST) {

            std::unique_ptr<protocol::Login> login(protocol::decodeLogin(iterator, end));

            std::cout << "New login" << login->name << std::endl;

            std::string serverId = "123456789012345";
/*            serverId.reserve(16);
            generate_n(std::back_inserter(serverId), 16, rand_alnum);*/

            std::vector<char> vt;
            vt.reserve(4);
            generate_n(std::back_inserter(vt), 4, std::rand);

            const std::vector<char> &request = protocol::makeEncryptionRequest(serverId, connection.rsaEncryption().getPublicKey(), vt);

            connection.send(request);

        } else if (messageId == 0x01) {

            protocol::EncryptionResponse *response = protocol::decodeEncryptionResponse(iterator, end);

            std::vector<char> vt = {'v', 't', 'v', 't'};
            std::vector<char> decodedToken;
            std::vector<char> decodedSecret;

            connection.rsaEncryption().decrypt(decodedSecret, response->secret.data(), response->secret.size());
            connection.rsaEncryption().decrypt(decodedToken, response->token.data(), response->token.size());

            std::shared_ptr<encryption::AESEncryption> pEncryption(new encryption::AESEncryption(decodedSecret, decodedSecret));
            connection.aesEncryption(pEncryption);

            std::string login;
            const std::vector<char> &success = protocol::makeLoginSuccess(0,
                                                                                 0x0,
                                                                                 login);

            protocol::SignedSha1 hash;

            std::string serverId = "123456789012345";
            hash.update(serverId);
            hash.update(decodedSecret);
            hash.update(connection.rsaEncryption().getPublicKey());
            const std::string &string = hash.finalise();
            std::cout << "Hash " << string << std::endl;

            connection.send(success);
        }
    }

    void handshake_handler(TcpConnection &connection, std::vector<char>::iterator &begin, std::vector<char>::iterator &end) {
        auto iterator = begin;

        int32_t messageId;
        auto bytes_read = protocol::pt_read_int32_t(iterator, end, &messageId);
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
