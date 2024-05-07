#ifndef MCAS_PROTOCOL_HANDSHAKE_H
#define MCAS_PROTOCOL_HANDSHAKE_H

#include <cstdint>
#include <string>
#include <vector>


namespace protocol::handshake {

    const int MT_SWITCH_PROTOCOL = 0x00;

    struct SwitchProtocol {
        int32_t protocolVersion;
        std::string hostname;
        int16_t port;
        int32_t intent;
    };

    std::vector<char> makeSwitchProtocol(
            int32_t protocolVersion,
            const std::string &hostname,
            int32_t port,
            int8_t intent);

    SwitchProtocol *decodeSwitchProtocol(
            const std::vector<char>::iterator &begin,
            const std::vector<char>::iterator &end);

}

#endif // MCAS_PROTOCOL_HANDSHAKE_H