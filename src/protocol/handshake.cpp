#include "handshake.h"
#include "protocol.h"
#include "../leb128.h"

#include <cassert>

namespace mcas::protocol {

    std::vector<char> makeSwitchProtocol(
            int32_t protocolVersion,
            const std::string &hostname,
            int32_t port,
            int8_t intent) {

        auto buffer = std::vector<char>();
        unsigned long hostnameLength = hostname.length();
        buffer.reserve(hostnameLength + 8);

        buffer.push_back(MT_SWITCH_PROTOCOL);

        leb128_encode(buffer, protocolVersion);
        leb128_encode(buffer, hostname.size());
        copy(hostname.begin(), hostname.end(), back_inserter(buffer));
        //buffer.push_back(0x00);
        leb128_encode(buffer, port);
        leb128_encode(buffer, intent);
        buffer[0] = buffer.size() - 1;

        return buffer;
    }

    SwitchProtocol *decodeSwitchProtocol(
            const std::vector<char>::iterator &begin,
            const std::vector<char>::iterator &end) {

        auto it = begin;
        auto *switchProtocol = new SwitchProtocol();

        ptrdiff_t bytes_read = pt_read_int32(it, end, switchProtocol->protocolVersion);
        assert(bytes_read >= 0);
        it = next(it, bytes_read);

        bytes_read = pt_read_string(it, end, switchProtocol->hostname);
        assert(bytes_read >= 0);
        it = next(it, bytes_read);

        bytes_read = pt_read_int16(it, end, switchProtocol->port);
        assert(bytes_read >= 0);
        it = next(it, bytes_read);

        bytes_read = pt_read_int32(it, end, switchProtocol->intent);
        assert(bytes_read >= 0);

        assert(next(it) == end);

        return switchProtocol;
    }
}
