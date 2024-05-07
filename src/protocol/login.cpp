#include <cassert>
#include <cstring>
#include "login.h"
#include "protocol.h"
#include "../leb128.h"

namespace mcas::protocol {

    std::vector<char> makeLoginSuccess(uint64_t uuidM, uint64_t uuidL, std::string &name) {

        auto buffer = std::vector<char>();

        leb128_encode(buffer, MT_LOGIN_SUCCESS);

        copy((char*)&uuidM, ((char*)(&uuidM)) + sizeof(int64_t), back_inserter(buffer));
        copy((char*)&uuidL, ((char*)(&uuidL)) + sizeof(int64_t), back_inserter(buffer));

        pt_write_string(buffer, name);

        leb128_encode(buffer, 1);
        std::string a = "textures";
        pt_write_string(buffer, a);
        a = "ewogICJ0aW1lc3RhbXAiIDogMTcxNTAyNDc2ODY0MiwKICAicHJvZmlsZUlkIiA6ICJlYmQ2N2JlMWQ2MTc0NjA0ODMwYmJiNDU1NzZlNmEwOSIsCiAgInByb2ZpbGVOYW1lIiA6ICJkcm9wc190bSIsCiAgInNpZ25hdHVyZVJlcXVpcmVkIiA6IHRydWUsCiAgInRleHR1cmVzIiA6IHsKICAgICJTS0lOIiA6IHsKICAgICAgInVybCIgOiAiaHR0cDovL3RleHR1cmVzLm1pbmVjcmFmdC5uZXQvdGV4dHVyZS85YjVlYTc5MzI4NzhkNGU4YTQ1NTgwOTBmNWQ4Yzc4MTRjNGFlMGMzOTViYmI5MGYyYmQzMTVkNjYzMDkyNGMyIiwKICAgICAgIm1ldGFkYXRhIiA6IHsKICAgICAgICAibW9kZWwiIDogInNsaW0iCiAgICAgIH0KICAgIH0KICB9Cn0=";
        pt_write_string(buffer, a);
        leb128_encode(buffer, 0);

        return buffer;
    }

    Login *decodeLogin(
            const std::vector<char>::iterator &begin,
            const std::vector<char>::iterator &end) {

        auto it = begin;
        auto *login = new Login;

        int32_t size = 0;
        ptrdiff_t bytes_read;

        bytes_read = pt_read_string(it, end, login->name);
        assert(bytes_read >= 0);
        it = next(it, bytes_read);

        memcpy(&login->uuidM, it.base(), 8);
        it = next(it, 8);
        memcpy(&login->uuidL, it.base(), 8);
        //copy(it, next(it, 7), &login->uuidM);
        //copy(next(it, 8), next(it, 15), &login->uuidL);

        return login;
    }

    EncryptionResponse *decodeEncryptionResponse(const std::vector<char>::iterator &begin, const std::vector<char>::iterator &end) {
        auto it = begin;
        ptrdiff_t bytes_read;
        auto *response = new EncryptionResponse;

        bytes_read = pt_read_vector(it, end, response->secret);
        assert(bytes_read >= 0);
        it = next(it, bytes_read);

        bytes_read = pt_read_vector(it, end, response->token);
        assert(bytes_read >= 0);

        return response;
    }

    std::vector<char> makeEncryptionRequest(std::string &serverId, std::vector<char> &publicKey, std::vector<char> &vt) {
        auto buffer = std::vector<char>();
        buffer.reserve(serverId.size()+publicKey.size()+vt.size()+8);

        leb128_encode(buffer, 1);

        pt_write_string(buffer, serverId);
        pt_write_bytes(buffer, publicKey);
        pt_write_bytes(buffer, vt);

        return buffer;
    }

}