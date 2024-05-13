#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include "protocol.h"

#include "../leb128.h"

namespace mcas::protocol {

    ptrdiff_t pt_read_int16(const std::vector<char>::iterator &begin,
                            const std::vector<char>::iterator &end,
                            int16_t &value) {
        if (next(begin, 2) > end) {
            return 0;
        }
        value = *(reinterpret_cast<int16_t *>(begin.base()));
        return sizeof(int16_t);
    }

    ptrdiff_t pt_read_int32(const std::vector<char>::iterator &begin,
                            const std::vector<char>::iterator &end,
                            int32_t &value) {
        return leb128_decode_int32(begin, end, value);
    }

    ptrdiff_t pt_read_varint(const std::vector<char>::iterator &begin,
                             const std::vector<char>::iterator &end,
                             varint_t &value) {
        return leb128_decode_int32(begin, end, value);
    }

    ptrdiff_t pt_read_string(const std::vector<char>::iterator &begin,
                             const std::vector<char>::iterator &end,
                             std::string &value) {

        int32_t stringSize;
        ptrdiff_t readed;

        readed = leb128_decode_int32(begin, end, stringSize);
        if (readed <= 0) return readed;

        auto it = next(begin, readed);

        if (std::distance(it, end) < stringSize || stringSize > 32767) return -1;

        value.resize(stringSize + 1);
        value.assign(it.base(), stringSize);

        return readed + stringSize;
    }

    ptrdiff_t pt_read_bytes(const std::vector<char>::iterator &begin,
                            const std::vector<char>::iterator &end,
                            std::vector<char> &value) {

        int32_t size;
        ptrdiff_t readed;

        readed = leb128_decode_int32(begin, end, size);
        if (readed <= 0) {
            return readed;
        }

        auto it = next(begin, readed);

        if (std::distance(it, end) < size || size > 32767) return -1;

        value.resize(size);
        memcpy(value.data(), it.base(), size);

        return readed + size;
    }

    ptrdiff_t pt_write_string(std::vector<char> &buffer, const std::string &value) {

        ptrdiff_t size = leb128_encode(buffer, value.size());
        size += std::distance(value.begin(), value.end());
        copy(value.begin(), value.end(), back_inserter(buffer));

        return size;
    }

    ptrdiff_t pt_write_bytes(std::vector<char> &buffer, const std::vector<char> &value) {

        leb128_encode(buffer, value.size());
        copy(value.begin(), value.end(), back_inserter(buffer));

        return 1;
    }

    ptrdiff_t pt_write_varint(std::vector<char> &buffer, const int32_t &value) {
        return leb128_encode(buffer, value);
    }

    ptrdiff_t pt_write_varint(std::vector<char> &buffer, const size_t &value) {
        return leb128_encode(buffer, value);
    }

    ptrdiff_t pt_write_int64(std::vector<char> &buffer, const int64_t &value) {
        size_t size = sizeof(value);
        buffer.insert(buffer.end(), reinterpret_cast<const char *>(&value), reinterpret_cast<const char *>(&value) + size);
        return size;
    }

    ptrdiff_t pt_write_int32(std::vector<char> &buffer, const int32_t &value) {
        size_t size = sizeof(value);
        buffer.insert(buffer.end(), reinterpret_cast<const char *>(&value), reinterpret_cast<const char *>(&value) + size);
        return size;
    }

    ptrdiff_t pt_write_int16(std::vector<char> &buffer, const int16_t &value) {
        size_t size = sizeof(value);
        buffer.insert(buffer.end(), reinterpret_cast<const char *>(&value), reinterpret_cast<const char *>(&value) + size);
        return size;
    }

    ptrdiff_t pt_write_int8(std::vector<char> &buffer, const int8_t &value) {
        size_t size = sizeof(value);
        buffer.insert(buffer.end(), reinterpret_cast<const char *>(&value), reinterpret_cast<const char *>(&value) + size);
        return size;
    }

    ptrdiff_t pt_write_bool(std::vector<char> &buffer, const bool value) {
        buffer.push_back(value ? 0 : 1);
        return 1;
    }

    ptrdiff_t pt_write_position_t(std::vector<char> &buffer, const position_t &value) {
        int32_t v = value.x;
        if (((v & 1 << 31) && ((v & 0x7F800000) != 0x7F800000)) || ((v & 1 << 31) == 0 &&(v & 0x7F800000) != 0))
            std::cerr << __PRETTY_FUNCTION__ << " Value X overflow" << std::endl;
        if (v & 1 << 31) v & 1 << 23;
        buffer.insert(buffer.end(), reinterpret_cast<const char *>(&v), reinterpret_cast<const char *>(&v) + 24);

        v = value.z;
        if (((v & 1 << 31) && ((v & 0x7F800000) != 0x7F800000)) || ((v & 1 << 31) == 0 &&(v & 0x7F800000) != 0))
            std::cerr << __PRETTY_FUNCTION__ << " Value Z overflow" << std::endl;
        if (v & 1 << 31) v &= 1 << 23;
        buffer.insert(buffer.end(), reinterpret_cast<const char *>(&v), reinterpret_cast<const char *>(&v) + 24);

        v = value.y;
        if (((v & 1 << 31) && ((v & 0x7FFF8000) != 0x7FFF8000)) || ((v & 1 << 31) == 0 &&(v & 0x7FFF8000) != 0))
            std::cerr << __PRETTY_FUNCTION__ << " Value Y overflow" << std::endl;
        if (v & 1 << 31) v &= 1 << 15;
        buffer.insert(buffer.end(), reinterpret_cast<const char *>(&v), reinterpret_cast<const char *>(&v) + 16);

        return 24 + 24 + 16; //64
    }

    ptrdiff_t pt_write_uuid(std::vector<char>& bytes, const uuid_t& uuid) {
        auto ptr = reinterpret_cast<const char*>(&uuid);
        std::copy(ptr, ptr + sizeof(uuid), std::back_inserter(bytes));
        return sizeof(uuid_t);
    }

    ptrdiff_t pt_read_bool(const std::vector<char>::iterator &begin, const std::vector<char>::iterator &end, bool &value) {
        if (begin == end) return -1;
        value = *begin;
        return 1;
    }

    ptrdiff_t pt_read_uuid(const std::vector<char>::iterator &begin, const std::vector<char>::iterator &end, uuid_t &value) {
        if(std::distance(begin, end) < sizeof(uuid_t)) {
            return -1;  // Not enough data to form a UUID
        }

        std::copy(begin, begin + sizeof(uuid_t), reinterpret_cast<char*>(&value));
        return sizeof(uuid_t);
    }
}
