#include "leb128.h"

ptrdiff_t leb128_encode(std::vector<char> &buffer, int32_t value) {
    uint32_t *v = (uint32_t*)&value;

    ptrdiff_t n = 0;
    while (true) {
        n++;

        if ((*v & ~0x7F) == 0) {
            buffer.push_back((char) *v);
            return n;
        }

        buffer.push_back((char) ((*v & 0x7F) | 0x80));

        *v >>= 7;
    }
}

ptrdiff_t leb128_encode(const std::vector<char>::iterator &iterator, int32_t value) {
    uint32_t *v = (uint32_t*)&value;
    auto it = iterator;

    ptrdiff_t n = 0;
    while (true) {
        n++;

        if ((*v & ~0x7F) == 0) {
            *it = (char) *v;
            return n;
        }

        *it = (char) ((*v & 0x7F) | 0x80);
        it = next(it);

        *v >>= 7;
    }
}

ptrdiff_t leb128_decode_int32(
        const std::vector<char>::iterator &begin,
        const std::vector<char>::iterator &end,
        int32_t *value) {
    unsigned int shift = 0;
    int32_t result = 0;
    uint8_t byte;

    std::vector<char>::iterator it = begin;

    do {
        if (it >= end) {
            return 0;
        }

        byte = *it;
        it = next(it);

        result |= ((int32_t)(byte & 0x7f)) << shift;
        shift += 7;

    } while ((byte & 0x80) != 0);

    if (shift < (sizeof(*value) * 8) && (byte & 0x40) != 0)
        result |= -(((int32_t) 1) << shift);

    *value = result;
    return it - begin;
}