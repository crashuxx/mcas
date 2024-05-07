#include <cstring>
#include "protocol.h"

#include "../leb128.h"

ptrdiff_t pt_read_int16_t(const std::vector<char>::iterator &begin,
                          const std::vector<char>::iterator &end,
                          int16_t *value) {
    if(next(begin, 2) == end) {
        return 0;
    }

    memcpy(value, begin.base(), sizeof(uint16_t));

    return sizeof(uint16_t);
}

ptrdiff_t pt_read_int32_t(const std::vector<char>::iterator &begin,
                          const std::vector<char>::iterator &end,
                          int32_t *value) {
    return leb128_decode_int32(begin, end, value);
}

ptrdiff_t pt_read_string(const std::vector<char>::iterator &begin,
                         const std::vector<char>::iterator &end,
                         std::string &value) {

    int32_t stringSize;
    ptrdiff_t readed;

    readed = leb128_decode_int32(begin, end, &stringSize);
    if (readed <= 0) {
        return readed;
    }
    if ((stringSize + readed) > (end - begin)) {
        return -1;
    }

    auto it = next(begin, readed);

    value.resize(stringSize + 1);
    value.assign(it.base(), stringSize);

    return readed + stringSize;
}

ptrdiff_t pt_read_vector(const std::vector<char>::iterator &begin,
                         const std::vector<char>::iterator &end,
                         std::vector<char> &value) {

    int32_t size;
    ptrdiff_t readed;

    readed = leb128_decode_int32(begin, end, &size);
    if (readed <= 0) {
        return readed;
    }
    if ((size + readed) > (end - begin)) {
        return -1;
    }

    auto it = next(begin, readed);

    value.resize(size);
    memcpy(value.data(), it.base(), size);

    return readed + size;
}

ptrdiff_t pt_write_string(std::vector<char> &buffer, std::string &value) {

    leb128_encode(buffer, value.size());
    copy(value.begin(), value.end(), back_inserter(buffer));

    return 1;
}

ptrdiff_t pt_write_bytes(std::vector<char> &buffer, std::vector<char> &value) {

    leb128_encode(buffer, value.size());
    copy(value.begin(), value.end(), back_inserter(buffer));

    return 1;
}