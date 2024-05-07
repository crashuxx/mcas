#ifndef MCAS_PROTOCOL_H
#define MCAS_PROTOCOL_H

#include "common.h"
#include "types.h"

namespace mcas::protocol {

    ptrdiff_t pt_read_int16_t(const std::vector<char>::iterator &begin,
                              const std::vector<char>::iterator &end,
                              int16_t *value);

    ptrdiff_t pt_read_int32_t(const std::vector<char>::iterator &begin,
                              const std::vector<char>::iterator &end,
                              int32_t *value);

    ptrdiff_t pt_read_string(const std::vector<char>::iterator &begin,
                             const std::vector<char>::iterator &end,
                             std::string &value);

    ptrdiff_t pt_read_vector(const std::vector<char>::iterator &begin,
                             const std::vector<char>::iterator &end,
                             std::vector<char> &value);

    ptrdiff_t pt_write_string(std::vector<char> &buffer, const std::string &value);

    ptrdiff_t pt_write_bytes(std::vector<char> &buffer, std::vector<char> &value);

    ptrdiff_t pt_write_varint(std::vector<char> &buffer, const int32_t &value);

    ptrdiff_t pt_write_varint(std::vector<char> &buffer, const size_t &value);

    ptrdiff_t pt_write_int64(std::vector<char> &buffer, const int64_t &value);

    ptrdiff_t pt_write_int32(std::vector<char> &buffer, const int32_t &value);

    ptrdiff_t pt_write_int16(std::vector<char> &buffer, const int16_t &value);

    ptrdiff_t pt_write_int8(std::vector<char> &buffer, const int8_t &value);

    ptrdiff_t pt_write_bool(std::vector<char> &buffer, bool value);

    ptrdiff_t pt_write_position_t(std::vector<char> &buffer, position_t value);

}

#endif //MCAS_PROTOCOL_H
