#ifndef MCAS_LEB128_H
#define MCAS_LEB128_H

#include <cstdint>
#include <cstddef>
#include <vector>

ptrdiff_t leb128_encode(std::vector<char> &buffer, int32_t value);

ptrdiff_t leb128_encode(const std::vector<char>::iterator &iterator, int32_t value);

ptrdiff_t leb128_decode_int32(
        const std::vector<char>::iterator &begin,
        const std::vector<char>::iterator &end,
        int32_t *value);

#endif //MCAS_LEB128_H
