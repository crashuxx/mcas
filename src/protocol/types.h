#ifndef MCAS_TYPES_H
#define MCAS_TYPES_H

#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <tuple>

namespace mcas::protocol {

    typedef int32_t varint_t;
    typedef std::tuple<int32_t, int32_t, int32_t> position_t;

}

#endif //MCAS_TYPES_H
