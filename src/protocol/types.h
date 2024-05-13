#ifndef MCAS_TYPES_H
#define MCAS_TYPES_H

#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <tuple>

namespace mcas::protocol {

    typedef int32_t varint_t;
    typedef int64_t uuid_t[2];
    typedef double f64_t;
    typedef float f32_t;

    struct slot_t {
        bool present;
        varint_t itemId; // optional
        unsigned char itemCount; // optional
        bool nbt; // optional
    };

    typedef int32_t packedChunkPos_t[2];
    struct position_t {
        int32_t x;
        int32_t z;
        int32_t y;
    };  // 24 24 16 = 64bits
}

#endif //MCAS_TYPES_H
