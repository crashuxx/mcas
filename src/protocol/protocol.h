#ifndef MCAS_PROTOCOL_H
#define MCAS_PROTOCOL_H

#include "common.h"

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

ptrdiff_t pt_write_string(std::vector<char> &buffer, std::string &value);
ptrdiff_t pt_write_bytes(std::vector<char> &buffer, std::vector<char> &value);

#endif //MCAS_PROTOCOL_H
