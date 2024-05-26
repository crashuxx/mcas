#ifndef MCAS_AESENCRYPTION_H
#define MCAS_AESENCRYPTION_H

#include <cstddef>
#include <vector>

namespace mcas::encryption {

    class AESEncryption {
    public:
        AESEncryption();
        AESEncryption(std::vector<char> key, std::vector<char> iv);
        void init(std::vector<char> &key, std::vector<char> &iv);

        virtual ~AESEncryption();

        size_t encrypt(std::vector<char> &output, void *input, size_t inputSize);

        size_t decrypt(std::vector<char> &output, void *input, size_t inputSize);

    private:
        void cleanup();

        void *ectx = nullptr;
        void *dctx = nullptr;
    };

} // encryption

#endif //MCAS_AESENCRYPTION_H
