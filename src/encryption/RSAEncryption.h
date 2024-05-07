#ifndef MCAS_RSAENCRYPTION_H
#define MCAS_RSAENCRYPTION_H

#include <string>
#include <vector>

namespace mcas::encryption {

    class RSAEncryption {
    public:
        RSAEncryption();

        virtual ~RSAEncryption();

        size_t encrypt(std::vector<char> &output, char *input, size_t inputSize);

        size_t encrypt(std::vector<char> &output, void *input, size_t inputSize);

        size_t decrypt(std::vector<char> &output, char *input, size_t inputSize);

        size_t decrypt(std::vector<char> &output, void *input, size_t inputSize);

        std::vector<char>& getPublicKey();

    private:
        void *pkey = nullptr;
        std::vector<char> publicKey;

        std::string extractBase64PublicKey();

        static void cleanKey(std::string &b64key);

        void decodeBase64Key(std::string &b64key);
    };

} // encryption

#endif //MCAS_RSAENCRYPTION_H
