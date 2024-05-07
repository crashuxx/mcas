#ifndef MCAS_HASH_H
#define MCAS_HASH_H

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string>
#include <vector>
#include <iomanip>

namespace mcas::protocol {
    struct SignedSha1 {
        SignedSha1() {
            hashptr = EVP_sha1();
            assert(hashptr);
            hashctx = EVP_MD_CTX_new();
            assert(hashctx);
            EVP_MD_CTX_init(hashctx);
            EVP_DigestInit_ex(hashctx, hashptr, nullptr);
        }

        ~SignedSha1() {
            EVP_MD_CTX_free(hashctx);
        }

        SignedSha1(SignedSha1 const &) = delete;

        SignedSha1(SignedSha1 &&) = delete;

        SignedSha1 &operator=(SignedSha1 const &) = delete;

        SignedSha1 &operator=(SignedSha1 &&) = delete;

        void update(std::vector<char> &input) {
            EVP_DigestUpdate(hashctx, (const void *) input.data(), (size_t) input.size());
        }

        void update(std::string &input) {
            EVP_DigestUpdate(hashctx, (const void *) input.data(), (size_t) input.size());
        }

        std::string finalise() {
            unsigned int size = 20;
            unsigned char buffer[size];

            EVP_DigestFinal_ex(hashctx, buffer, &size);
            EVP_MD_CTX_reset(hashctx);

            std::stringstream ss;
            if (buffer[0] & 1 << 7) {
                ss << '-';
                buffer[19] -= 1;
                for(int i = 0; i < size; i++) {
                    buffer[i] ^= 0xFF;
                }
            }

            for(int i = 0; i < size; i++) {
                ss << std::setfill('0') << std::setw(2) << std::hex << (unsigned int)buffer[i];
            }

            return ss.str();
        }

    private:
        const EVP_MD *hashptr;
        EVP_MD_CTX *hashctx;
    };

}   // namespace mcas::protocol

#endif //MCAS_HASH_H
