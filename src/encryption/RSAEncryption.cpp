#include "RSAEncryption.h"

#include <algorithm>
#include <cstring>
#include <vector>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <boost/beast/core/detail/base64.hpp>

namespace mcas::encryption {
    RSAEncryption::RSAEncryption() {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1024);
        EVP_PKEY_keygen(ctx, (EVP_PKEY**)&pkey);
        EVP_PKEY_CTX_free(ctx);

        std::string b64key = extractBase64PublicKey();
        cleanKey(b64key);
        decodeBase64Key(b64key);
    }

    void RSAEncryption::decodeBase64Key(std::string &b64key) {
        publicKey.resize(boost::beast::detail::base64::decoded_size(b64key.size()));
        boost::beast::detail::base64::decode(publicKey.data(), b64key.data(), b64key.size());
    }

    void RSAEncryption::cleanKey(std::string &b64key) {
        b64key.erase(std::remove(b64key.begin(), b64key.end(), '\n'), b64key.end());
        b64key.erase(std::remove(b64key.begin(), b64key.end(), '\r'), b64key.end());
        b64key.erase(0, 26);
        b64key.erase(b64key.size() - 24, 24);
    }

    RSAEncryption::~RSAEncryption() {
        if (pkey != nullptr) {
            EVP_PKEY_free((EVP_PKEY*)pkey);
        }
    }

    size_t RSAEncryption::encrypt(std::vector<char> &output, char *input, size_t inputSize) {
        return encrypt(output, (void *) input, inputSize);
    }

    size_t RSAEncryption::encrypt(std::vector<char> &output, void *input, size_t inputSize) {
        int ret;

        if (input == nullptr) {
            std::cerr << __PRETTY_FUNCTION__ << " Encryption::encrypt input == nullptr" << std::endl;
            return -1;
        }
        if (inputSize <= 0) {
            std::cerr << __PRETTY_FUNCTION__ << " Encryption::encrypt inputSize <= 0" << std::endl;
            return -1;
        }

        EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new((EVP_PKEY*)pkey, nullptr);
        if (pkey_ctx == nullptr) {
            std::cerr << __PRETTY_FUNCTION__ << " EVP_PKEY_CTX_new(..) == nullptr" << std::endl;
            return -1;
        }

        ret = EVP_PKEY_encrypt_init(pkey_ctx);
        if (ret <= 0) {
            EVP_PKEY_CTX_free(pkey_ctx);
            std::cout << "EVP_PKEY_encrypt_init(..) failed" << std::endl;
            return ret;
        }

        size_t encryptedSize;

        ret = EVP_PKEY_encrypt(pkey_ctx, nullptr, &encryptedSize, (const unsigned char *) input, inputSize);
        if (ret <= 0) {
            EVP_PKEY_CTX_free(pkey_ctx);
            std::cout << "EVP_PKEY_encrypt(..) failed" << std::endl;
            return ret;
        }

        output.resize(encryptedSize);
        ret = EVP_PKEY_encrypt(pkey_ctx, (unsigned char *) output.data(), &encryptedSize, (const unsigned char *) input, inputSize);
        if (ret <= 0) {
            EVP_PKEY_CTX_free(pkey_ctx);
            std::cout << "EVP_PKEY_encrypt(..) failed" << std::endl;
            return ret;
        }

        EVP_PKEY_CTX_free(pkey_ctx);

        return encryptedSize;
    }

    size_t RSAEncryption::decrypt(std::vector<char> &output, char *input, size_t inputSize) {
        return decrypt(output, (void *) input, inputSize);
    }

    size_t RSAEncryption::decrypt(std::vector<char> &output, void *input, size_t inputSize) {
        int ret;

        if (input == nullptr) {
            std::cerr << __PRETTY_FUNCTION__ << " input == nullptr" << std::endl;
            return -1;
        }
        if (inputSize <= 0) {
            std::cerr << __PRETTY_FUNCTION__ << " inputSize <= 0" << std::endl;
            return -1;
        }

        EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new((EVP_PKEY*)pkey, nullptr);
        if (pkey_ctx == nullptr) {
            std::cerr << __PRETTY_FUNCTION__ << " EVP_PKEY_CTX_new(..) == nullptr" << std::endl;
            return -1;
        }

        ret = EVP_PKEY_decrypt_init(pkey_ctx);
        if (ret <= 0) {
            EVP_PKEY_CTX_free(pkey_ctx);
            std::cerr << __PRETTY_FUNCTION__ << " EVP_PKEY_decrypt_init(..) == nullptr" << std::endl;
            return ret;
        }

        size_t decryptedSize;

        ret = EVP_PKEY_decrypt(pkey_ctx, nullptr, &decryptedSize, (const unsigned char *) input, inputSize);
        if (ret <= 0) {
            EVP_PKEY_CTX_free(pkey_ctx);
            std::cerr << __PRETTY_FUNCTION__ << " EVP_PKEY_decrypt(..) failed" << std::endl;
            return ret;
        }
        output.resize(decryptedSize);
        ret = EVP_PKEY_decrypt(pkey_ctx, (unsigned char *) output.data(), &decryptedSize, (const unsigned char *) input, inputSize);
        if (ret <= 0) {
            EVP_PKEY_CTX_free(pkey_ctx);
            std::cerr << __PRETTY_FUNCTION__ << " EVP_PKEY_decrypt(..) data failed" << std::endl;
            return ret;
        }

        EVP_PKEY_CTX_free(pkey_ctx);

        output.resize(decryptedSize);
        return decryptedSize;
    }

    std::string RSAEncryption::extractBase64PublicKey() {
        std::string b64key;
        BIO *bio_out = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(bio_out, (EVP_PKEY*)pkey);

        char *bio_data;
        size_t bio_dataSize = BIO_get_mem_data(bio_out, &bio_data);
        b64key.resize(bio_dataSize);
        memcpy(b64key.data(), bio_data, bio_dataSize);

        BIO_free(bio_out);

        return b64key;
    }

    std::vector<char> &RSAEncryption::getPublicKey() {
        return publicKey;
    }

} // encryption