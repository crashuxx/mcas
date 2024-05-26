#include "AESEncryption.h"

#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>

namespace mcas::encryption {

    AESEncryption::AESEncryption() {
        ectx = nullptr;
        dctx = nullptr;
    }

    AESEncryption::AESEncryption(std::vector<char> key, std::vector<char> iv) {
        init(key, iv);
    }

    void AESEncryption::init(std::vector<char> &key, std::vector<char> &iv) {
        cleanup();

        ectx = (void *) EVP_CIPHER_CTX_new();
        if (ectx == nullptr) {
            std::cerr << __PRETTY_FUNCTION__ << " EVP_CIPHER_CTX_new() == nullptr" << std::endl;
            exit(-1);
        }

        int initEx = EVP_EncryptInit_ex((EVP_CIPHER_CTX *) ectx, EVP_aes_128_cfb8(), nullptr, (const unsigned char *) key.data(),
                                        (const unsigned char *) iv.data());
        if (initEx <= 0) {
            std::cerr << __PRETTY_FUNCTION__ << " EVP_EncryptInit_ex(..) <= " << initEx << std::endl;
            exit(-1);
        }

        dctx = (void *) EVP_CIPHER_CTX_new();
        if (dctx == nullptr) {
            std::cerr << __PRETTY_FUNCTION__ << " EVP_CIPHER_CTX_new() == nullptr" << std::endl;
            exit(-1);
        }

        initEx = EVP_DecryptInit_ex((EVP_CIPHER_CTX *) dctx, EVP_aes_128_cfb8(), nullptr, (const unsigned char *) key.data(),
                                    (const unsigned char *) iv.data());
        if (initEx <= 0) {
            std::cerr << __PRETTY_FUNCTION__ << " EVP_DecryptInit_ex(..) <= " << initEx << std::endl;
            exit(-1);
        }
    }

    AESEncryption::~AESEncryption() {
        cleanup();
    }

    void AESEncryption::cleanup() {
        if (ectx != nullptr) EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *) ectx);
        if (dctx != nullptr) EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *) dctx);

        ectx = nullptr;
        dctx = nullptr;
    }

    size_t AESEncryption::encrypt(std::vector<char> &output, void *input, size_t inputSize) {
        int outputSize;
        int tmpSize;

        if (inputSize > INT_MAX) {
            std::cerr << __PRETTY_FUNCTION__ << " inputSize > " << INT_MAX << std::endl;
            return 0;
        }

        if (output.size() != inputSize)
            output.resize(inputSize);

        if (!EVP_EncryptUpdate((EVP_CIPHER_CTX *) ectx, (unsigned char *) output.data(), &tmpSize, (unsigned char *) input, inputSize)) {
            std::cerr << __PRETTY_FUNCTION__ << " EVP_EncryptUpdate failed " << std::endl;
            return 0;
        }

        outputSize = tmpSize;

//        if (!EVP_EncryptFinal_ex((EVP_CIPHER_CTX*)ectx, (unsigned char *) output.data() + tmpSize, &tmpSize)) {
//            std::cerr << __PRETTY_FUNCTION__ << " EVP_EncryptFinal_ex " << std::endl;
//            return 0;
//        }
//        outputSize += tmpSize;

        output.resize(outputSize);

        return outputSize;
    }

    size_t AESEncryption::decrypt(std::vector<char> &output, void *input, size_t inputSize) {
        int outputSize;
        int tmpSize;

        if (inputSize > INT_MAX) {
            std::cerr << __PRETTY_FUNCTION__ << " inputSize > " << INT_MAX << std::endl;
            return 0;
        }

        output.resize(inputSize);

        if (!EVP_DecryptUpdate((EVP_CIPHER_CTX *) dctx, (unsigned char *) output.data(), &tmpSize, (unsigned char *) input, inputSize)) {
            std::cerr << __PRETTY_FUNCTION__ << " EVP_EncryptUpdate failed " << std::endl;
            return 0;
        }

        outputSize = tmpSize;

        if (!EVP_DecryptFinal_ex((EVP_CIPHER_CTX *) dctx, (unsigned char *) output.data() + tmpSize, &tmpSize)) {
            std::cerr << __PRETTY_FUNCTION__ << " EVP_EncryptFinal_ex " << std::endl;
            return 0;
        }

        outputSize += tmpSize;

        return outputSize;
    }
} // encryption