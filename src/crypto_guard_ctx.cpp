#include "crypto_guard_ctx.h"
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <openssl/evp.h>
#include <streambuf>
#include <vector>

#define BUFSIZE 1024

namespace CryptoGuard {

// Структура для хранения параметров шифрования
struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

struct CryptoGuardCtx::Impl {

    // Указатель на CTX структуру
    std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })> ctx;

    // Констурктор
    Impl() {
        OpenSSL_add_all_algorithms();
        ctx.reset(EVP_CIPHER_CTX_new());
        EVP_CIPHER_CTX_init(ctx.get());
    }

    // Деструктор
    ~Impl() {
        EVP_CIPHER_CTX_init(ctx.get());
        EVP_cleanup();
    }

    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }

    AesCipherParams params;

    // Заготовка приватных методов шифрования, дешифрования и расчета контрольной суммы
    void Encrypt(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        params = CreateChiperParamsFromPassword(password);
        params.encrypt = 1;
        std::vector<char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
        std::vector<char> inBuf(16);
        int outLen = 0;
        std::ifstream *in = (std::ifstream *)&inStream;
        std::ofstream *op = (std::ofstream *)&outStream;

        EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);

        while (in->read(inBuf.data(), inBuf.size())) {
            EVP_CipherUpdate(ctx.get(), (unsigned char *)outBuf.data(), &outLen, (unsigned char *)inBuf.data(),
                             in->gcount());
            op->write(outBuf.data(), outLen);
        }

        EVP_CipherUpdate(ctx.get(), (unsigned char *)outBuf.data(), &outLen, (unsigned char *)inBuf.data(),
                         in->gcount());
        EVP_CipherFinal_ex(ctx.get(), (unsigned char *)outBuf.data(), &outLen);
        op->write(outBuf.data(), outLen);
    }

    void Decrypt(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        params = CreateChiperParamsFromPassword(password);
        params.encrypt = 0;
        std::vector<char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
        std::vector<char> inBuf(16);
        int outLen = 0;
        std::ifstream *in = (std::ifstream *)&inStream;
        std::ofstream *op = (std::ofstream *)&outStream;

        EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);
        while (in->read(inBuf.data(), inBuf.size())) {
            EVP_CipherUpdate(ctx.get(), (unsigned char *)outBuf.data(), &outLen, (unsigned char *)inBuf.data(),
                             in->gcount());
            op->write(outBuf.data(), outLen);
        }

        EVP_CipherUpdate(ctx.get(), (unsigned char *)outBuf.data(), &outLen, (unsigned char *)inBuf.data(),
                         in->gcount());
        EVP_CipherFinal_ex(ctx.get(), (unsigned char *)outBuf.data(), &outLen);
        op->write(outBuf.data(), outLen);
    }

    std::string CalculateChecksum(std::iostream &inStream) { return "NOT IMPLEMENTED"; }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()){};
CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->Encrypt(inStream, outStream, password);
};
void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->Decrypt(inStream, outStream, password);
};
std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); };

}  // namespace CryptoGuard
