#include "crypto_guard_ctx.h"
#include <iomanip>
#include <iostream>
#include <memory>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>
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
    std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ctxMd) { EVP_MD_CTX_free(ctxMd); })> ctxMd;

    // Констурктор
    Impl() {
        OpenSSL_add_all_algorithms();
        ctx.reset(EVP_CIPHER_CTX_new());
        EVP_CIPHER_CTX_init(ctx.get());
        ctxMd.reset(EVP_MD_CTX_new());
        EVP_MD_CTX_init(ctxMd.get());
    }

    // Деструктор
    ~Impl() {
        EVP_CIPHER_CTX_init(ctx.get());
        EVP_MD_CTX_init(ctxMd.get());
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
    void Encrypt(std::istream &inStream, std::ostream &outStream, std::string_view password) {
        params = CreateChiperParamsFromPassword(password);
        params.encrypt = 1;
        std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(16);
        int outLen = 0;

        EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);
        while (inStream.read((char *)inBuf.data(), inBuf.size())) {
            EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inStream.gcount());
            outStream.write((char *)outBuf.data(), outLen);
        }

        EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inStream.gcount());
        EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen);
        outStream.write((char *)outBuf.data(), outLen);
    }

    void Decrypt(std::istream &inStream, std::ostream &outStream, std::string_view password) {
        params = CreateChiperParamsFromPassword(password);
        params.encrypt = 0;
        std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(16);
        int outLen = 0;

        EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);
        while (inStream.read((char *)inBuf.data(), inBuf.size())) {
            EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inStream.gcount());
            outStream.write((char *)outBuf.data(), outLen);
        }

        EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inStream.gcount());
        EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen);
        outStream.write((char *)outBuf.data(), outLen);
    }

    std::string CalculateChecksum(std::istream &inStream) {
        const EVP_MD *md;
        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned int md_len;
        md = EVP_get_digestbyname("SHA256");
        EVP_DigestInit(ctxMd.get(), md);
        std::vector<unsigned char> inBuf(16);

        while (inStream.read((char *)inBuf.data(), inBuf.size())) {
            EVP_DigestUpdate(ctxMd.get(), inBuf.data(), inStream.gcount());
        }
        EVP_DigestUpdate(ctxMd.get(), inBuf.data(), inStream.gcount());
        EVP_DigestFinal(ctxMd.get(), md_value, &md_len);

        /*char* converted=new char[md_len];
        int i;
        for(i=0; i<md_len; i++){
            sprintf(&converted[i*2], "%02X", md_value[i]);
        }
        printf("%s\n", converted);*/

        std::stringstream ss;
        for (int i = 0; i < md_len; i++) {
            ss << std::setfill('0') << std::setw(2) << std::hex << (unsigned int)md_value[i];
        }
        std::string result = ss.str();

        return result;
    }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()){};
CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    pImpl_->Encrypt(inStream, outStream, password);
};
void CryptoGuardCtx::DecryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    pImpl_->Decrypt(inStream, outStream, password);
};
std::string CryptoGuardCtx::CalculateChecksum(std::istream &inStream) { return pImpl_->CalculateChecksum(inStream); };

}  // namespace CryptoGuard
