#include "crypto_guard_ctx.h"
#include <iomanip>
#include <iostream>
#include <memory>
#include <openssl/err.h>
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

    // Указатели на структуры контекста, освобождение ресурса предусмотрено в удалителе
    std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })> ctx;
    std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ctxMd) { EVP_MD_CTX_free(ctxMd); })> ctxMd;

    // Констурктор
    Impl() {
        OpenSSL_add_all_algorithms();
        // Создание указателей
        ctx.reset(EVP_CIPHER_CTX_new());
        ctxMd.reset(EVP_MD_CTX_new());
        // Очистка памяти (м. б. лишнее)
        EVP_CIPHER_CTX_init(ctx.get());
        EVP_MD_CTX_init(ctxMd.get());
    }

    // Деструктор
    ~Impl() {
        // Очистка памяти
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

    // Получение описания ошибки OpenSSL
    char *GetError() { return ERR_error_string(ERR_get_error(), NULL); }

    // Обертка для функции инициализации шифра
    void CipherInit() {
        if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                               params.encrypt)) {
            throw std::runtime_error(GetError());
        }
    }

    // Обертка для функции шифрования
    void CipherUpdate(std::vector<unsigned char> &outBuf, int &outLen, std::vector<unsigned char> &inBuf, int bufSize) {
        if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), bufSize)) {
            throw std::runtime_error(GetError());
        }
    }

    // Обертка для функции дошифровки
    void CipherFinal(std::vector<unsigned char> &outBuf, int &outLen) {
        if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
            throw std::runtime_error(GetError());
        }
    }

    AesCipherParams params;

    // Метод шифрования, аргументы - входной и выходной потоки, пароль
    void Encrypt(std::istream &inStream, std::ostream &outStream, std::string_view password) {
        // inStream.exceptions(std::istream::badbit);
        // Проверка состояния входного и выходного потоков
        if (!inStream.good() && !outStream.good()) {
            throw std::runtime_error("Streams not allow read/write");
        }

        params = CreateChiperParamsFromPassword(password);
        params.encrypt = 1;

        // Подготовка буферов
        std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(16);
        int outLen = 0;

        CipherInit();

        // Цикл шифрования согласно размеру входного буфера
        while (inStream.read((char *)inBuf.data(), inBuf.size())) {
            CipherUpdate(outBuf, outLen, inBuf, inStream.gcount());
            // Проверка состояния входного и выходного потоков
            if (!inStream.good() && !outStream.good()) {
                throw std::runtime_error("Streams not allow read/write");
            }
            outStream.write((char *)outBuf.data(), outLen);
        }
        // Поскольку выход из цикла происходит по факту прочтения потока, необходимо вызывать метод шифрования еще раз
        CipherUpdate(outBuf, outLen, inBuf, inStream.gcount());
        CipherFinal(outBuf, outLen);
        if (!outStream.good()) {
            throw std::runtime_error("Streams not allow read/write");
        }
        outStream.write((char *)outBuf.data(), outLen);
    }

    // Метод дешифровки полностью аналогичен методу шифрования
    void Decrypt(std::istream &inStream, std::ostream &outStream, std::string_view password) {
        if (!inStream.good() && !outStream.good()) {
            throw std::runtime_error("Streams not allow read/write");
        }
        params = CreateChiperParamsFromPassword(password);
        params.encrypt = 0;
        std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(16);
        int outLen = 0;

        CipherInit();
        while (inStream.read((char *)inBuf.data(), inBuf.size())) {
            CipherUpdate(outBuf, outLen, inBuf, inStream.gcount());
            if (!inStream.good() && !outStream.good()) {
                throw std::runtime_error("Streams not allow read/write");
            }
            outStream.write((char *)outBuf.data(), outLen);
        }
        CipherUpdate(outBuf, outLen, inBuf, inStream.gcount());
        CipherFinal(outBuf, outLen);
        if (!outStream.good()) {
            throw std::runtime_error("Streams not allow read/write");
        }
        outStream.write((char *)outBuf.data(), outLen);
    }

    // Метод расчета контрольной суммы
    std::string CalculateChecksum(std::istream &inStream) {
        // Проверка состояния потока
        if (!inStream.good()) {
            throw std::runtime_error("Streams not allow read");
        }

        const EVP_MD *md;
        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned int md_len;
        md = EVP_get_digestbyname("SHA256");

        // Инициализация контекста подсчета контрольной суммы
        if (!EVP_DigestInit(ctxMd.get(), md)) {
            throw std::runtime_error(GetError());
        }

        // Подготовка буфера
        std::vector<unsigned char> inBuf(16);

        // Цикл подсчета контрольной суммы
        while (inStream.read((char *)inBuf.data(), inBuf.size())) {
            // Проверка состония потока
            if (!inStream.good()) {
                throw std::runtime_error("Streams not allow read");
            }
            // Расчет контрольной суммы согласно размеру входного буфера
            if (!EVP_DigestUpdate(ctxMd.get(), inBuf.data(), inStream.gcount())) {
                throw std::runtime_error(GetError());
            }
        }

        // Поскольку выход из цикла происходит по факту прочтения потока, необходимо вызывать функцию расчета к с еще
        // раз
        if (!EVP_DigestUpdate(ctxMd.get(), inBuf.data(), inStream.gcount())) {
            throw std::runtime_error(GetError());
        }

        // Заполнение массива полученной к с
        if (!EVP_DigestFinal(ctxMd.get(), md_value, &md_len)) {
            throw std::runtime_error(GetError());
        }

        /*char* converted=new char[md_len];
        int i;
        for(i=0; i<md_len; i++){
            sprintf(&converted[i*2], "%02X", md_value[i]);
        }
        printf("%s\n", converted);*/

        // Преобразование к с в строку
        std::stringstream ss;
        for (int i = 0; i < md_len; i++) {
            ss << std::setfill('0') << std::setw(2) << std::hex << (unsigned int)md_value[i];
        }
        std::string result = ss.str();

        return result;
    }
};

// В конструкторе создается unique_ptr на Impl объект
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
