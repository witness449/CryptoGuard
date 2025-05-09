#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <array>
#include <fstream>
#include <iostream>
#include <istream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>
#include <string>

int main(int argc, char *argv[]) {
    try {
        //
        // OpenSSL пример использования:
        //
        // std::string input = "01234567890123456789";
        /*std::string output;

        OpenSSL_add_all_algorithms();

        auto params = CreateChiperParamsFromPassword("12341234");
        params.encrypt = 1;
        auto *ctx = EVP_CIPHER_CTX_new();

        // Инициализируем cipher
        EVP_CipherInit_ex(ctx, params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);

        std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(16);
        int outLen;

        // Обрабатываем первые N символов
        EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(16));
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }

        // Обрабатываем оставшиеся символы
        EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(16));
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }

        // Заканчиваем работу с cipher
        EVP_CipherFinal_ex(ctx, outBuf.data(), &outLen);
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }
        EVP_CIPHER_CTX_free(ctx);
        std::print("String encoded successfully. Result: '{}'\n\n", output);
        EVP_cleanup();
        //
        // Конец примера
        //
        */

        CryptoGuard::ProgramOptions options;

        // Вызов парсинга аргументов
        options.Parse(argc, argv);

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            std::string inputFileName = options.GetInputFile();
            std::string outputFileName = options.GetOutputFile();
            std::ifstream *in = new std::ifstream();
            std::ofstream *out = new std::ofstream();
            in->open(inputFileName);
            out->open(outputFileName);
            cryptoCtx.EncryptFile(*(std::iostream *)in, *(std::iostream *)out, options.GetPassword());
            in->close();
            out->close();
            delete in;
            delete out;
            std::print("File encoded successfully\n");
            break;
        }

        case COMMAND_TYPE::DECRYPT: {
            std::string inputFileName = options.GetInputFile();
            std::string outputFileName = options.GetOutputFile();
            std::ifstream *in = new std::ifstream();
            std::ofstream *out = new std::ofstream();
            in->open(inputFileName);
            out->open(outputFileName);
            cryptoCtx.DecryptFile(*(std::iostream *)in, *(std::iostream *)out, options.GetPassword());
            in->close();
            out->close();
            delete in;
            delete out;
            std::print("File decoded successfully\n");
            break;
        }
        case COMMAND_TYPE::CHECKSUM:
            std::print("Checksum: {}\n", "CHECKSUM_NOT_IMPLEMENTED");
            break;
        case COMMAND_TYPE::NONE:
            break;
        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}