#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <boost/scope/scope_exit.hpp>
#include <boost/scope/scope_fail.hpp>
#include <boost/scope/scope_success.hpp>
#include <exception>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>
#include <string>

std::fstream GetFilestream(std::string path, std::ios_base::openmode flags) {
    std::fstream stream(path, flags);
    if (!stream.is_open()) {
        throw std::runtime_error{"Error opening file"};
    }
    return stream;
}

int main(int argc, char *argv[]) {
    try {

        CryptoGuard::ProgramOptions options;

        // Вызов парсинга аргументов
        options.Parse(argc, argv);

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;

        // В зависимости от команды вызываем соответствующий блок
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {

            // Проверка совпадений входящего и выходящего файлов
            if (options.GetInputFile() == options.GetOutputFile()) {
                throw std::runtime_error{"I/O files are identical"};
            }

            std::fstream in = GetFilestream(options.GetInputFile(), std::ios::in);
            std::fstream out = GetFilestream(options.GetOutputFile(), std::ios::out | std::ios::trunc);

            cryptoCtx.EncryptFile(in, out, options.GetPassword());
            std::print("File encoded successfully\n");
            break;
        }

        case COMMAND_TYPE::DECRYPT: {

            // Проверка совпадений входящего и выходящего файлов
            if (options.GetInputFile() == options.GetOutputFile()) {
                throw std::runtime_error{"I/O files are identical"};
            }
            std::fstream in = GetFilestream(options.GetInputFile(), std::ios::in);
            std::fstream out = GetFilestream(options.GetOutputFile(), std::ios::out | std::ios::trunc);

            cryptoCtx.DecryptFile(in, out, options.GetPassword());
            std::print("File decoded successfully\n");
            break;
        }
        case COMMAND_TYPE::CHECKSUM: {
            std::fstream in = GetFilestream(options.GetInputFile(), std::ios::in);

            std::string result = cryptoCtx.CalculateChecksum(in);
            std::print("Checksum: {}\n", result);
            break;
        }
        case COMMAND_TYPE::HELP:
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