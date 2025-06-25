#include "cmd_options.h"
#include <iostream>
#include <stdexcept>
#include <string_view>

namespace CryptoGuard {

// Вынесение статической константы в cpp файл
const std::unordered_map<std::string_view, ProgramOptions::COMMAND_TYPE> ProgramOptions::commandMapping_ = {
    {"encrypt", ProgramOptions::COMMAND_TYPE::ENCRYPT},
    {"decrypt", ProgramOptions::COMMAND_TYPE::DECRYPT},
    {"checksum", ProgramOptions::COMMAND_TYPE::CHECKSUM},
};

// Реализация метода соответсвия строки и команды типа enum COMMAND_TYPE
ProgramOptions::COMMAND_TYPE ProgramOptions::Mapping(std::string_view tok) {
    auto it = commandMapping_.find(tok);
    if (it != commandMapping_.end()) {
        return it->second;
    } else {
        return COMMAND_TYPE::NONE;
    }
}

void ProgramOptions::checkCommand(ProgramOptions::COMMAND_TYPE comand) {
    if (comand == ProgramOptions::COMMAND_TYPE::NONE) {
        throw(std::runtime_error{"Please use help option"});
    }
}

// Конструктор включает в себя добавление аргументов командной строки
ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    // clang-format off
    desc_.add_options()("help,h", "Produce help message")
                       ("input,i", po::value<std::string>(&inputFile_), "Input filepath")
                       ("output,o", po::value<std::string>(&outputFile_), "Output filepath")
                       ("password,p", po::value<std::string>(&password_), "Encrypt/decrypt password")
                       ("command", po::value<ProgramOptions::COMMAND_TYPE>(&command_)->notifier(checkCommand), "Command: encrypt, decrypt, checksum");
    //clang-format on
}

ProgramOptions::~ProgramOptions() = default;

// Парсинг аргументов командной строки
void ProgramOptions::Parse(int argc, char *argv[]) {
    try {
        po::store(po::parse_command_line(argc, argv, desc_), vm);
        po::notify(vm);

        if (vm.count("help") && vm.size() == 1) {
            std::cout << desc_ << std::endl;
        } else if (vm.count("input") && vm.count("output") && vm.count("password") && vm.count("command") &&
                   command_ != COMMAND_TYPE::CHECKSUM) {
        } else if (vm.count("input") && command_ == COMMAND_TYPE::CHECKSUM && !vm.count("output") &&
                   !vm.count("password")) {
        } else {
            throw(std::runtime_error{"Please use help option"});
        }

        
    } catch (const std::exception &e) {
        throw;
    }
}

}  // namespace CryptoGuard
