#include "cmd_options.h"
#include <iostream>

namespace CryptoGuard {

// Вынесение статической константы в cpp файл
const std::unordered_map<std::string_view, ProgramOptions::COMMAND_TYPE> ProgramOptions::commandMapping_ = {
    {"encrypt", ProgramOptions::COMMAND_TYPE::ENCRYPT},
    {"decrypt", ProgramOptions::COMMAND_TYPE::DECRYPT},
    {"checksum", ProgramOptions::COMMAND_TYPE::CHECKSUM},
};

// Реализация метода соответсвия строки и команды типа enum COMMAND_TYPE
ProgramOptions::COMMAND_TYPE ProgramOptions::Mapping(std::string tok) {
    auto it = commandMapping_.find(tok);
    if (it != commandMapping_.end()) {
        return it->second;
    } else {
        return COMMAND_TYPE::NONE;
    }
}

// Конструктор включает в себя добавление аргументов командной строки
ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()("help,h", "Produce help message")(
        "input,i", boost::program_options::value<std::string>(&inputFile_),
        "Input filepath")("output,o", boost::program_options::value<std::string>(&outputFile_), "Output filepath")(
        "password,p", boost::program_options::value<std::string>(&password_),
        "Encrypt/decrypt password")("command", boost::program_options::value<ProgramOptions::COMMAND_TYPE>(&command_),
                                    "Command: encrypt, decrypt, checksum");
}

ProgramOptions::~ProgramOptions() = default;

// Парсинг аргументов командной строки
bool ProgramOptions::Parse(int argc, char *argv[]) {
    try {
        boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc_), vm);
        boost::program_options::notify(vm);
        if (vm.count("help")) {
            std::cout << desc_ << std::endl;
            return true;
        } else if (vm.count("input") && vm.count("output") && vm.count("password") && vm.count("command") &&
                   command_ != COMMAND_TYPE::CHECKSUM) {
            return true;
        } else if (vm.count("input") && command_ == COMMAND_TYPE::CHECKSUM) {
            return true;
        } else {
            std::cout << "Please use help option " << std::endl;
            return false;
        }
    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return false;
    }
}

/*std::istream& operator>>(std::istream& is, ProgramOptions& po){
    std::string tok;
    is >> tok;
    po.command_=po.commandMapping_.at(tok);

    return is;
}*/

}  // namespace CryptoGuard
