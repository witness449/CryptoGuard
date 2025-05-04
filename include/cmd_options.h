#pragma once

#include <boost/program_options.hpp>
#include <string>
#include <unordered_map>

namespace CryptoGuard {

class ProgramOptions {
public:
    ProgramOptions();
    ~ProgramOptions();

    enum class COMMAND_TYPE {
        ENCRYPT,
        DECRYPT,
        CHECKSUM,
        NONE
    };

    //Перегрузка оператора >> для записи значения аргумента в переменную типа Enum
    friend std::istream& operator>>(std::istream& is, COMMAND_TYPE& command_){
        std::string tok;
        is >> tok;
        command_=ProgramOptions::Mapping(tok);
           
        return is;
    }

    bool Parse(int argc, char *argv[]);

    COMMAND_TYPE GetCommand() const { return command_; }
    std::string GetInputFile() const { return inputFile_; }
    std::string GetOutputFile() const { return outputFile_; }
    std::string GetPassword() const { return password_; }

    //Метод соответсвия строки tok переменной типа enum COMMAND_TYPE
    static COMMAND_TYPE Mapping(std::string tok);

private:
    COMMAND_TYPE command_;
    //Словарь сделан статическим, чтобы к нему был доступ из friend функции перегрузки оператора >>
    static const std::unordered_map<std::string_view, COMMAND_TYPE> commandMapping_; 
 
    std::string inputFile_;
    std::string outputFile_;
    std::string password_;

    boost::program_options::options_description desc_;
    boost::program_options::variables_map vm;
};

}  // namespace CryptoGuard
