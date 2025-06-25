#include "cmd_options.h"
#include <gtest/gtest.h>
#include <stdexcept>

// Позитивный тест, что аргумент --help работает правильно
TEST(cmd_options_test, helpOption) {
    CryptoGuard::ProgramOptions po;
    std::array<const char *, 2> argv{"filepath", "--help"};
    ASSERT_NO_THROW(po.Parse(argv.size(), const_cast<char **>(argv.data())));
}

// Позитивный тест для сценария использования аргументов для шифрования
TEST(cmd_options_test, encryptCommand) {
    CryptoGuard::ProgramOptions po;
    std::array<const char *, 9> argv{"filepath", "-i",   "input.txt", "-o",     "output.txt",
                                     "-p",       "1234", "--command", "encrypt"};
    po.Parse(argv.size(), const_cast<char **>(argv.data()));
    CryptoGuard::ProgramOptions::COMMAND_TYPE command = po.GetCommand();
    std::string inFile = po.GetInputFile();
    std::string outFile = po.GetOutputFile();
    std::string password = po.GetPassword();
    bool res = (inFile == "input.txt" && outFile == "output.txt" && password == "1234" &&
                command == CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(res, true);
}

// Негативный тест. проверка на опечатку в команде
TEST(cmd_options_test, encryptCommandWithMistake) {
    CryptoGuard::ProgramOptions po;
    std::array<const char *, 9> argv = {"filepath", "-i",   "input.txt", "-o",    "output.txt",
                                        "-p",       "1234", "--command", "encryp"};
    ASSERT_THROW(po.Parse(argv.size(), const_cast<char **>(argv.data())), std::runtime_error);
}

// Негативный тест, проверка того что аргументов командной строки меньше требуемых
TEST(cmd_options_test, argsLessThanNecessary) {
    CryptoGuard::ProgramOptions po;
    std::array<const char *, 7> argv{"filepath", "-i", "input.txt", "-o", "output.txt", "-p", "1234"};
    ASSERT_THROW(po.Parse(argv.size(), const_cast<char **>(argv.data())), std::runtime_error);
}

// Негавтивный тест, проверка использованяи аргумента --help с дополнительными аргументами
TEST(cmd_options_test, wrongHelpOptionUsing) {
    CryptoGuard::ProgramOptions po;
    std::array<const char *, 9> argv{"filepath", "--help", "input.txt", "-o",     "output.txt",
                                     "-p",       "1234",   "--command", "encrypt"};
    ASSERT_THROW(po.Parse(argv.size(), const_cast<char **>(argv.data())), std::runtime_error);
}

// Негативный тест, проверка использования невалидных аргументов
TEST(cmd_options_test, wrongNames) {
    CryptoGuard::ProgramOptions po;
    std::array<const char *, 9> argv = {"one", "--two", "three", "-f", "five", "-six", "seven", "--eight", "encrypt"};
    ASSERT_THROW(po.Parse(argv.size(), const_cast<char **>(argv.data())), boost::program_options::error);
}