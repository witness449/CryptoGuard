#include "cmd_options.h"
#include <gtest/gtest.h>
#include <stdexcept>

// Позитивный тест, что аргумент --help работает правильно
TEST(cmd_options_test, helpOption) {
    CryptoGuard::ProgramOptions po;
    std::array<const char *, 2> argv;
    argv[0] = "filepath";
    argv[1] = "--help";
    ASSERT_NO_THROW(po.Parse(argv.size(), const_cast<char **>(argv.data())));
}

// Позитивный тест для сценария использования аргументов для шифрования
TEST(cmd_options_test, encryptCommand) {
    CryptoGuard::ProgramOptions po;
    std::array<const char *, 9> argv;
    argv[0] = "filepath";
    argv[1] = "-i";
    argv[2] = "input.txt";
    argv[3] = "-o";
    argv[4] = "output.txt";
    argv[5] = "-p";
    argv[6] = "1234";
    argv[7] = "--command";
    argv[8] = "encrypt";
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
    char first[] = "filepath";
    char second[] = "-i";
    char third[] = "input.txt";
    char fourth[] = "-o";
    char fifth[] = "output.txt";
    char sixth[] = "-p";
    char seventh[] = "1234";
    char eighth[] = "--command";
    char ninth[] = "encryp";
    std::array<char *, 9> argv = {first, second, third, fourth, fifth, sixth, seventh, eighth, ninth};
    ASSERT_THROW(po.Parse(argv.size(), const_cast<char **>(argv.data())), std::runtime_error);
}

// Негативный тест, проверка того что аргументов командной строки меньше требуемых
TEST(cmd_options_test, argsLessThanNecessary) {
    CryptoGuard::ProgramOptions po;
    char first[] = "filepath";
    char second[] = "-i";
    char third[] = "input.txt";
    char fourth[] = "-o";
    char fifth[] = "output.txt";
    char sixth[] = "-p";
    char seventh[] = "1234";
    std::array<char *, 7> argv = {first, second, third, fourth, fifth, sixth, seventh};
    int argc = sizeof(argv) / sizeof(char *);
    ASSERT_THROW(po.Parse(argv.size(), const_cast<char **>(argv.data())), std::runtime_error);
}

// Негавтивный тест, проверка использованяи аргумента --help с дополнительными аргументами
TEST(cmd_options_test, wrongHelpOptionUsing) {
    CryptoGuard::ProgramOptions po;
    char first[] = "filepath";
    char second[] = "--help";
    char third[] = "input.txt";
    char fourth[] = "-o";
    char fifth[] = "output.txt";
    char sixth[] = "-p";
    char seventh[] = "1234";
    char eighth[] = "--command";
    char ninth[] = "encrypt";
    std::array<char *, 9> argv = {first, second, third, fourth, fifth, sixth, seventh, eighth, ninth};
    ASSERT_THROW(po.Parse(argv.size(), const_cast<char **>(argv.data())), std::runtime_error);
}

// Негативный тест, проверка использования невалидных аргументов
TEST(cmd_options_test, wrongNames) {
    CryptoGuard::ProgramOptions po;
    char first[] = "one";
    char second[] = "--two";
    char third[] = "three";
    char fourth[] = "-f";
    char fifth[] = "five";
    char sixth[] = "-six";
    char seventh[] = "seven";
    char eighth[] = "--eight";
    char ninth[] = "encrypt";
    std::array<char *, 9> argv = {first, second, third, fourth, fifth, sixth, seventh, eighth, ninth};
    int argc = sizeof(argv) / sizeof(char *);
    ASSERT_THROW(po.Parse(argv.size(), const_cast<char **>(argv.data())), boost::program_options::error);
}