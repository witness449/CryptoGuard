#include "cmd_options.h"
#include <gtest/gtest.h>
#include <memory>
#include <stdexcept>

// Инициализация объекта проверяемого класса
class cmd_options_test : public testing::Test {
    std::unique_ptr<CryptoGuard::ProgramOptions> po;

public:
    CryptoGuard::ProgramOptions *GetPo() { return po.get(); }
    void SetUp() { po = std::make_unique<CryptoGuard::ProgramOptions>(); }
    void TearDown() {}
};

// Позитивный тест, что аргумент --help работает правильно
TEST_F(cmd_options_test, helpOption) {
    std::array<const char *, 2> argv;
    argv[0] = "filepath";
    argv[1] = "--help";
    ASSERT_NO_THROW(GetPo()->Parse(argv.size(), const_cast<char **>(argv.data())));
}

// Позитивный тест для сценария использования аргументов для шифрования
TEST_F(cmd_options_test, encryptCommand) {
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
    GetPo()->Parse(argv.size(), const_cast<char **>(argv.data()));
    CryptoGuard::ProgramOptions::COMMAND_TYPE command = GetPo()->GetCommand();
    std::string inFile = GetPo()->GetInputFile();
    std::string outFile = GetPo()->GetOutputFile();
    std::string password = GetPo()->GetPassword();
    bool res = (inFile == "input.txt" && outFile == "output.txt" && password == "1234" &&
                command == CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(res, true);
}

// Негативный тест. проверка на опечатку в команде
TEST_F(cmd_options_test, encryptCommandWithMistake) {
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
    ASSERT_THROW(GetPo()->Parse(argv.size(), const_cast<char **>(argv.data())), std::runtime_error);
}

// Негативный тест, проверка того что аргументов командной строки меньше требуемых
TEST_F(cmd_options_test, argsLessThanNecessary) {
    char first[] = "filepath";
    char second[] = "-i";
    char third[] = "input.txt";
    char fourth[] = "-o";
    char fifth[] = "output.txt";
    char sixth[] = "-p";
    char seventh[] = "1234";
    std::array<char *, 7> argv = {first, second, third, fourth, fifth, sixth, seventh};
    int argc = sizeof(argv) / sizeof(char *);
    ASSERT_THROW(GetPo()->Parse(argv.size(), const_cast<char **>(argv.data())), std::runtime_error);
}

// Негавтивный тест, проверка использованяи аргумента --help с дополнительными аргументами
TEST_F(cmd_options_test, wrongHelpOptionUsing) {
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
    ASSERT_THROW(GetPo()->Parse(argv.size(), const_cast<char **>(argv.data())), std::runtime_error);
}

// Негативный тест, проверка использования невалидных аргументов
TEST_F(cmd_options_test, wrongNames) {
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
    ASSERT_THROW(GetPo()->Parse(argv.size(), const_cast<char **>(argv.data())), boost::program_options::error);
}