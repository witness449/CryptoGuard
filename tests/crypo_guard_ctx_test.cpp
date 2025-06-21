#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <sstream>
#include <stdexcept>
#include <string>

// Инициализация объекта проверяемого класса
class crypto_guard_ctx__test : public testing::Test {
    std::unique_ptr<CryptoGuard::CryptoGuardCtx> ctx;

public:
    CryptoGuard::CryptoGuardCtx *GetCtx() { return ctx.get(); }
    void SetUp() { ctx = std::make_unique<CryptoGuard::CryptoGuardCtx>(); }
    void TearDown() {}
};

// Позитивный тест, что команда encrypt работает правильно
TEST_F(crypto_guard_ctx__test, encrypt) {
    std::stringstream inStream("test");
    std::stringstream outStream;
    std::ostringstream resStream;
    GetCtx()->EncryptFile(inStream, outStream, "23456");
    std::array<char, 16> res = {'\xc6', '\x12', '\x9a', '\xb4', '-', ':',    '\xc2', 'P',
                    'N',    '\x8f', ' ',    'p',    'E', '\xe3', '5',    '\x13'};
    resStream.write(res.data(), res.size());
    bool flag = true;
    flag = (resStream.str() == outStream.str());
    EXPECT_EQ(flag, true);

}

// Негативный тест, что команда encrypt вбрасывает исключение при некорректном состоянии потока вывода
TEST_F(crypto_guard_ctx__test, encryptAssert) {
    std::stringstream inStream("test");
    std::stringstream outStream(std::ios::in);
    ASSERT_THROW(GetCtx()->EncryptFile(inStream, outStream, "23456"), std::runtime_error);
}

// Позитивный тест, что команда encrypt работает с пустым паролем
TEST_F(crypto_guard_ctx__test, encryptEmptyPass) {
    std::stringstream inStream("test");
    std::stringstream outStream;
    std::ostringstream resStream;
    GetCtx()->EncryptFile(inStream, outStream, "");
    std::array<char, 16> res= {'\xab', '\x92', '\xc3', 'Y', '[', '$', '5', '[', ';', '\\', '\xab', '3', '\f', '}', '\xb2', '\x04'};
    resStream.write(res.data(), res.size());
    bool flag = true;
    flag = (resStream.str() == outStream.str());
    EXPECT_EQ(flag, true);
}

// Позитивный тест, что команда decrypt работает правильно
TEST_F(crypto_guard_ctx__test, decrypt) {
    std::stringstream inStream;
    std::stringstream outStream;

    std::array<char, 16> test = {'\xc6', '\x12', '\x9a', '\xb4', '-', ':',    '\xc2', 'P',
                     'N',    '\x8f', ' ',    'p',    'E', '\xe3', '5',    '\x13'};
    inStream.write(test.data(), test.size());
    GetCtx()->DecryptFile(inStream, outStream, "23456");

    bool flag = true;
    flag = (outStream.str() == "test");
    EXPECT_EQ(flag, true);
}

// Позитивный тест, что команда edcrypt работает с пустым паролем
TEST_F(crypto_guard_ctx__test, decryptEmptyPass) {
    std::stringstream inStream;
    std::stringstream outStream;

    std::array<char, 16> test  = {'\xab', '\x92', '\xc3', 'Y', '[',  '$', '5',    '[',
                     ';',    '\\',   '\xab', '3', '\f', '}', '\xb2', '\x04'};
    inStream.write(test.data(), test.size());
    GetCtx()->DecryptFile(inStream, outStream, "");

    bool flag = true;
    flag = (outStream.str() == "test");
    EXPECT_EQ(flag, true);
}

// Негативный тест, что команда decrypt вбрасывает исключение при отсутствии данных в потока ввода
TEST_F(crypto_guard_ctx__test, decryptEmptyStream) {
    std::stringstream inStream;
    std::stringstream outStream;
    ASSERT_THROW(GetCtx()->DecryptFile(inStream, outStream, ""), std::runtime_error);
}

// Позитивный тест, что команда checksum работает правильно
TEST_F(crypto_guard_ctx__test, checksumVal) {
    std::stringstream str("test");
    EXPECT_EQ(GetCtx()->CalculateChecksum(str), "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
}

// Позитивный тест, что контрольная сумма данных после шифрования и дешифрования одна и та же
TEST_F(crypto_guard_ctx__test, checkSumAfterEncrDecr) {
    std::string check = "checkConvert";
    std::stringstream encryptInput(check);
    std::stringstream encryptInputCopy(check);
    std::stringstream encryptOutput;
    std::stringstream decryptOutput;

    GetCtx()->EncryptFile(encryptInput, encryptOutput, "12345");
    std::string sum1 = GetCtx()->CalculateChecksum(encryptInputCopy);
    GetCtx()->DecryptFile(encryptOutput, decryptOutput, "12345");
    std::string sum2 = GetCtx()->CalculateChecksum(decryptOutput);

    EXPECT_EQ(sum1, sum2);
}

// Позитивный тест, что команда checksum работает корректно с пустой строкой
TEST_F(crypto_guard_ctx__test, checkSumEmptyStr) {
    std::stringstream str("");
    EXPECT_EQ(GetCtx()->CalculateChecksum(str), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}
