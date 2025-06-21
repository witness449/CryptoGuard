#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <sstream>
#include <stdexcept>
#include <string>

// Позитивный тест, что команда encrypt работает правильно
TEST(crypto_guard_ctx__test, encrypt) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStream("test");
    std::stringstream outStream;
    std::ostringstream resStream;
    ctx.EncryptFile(inStream, outStream, "23456");
    std::array<char, 16> res = {'\xc6', '\x12', '\x9a', '\xb4', '-', ':',    '\xc2', 'P',
                                'N',    '\x8f', ' ',    'p',    'E', '\xe3', '5',    '\x13'};
    resStream.write(res.data(), res.size());
    EXPECT_EQ(resStream.str(), outStream.str());
}

// Негативный тест, что команда encrypt вбрасывает исключение при некорректном состоянии потока вывода
TEST(crypto_guard_ctx__test, encryptAssert) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStream("test");
    std::stringstream outStream(std::ios::in);
    ASSERT_THROW(ctx.EncryptFile(inStream, outStream, "23456"), std::runtime_error);
}

// Позитивный тест, что команда encrypt работает с пустым паролем
TEST(crypto_guard_ctx__test, encryptEmptyPass) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStream("test");
    std::stringstream outStream;
    std::ostringstream resStream;
    ctx.EncryptFile(inStream, outStream, "");
    std::array<char, 16> res = {'\xab', '\x92', '\xc3', 'Y', '[',  '$', '5',    '[',
                                ';',    '\\',   '\xab', '3', '\f', '}', '\xb2', '\x04'};
    resStream.write(res.data(), res.size());
    EXPECT_EQ(resStream.str(), outStream.str());
}

// Позитивный тест, что команда decrypt работает правильно
TEST(crypto_guard_ctx__test, decrypt) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStream;
    std::stringstream outStream;

    std::array<char, 16> test = {'\xc6', '\x12', '\x9a', '\xb4', '-', ':',    '\xc2', 'P',
                                 'N',    '\x8f', ' ',    'p',    'E', '\xe3', '5',    '\x13'};
    inStream.write(test.data(), test.size());
    ctx.DecryptFile(inStream, outStream, "23456");

    EXPECT_EQ(outStream.str(), "test");
}

// Позитивный тест, что команда edcrypt работает с пустым паролем
TEST(crypto_guard_ctx__test, decryptEmptyPass) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStream;
    std::stringstream outStream;

    std::array<char, 16> test = {'\xab', '\x92', '\xc3', 'Y', '[',  '$', '5',    '[',
                                 ';',    '\\',   '\xab', '3', '\f', '}', '\xb2', '\x04'};
    inStream.write(test.data(), test.size());
    ctx.DecryptFile(inStream, outStream, "");

    EXPECT_EQ(outStream.str(), "test");
}

// Негативный тест, что команда decrypt вбрасывает исключение при отсутствии данных в потока ввода
TEST(crypto_guard_ctx__test, decryptEmptyStream) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStream;
    std::stringstream outStream;
    ASSERT_THROW(ctx.DecryptFile(inStream, outStream, ""), std::runtime_error);
}

// Позитивный тест, что команда checksum работает правильно
TEST(crypto_guard_ctx__test, checksumVal) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream str("test");
    EXPECT_EQ(ctx.CalculateChecksum(str), "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
}

// Позитивный тест, что контрольная сумма данных после шифрования и дешифрования одна и та же
TEST(crypto_guard_ctx__test, checkSumAfterEncrDecr) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::string check = "checkConvert";
    std::stringstream encryptInput(check);
    std::stringstream encryptInputCopy(check);
    std::stringstream encryptOutput;
    std::stringstream decryptOutput;

    ctx.EncryptFile(encryptInput, encryptOutput, "12345");
    std::string sum1 = ctx.CalculateChecksum(encryptInputCopy);
    ctx.DecryptFile(encryptOutput, decryptOutput, "12345");
    std::string sum2 = ctx.CalculateChecksum(decryptOutput);

    EXPECT_EQ(sum1, sum2);
}

// Позитивный тест, что команда checksum работает корректно с пустой строкой
TEST(crypto_guard_ctx__test, checkSumEmptyStr) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream str("");
    EXPECT_EQ(ctx.CalculateChecksum(str), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}
