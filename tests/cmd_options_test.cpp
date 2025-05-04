#include <gtest/gtest.h>
#include "cmd_options.h"

// Инициализация объекта проверяемого класса
class cmd_options_test : public testing::Test {
    CryptoGuard::ProgramOptions *po;

public:
    CryptoGuard::ProgramOptions* GetPo(){return po;} 
    void SetUp() { po = new CryptoGuard::ProgramOptions(); } 
    void TearDown() { delete po; } 
  };

// Позитивный тест, что аргумент --help работает правильно
TEST_F(cmd_options_test, helpOption){
    char first[]="filepath";
    char second[]="--help";
    char* argv[]={first, second};
    int argc=sizeof(argv)/sizeof(char*);
    EXPECT_EQ(GetPo()->Parse(argc, argv), true);
}

//Позитивный тест для сценария использования аргументов для шифрования
TEST_F(cmd_options_test, encryptCommand){
    char first[]="filepath";
    char second[]="-i";
    char third[]="input.txt";
    char fourth[]="-o";
    char fifth[]="output.txt";
    char sixth[]="-p";
    char seventh[]="1234";
    char eighth[]="--command";
    char ninth[]="encrypt";
    char* argv[]={first, second, third, fourth, fifth, sixth, seventh, eighth, ninth};
    int argc=sizeof(argv)/sizeof(char*);
    EXPECT_EQ(GetPo()->Parse(argc, argv), true);
}

//Негативный тест. проверка на опечатку в команде 
TEST_F(cmd_options_test, encryptCommandWithMistake){
    char first[]="filepath";
    char second[]="-i";
    char third[]="input.txt";
    char fourth[]="-o";
    char fifth[]="output.txt";
    char sixth[]="-p";
    char seventh[]="1234";
    char eighth[]="--command";
    char ninth[]="encryp";
    char* argv[]={first, second, third, fourth, fifth, sixth, seventh, eighth, ninth};
    int argc=sizeof(argv)/sizeof(char*);
    EXPECT_EQ(GetPo()->Parse(argc, argv), false);
}

//Негативный тест, проверка того что аргументов командной строки меньше требуемых
TEST_F(cmd_options_test, argsLessThanNecessary){
    char first[]="filepath";
    char second[]="-i";
    char third[]="input.txt";
    char fourth[]="-o";
    char fifth[]="output.txt";
    char sixth[]="-p";
    char seventh[]="1234";
    char* argv[]={first, second, third, fourth, fifth, sixth, seventh};
    int argc=sizeof(argv)/sizeof(char*);
    EXPECT_EQ(GetPo()->Parse(argc, argv), false);
}

//Негавтивный тест, проверка использованяи аргумента --help с дополнительными аргументами
TEST_F(cmd_options_test, wrongHelpOptionUsing){
    char first[]="filepath";
    char second[]="--help";
    char third[]="input.txt";
    char fourth[]="-o";
    char fifth[]="output.txt";
    char sixth[]="-p";
    char seventh[]="1234";
    char eighth[]="--command";
    char ninth[]="encrypt";
    char* argv[]={first, second, third, fourth, fifth, sixth, seventh, eighth, ninth};
    int argc=sizeof(argv)/sizeof(char*);
    EXPECT_EQ(GetPo()->Parse(argc, argv), false);
}

//Негативный тест, проверка использования невалидных аргументов
TEST_F(cmd_options_test, wrongNames){
    char first[]="one";
    char second[]="--two";
    char third[]="three";
    char fourth[]="-f";
    char fifth[]="five";
    char sixth[]="-six";
    char seventh[]="seven";
    char eighth[]="--eight";
    char ninth[]="encrypt";
    char* argv[]={first, second, third, fourth, fifth, sixth, seventh, eighth, ninth};
    int argc=sizeof(argv)/sizeof(char*);
    EXPECT_EQ(GetPo()->Parse(argc, argv), false);
}