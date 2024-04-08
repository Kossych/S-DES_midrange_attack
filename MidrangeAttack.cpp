#include "SDES.h"
#include <fstream>

int main()
{
    std::bitset<10> key("1011001101");
    S_DES_Key s_des_key(key);
    std::ifstream fin;
    std::ofstream fout;
    fin.open("plaintext1.txt");
    fout.open("encrypt.txt");
    unsigned char s;
    while(fin>>s)
    {
        std::bitset<8> bits(s);
        S_DES s_des(bits);
        s_des.Encrypt(s_des_key);
        fout<<s_des.GetSymbol();
    }
    fin.close();
    fout.close();
}