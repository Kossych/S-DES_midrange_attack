#ifndef SIMPLE_DES_H
#define SIMPLE_DES_H

#include <iostream>
#include <fstream>
#include <bitset>
#include <string>

const int S_Block1[4][4] = 
{
{1, 0, 3, 2},
{3, 2, 1, 0},
{0, 2, 1, 3},
{3, 1, 3, 2}
};

const int S_Block2[4][4] = 
{
{0, 1, 2, 3},
{2, 0, 1, 3},
{3, 0, 1, 0},
{2, 1, 0, 3}
};

const int ExtensionPermutation[8] =
{3, 0, 1, 2, 1, 2, 3, 0};

const int Permutation4[4] = 
{1, 3, 2, 0};

const int InitialPermutation[8] =
{1, 5, 2, 0, 3, 7, 4, 6};

const int FinalPermutation[8] = 
{3, 0, 2, 4, 6, 1, 7, 5};

const int CompressionPermutation[8] =
{5, 2, 6, 3, 7, 4, 9, 8};

const int Permutation10[10] = 
{2, 4, 1, 6, 3, 9, 0, 8, 7, 5};


class S_DES_Key
{
    private:
        std::bitset<8> RoundKeys[2];

        std::bitset<10> PermutationKey10(std::bitset<10>&);
        std::bitset<5> LeftShift(std::bitset<5>&,int);
        std::bitset<8> E_PermutationKey8(std::bitset<5>&, std::bitset<5>&);
    public:
        S_DES_Key(std::bitset<10>&);
        std::bitset<8> GetRoundKey(int);

        friend std::ostream & operator <<(std::ostream &, S_DES_Key &);

};


class S_DES
{
    private:
        std::bitset<8> text;

        std::bitset<4> Fk(std::bitset<4>&, const std::bitset<8>& RoundKey);
        std::bitset<4> SBlock(std::bitset<8>&);

    public:

        S_DES(std::bitset<8>&);
        S_DES& Encrypt(S_DES_Key&);
        S_DES& Decrypt(S_DES_Key&);

        S_DES& operator =(S_DES&);
        bool operator ==(S_DES&);
        bool operator !=(S_DES&);
        unsigned char GetSymbol();
        friend std::ostream & operator <<(std::ostream &, S_DES&);


};



#endif 