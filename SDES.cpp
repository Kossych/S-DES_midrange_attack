#include "SDES.h"

const char* plainTextPATH = "D:\\UniversityLabs\\4C2S\\S-DES_midrange_attack\\Texts1\\plaintext.txt";
const char* _encryptPATH = "D:\\UniversityLabs\\4C2S\\S-DES_midrange_attack\\Texts1\\_encrypt.txt";
const char* encryptPATH = "D:\\UniversityLabs\\4C2S\\S-DES_midrange_attack\\Texts1\\encrypt.txt";
const char* _decryptPATH = "D:\\UniversityLabs\\4C2S\\S-DES_midrange_attack\\Texts1\\_decrypt.txt";
const char* decryptPATH = "D:\\UniversityLabs\\4C2S\\S-DES_midrange_attack\\Texts1\\decrypt.txt";

const char* plainText2PATH = "D:\\UniversityLabs\\4C2S\\S-DES_midrange_attack\\Texts2\\plaintext.txt";
const char* _encrypt2PATH = "D:\\UniversityLabs\\4C2S\\S-DES_midrange_attack\\Texts2\\_encrypt.txt";
const char* encrypt2PATH = "D:\\UniversityLabs\\4C2S\\S-DES_midrange_attack\\Texts2\\encrypt.txt";
const char* _decrypt2PATH = "D:\\UniversityLabs\\4C2S\\S-DES_midrange_attack\\Texts2\\_decrypt.txt";
const char* decrypt2PATH = "D:\\UniversityLabs\\4C2S\\S-DES_midrange_attack\\Texts2\\decrypt.txt";

unsigned int GetRow(unsigned int Half)
{
    return((Half & 8)>>2)|(Half & 1);
}

unsigned int GetColumn(unsigned int Half)
{
    return (Half & 6)>>1;
}

S_DES_Key::S_DES_Key(std::bitset<10>& Key)
{
    std::bitset<10> P_Key = PermutationKey10(Key);
    std::bitset<5> LeftKey = P_Key.to_ulong(),
                RightKey = (P_Key.to_ulong()>>5);
    for(int i = 1; i <= 2; i++)
    {
        LeftKey = LeftShift(LeftKey, i);
        RightKey = LeftShift(RightKey, i);
        RoundKeys[i - 1] = E_PermutationKey8(LeftKey, RightKey);
    }
}

std::bitset<10> S_DES_Key::PermutationKey10(std::bitset<10>& Key) 
{
    std::bitset<10> PKey;
    for(int i = 0; i < 10; i++)
    {
        PKey[i] = Key[Permutation10[i]];
    }
    return PKey;
}


std::bitset<5> S_DES_Key::LeftShift(std::bitset<5>&HalfKey,int shift)
{
    std::bitset<5> ShiftBit = ((HalfKey.to_ulong() & (~((unsigned long)(~0) << shift))) << (5 - shift));
    HalfKey>>=shift;
    HalfKey|=ShiftBit;
    return HalfKey;
}

std::bitset<8> S_DES_Key::E_PermutationKey8(std::bitset<5>& LeftKey, std::bitset<5>& RightKey)
{
    std::bitset<10> Key = LeftKey.to_ulong() | (RightKey.to_ulong() << 5);
    std::bitset<8> RoundKey;
    for(int i = 0; i < 8; i++)
    {
        RoundKey[i] = Key[CompressionPermutation[i]];
    }
    return RoundKey;
}

std::bitset<8> S_DES_Key::GetRoundKey(int index)
{
    return RoundKeys[index];
}

std::ostream& operator <<(std::ostream &out, S_DES_Key &Keys)
{
    out<<Keys.RoundKeys[0]<<std::endl<<Keys.RoundKeys[1]<<std::endl;
    return out;
}

S_DES::S_DES(std::bitset<8>& _text)
{
    for(int i = 0; i < 8; i++)
    {
        text[i] = _text[i];
    }
}

S_DES& S_DES::operator=(S_DES& copy)
{
    for(int i = 0; i < 8; i++)
    {
        text[i] = copy.text[i];
    }
    return *this;
}

unsigned char S_DES::GetSymbol()
{
    return (text.to_ulong());
}

std::bitset<4> S_DES::Fk(std::bitset<4> &RightBits, const std::bitset<8>& RoundKey)
{
    std::bitset<8> E_Bits;
    for(int i = 0; i < 8; i++)
    {
        E_Bits[i] = RightBits[ExtensionPermutation[i]];
    }
    E_Bits ^= RoundKey;
    std::bitset<4> SBits = SBlock(E_Bits);
    std::bitset<4> F_Result;
    for(int i = 0; i < 4; i++)
    {
        F_Result[i] = SBits[Permutation4[i]];
    }
    return F_Result;
}


std::bitset<4> S_DES::SBlock(std::bitset<8>& Bits)
{
    unsigned int leftHalf = Bits.to_ulong() & 0xF;
    unsigned int rightHalf = ((Bits.to_ulong() & 0xF0)>>4);
    std::bitset<4> SBits(S_Block1[GetRow(leftHalf)][GetColumn(leftHalf)] | (S_Block2[GetRow(rightHalf)][GetColumn(rightHalf)] << 2));
    return SBits;
}

S_DES& S_DES::Encrypt(S_DES_Key& Key)
{
    std::bitset<8> IP;
    for(int i = 0; i < 8; i++)
    {
        IP[i] = text[InitialPermutation[i]];
    }

    std::bitset<4> leftHalf = IP.to_ulong();
    std::bitset<4> rightHalf = IP.to_ulong() >> 4;

    leftHalf ^= Fk(rightHalf, Key.GetRoundKey(0));

    std::bitset<4> tmp = leftHalf;
    leftHalf = rightHalf;
    rightHalf = tmp;

    leftHalf ^= Fk(rightHalf, Key.GetRoundKey(1));

    std::bitset<8> FP = (leftHalf.to_ulong() | (rightHalf.to_ulong() << 4));
    for(int i = 0; i < 8; i++)
    {
        text[i] = FP[FinalPermutation[i]];
    }
    return *this;
}

S_DES& S_DES::Decrypt(S_DES_Key& Key)
{
    std::bitset<8> IP;
    for(int i = 0; i < 8; i++)
    {
        IP[i] = text[InitialPermutation[i]];
    }

    std::bitset<4> leftHalf = IP.to_ulong();
    std::bitset<4> rightHalf = IP.to_ulong() >> 4;

    leftHalf ^= Fk(rightHalf, Key.GetRoundKey(1));

    std::bitset<4> tmp = leftHalf;
    leftHalf = rightHalf;
    rightHalf = tmp;

    leftHalf ^= Fk(rightHalf, Key.GetRoundKey(0));
    std::bitset<8> FP = (leftHalf.to_ulong() | (rightHalf.to_ulong() << 4));
    for(int i = 0; i < 8; i++)
    {
        text[i] = FP[FinalPermutation[i]];
    }
    return *this;
}

std::ostream& operator <<(std::ostream &out, S_DES &Text)
{
    out<<Text.text<<std::endl;
    return out;
}

bool S_DES::operator ==(S_DES&bit)
{
    return (text == bit.text);
}

bool S_DES::operator !=(S_DES&bit)
{
    return ~(text == bit.text);
}

void Encrypt(std::ifstream& fin, std::ofstream& fout, S_DES_Key& key)
{
    char s;
    while(fin.get(s))
    {
        std::bitset<8> bits(s);
        S_DES s_des(bits);
        s_des.Encrypt(key);
        fout<<s_des.GetSymbol();
    
    }
}

void Decrypt(std::ifstream& fin, std::ofstream& fout, S_DES_Key& key)
{
    char s;
    while(fin.get(s))
    {
        std::bitset<8> bits(s);
        S_DES s_des(bits);
        s_des.Decrypt(key);
        fout<<s_des.GetSymbol();
    
    }
}

void Double_S_DES(std::bitset<10>& key, std::bitset<10>& key2)
{
    S_DES_Key s_des_key(key);
    S_DES_Key s_des_key2(key2);
    std::ifstream fin;
    std::ofstream fout;
    fin.open(plainTextPATH);
    fout.open(_encryptPATH);
    Encrypt(fin, fout, s_des_key);
    fin.close();
    fout.close();
    fin.open(_encryptPATH);
    fout.open(encryptPATH);
    Encrypt(fin, fout, s_des_key2); 
    fin.close();
    fout.close();

    fin.open(encryptPATH);
    fout.open(_decryptPATH);
    Decrypt(fin, fout, s_des_key2); 
    fin.close();
    fout.close();

    fin.open(_decryptPATH);
    fout.open(decryptPATH);
    Decrypt(fin, fout, s_des_key); 
    fin.close();
    fout.close();
}

void Double_S_DES2(std::bitset<10>& key, std::bitset<10>& key2)
{
    S_DES_Key s_des_key(key);
    S_DES_Key s_des_key2(key2);
    std::ifstream fin;
    std::ofstream fout;
    fin.open(plainText2PATH);
    fout.open(_encrypt2PATH);
    Encrypt(fin, fout, s_des_key);
    fin.close();
    fout.close();
    fin.open(_encrypt2PATH);
    fout.open(encrypt2PATH);
    Encrypt(fin, fout, s_des_key2); 
    fin.close();
    fout.close();

    fin.open(encrypt2PATH);
    fout.open(_decrypt2PATH);
    Decrypt(fin, fout, s_des_key2); 
    fin.close();
    fout.close();

    fin.open(_decrypt2PATH);
    fout.open(decrypt2PATH);
    Decrypt(fin, fout, s_des_key); 
    fin.close();
    fout.close();
}

std::pair<unsigned long, unsigned long> MidRangeAttack(const char* plaintextPATH_arg, const char* encryptPATH_arg, unsigned long key1 = 0)
{
    std::ifstream plaintext;
    std::ifstream encrypt;
    plaintext.open(plaintextPATH_arg);
    encrypt.open(encryptPATH_arg); 
     
    if(!plaintext.is_open() || !encrypt.is_open())
    {
        throw;
    }
    unsigned long key2 = 1;
    char plaintext_symbol = 0;
    char encrypt2_symbol = 0;
    while(key1 <= 0x3ff)
    {
        key2 = 1;
        key1++;
        std::bitset<10> bits1(key1);
        S_DES_Key Key1(bits1);
        while(key2 <= 0x3ff)
        {
            plaintext.seekg(0, std::ios_base::beg);
            encrypt.seekg(0, std::ios_base::beg);
            std::bitset<10> bits2(key2);
            S_DES_Key Key2(bits2);
            while(!plaintext.eof() && !encrypt.eof())
            {
                plaintext.get(plaintext_symbol);
                encrypt.get(encrypt2_symbol);
                std::bitset<8> e_bits(plaintext_symbol);
                std::bitset<8> d_bits(encrypt2_symbol);
                S_DES e(e_bits);
                S_DES d(d_bits);
                e.Encrypt(Key1);
                d.Decrypt(Key2);

                if(!(e== d)) break;
            }

            if(plaintext.eof() || encrypt.eof())
            { 
                plaintext.close();
                encrypt.close();
                return std::pair(key1, key2);
            }

            key2++;

        }
    }
    plaintext.close();
    encrypt.close();
    return std::pair(key1, key2);
}

bool CheckPairKey(const char* plaintextPATH_arg, const char* encryptPATH_arg, std::pair<unsigned long, unsigned long> pairKey)
{
    std::ifstream plaintext;
    std::ifstream encrypt;
    plaintext.open(plaintextPATH_arg);
    encrypt.open(encryptPATH_arg); 
     
    if(!plaintext.is_open() || !encrypt.is_open())
    {
        throw;
    }

    char plaintext_symbol;
    char encrypt2_symbol;
    std::bitset<10> bits1(pairKey.first);
    std::bitset<10> bits2(pairKey.second);
    S_DES_Key key1(bits1);
    S_DES_Key key2(bits2);
    while(!plaintext.eof() && !encrypt.eof())
    {
        plaintext.get(plaintext_symbol);
        encrypt.get(encrypt2_symbol);
        std::bitset<8> e_bits(plaintext_symbol);
        std::bitset<8> d_bits(encrypt2_symbol);
        S_DES e(e_bits);
        S_DES d(d_bits);
        e.Encrypt(key1);
        d.Decrypt(key2);
        if(!(e == d))
        {
            plaintext.close();
            encrypt.close();
            return false;
        }
    }

    plaintext.close();
    encrypt.close();
    return true;


}


int main()
{
    std::bitset<10> key(253);
    std::bitset<10> key2(642);
    Double_S_DES(key, key2);
    Double_S_DES2(key, key2);

    std::pair<unsigned long, unsigned long> keys;

    keys.first = 0;
    while(keys.first <= 0x3ff)
    {
        unsigned int key2 = keys.first;
        keys = MidRangeAttack(plainTextPATH, encryptPATH, key2);
        std::cout<<"Possible key pair: "<<keys.first<<" "<<keys.second<<std::endl;
        if(CheckPairKey(plainText2PATH, encrypt2PATH, keys))
        {
            std::cout<<"Key pair found "<<keys.first<<" "<< keys.second<<std::endl;
            break;
        }
   }
  //std::cout<<CheckPairKey(plainText2PATH, encrypt2PATH, std::pair(253,642));

 

}