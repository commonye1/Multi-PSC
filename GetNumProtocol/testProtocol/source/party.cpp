#include "../header/paillier.h"
#include <cstdlib>
#include <time.h>
#include "party.h"
using namespace std;

//generator:生成元   modulus:模数N    number:生成的密文对数  u:解密份额   keylongth：密钥长度
Party::Party(NTL::ZZ &generator, NTL::ZZ &modulus, int number, NTL::ZZ &ds, long keyLength)
{
    //生成对应的paillier密钥对
    Paillier(generator, modulus, number, ds, keyLength);
}


//先找到隐私输入在全集中对应的位置，再构造对应的0序列和1序列，最后合并即可
void Party::Encode_GT(int input, vector<int> &U) {
    //在隐私数据一定是全集中元素的基础上，为了减少遍历次数，直接比较输入和集合元素进行编码
    //通用方式，首先假设codes中所有元素的初始值为0
    int i = 0;
    int length = U.size();
    while(i < length && U[i] < input) {
        ++i;
    }
    input_index = i;  //隐私输入在全集中的下标
    vector<int> code1(i, 1);
    vector<int> code0(length-i, 0);
    ////////////////////////////////////vector<int> code;
    merge(code0.begin(), code0.end(), code1.begin(), code1.end(), codes.begin());
    codes.insert(codes.begin(), code0.begin(), code0.end());
    codes.insert(codes.end(), code1.begin(), code1.end());
    
    //改进方式：
    //首先，假设全集就是从min~max的所有值，那么input在全集中的位置就是input-min
    /*
    int i = 0;
    int length = input - min + 1;
    while(i < length) {
        codes[i] = 1;
    }
    */
    cout << "Encode result:" << endl;
    for(i = 0; i < U.size(); ++i) {
        cout << codes[i] << " ";
    }
    cout << endl;
}

//用户对编码加密，返回的是公开的编码密文
void Party::encryptCode(NTL::ZZ* Enc_Code, int number) {
    for(int i = 0; i < number; ++i) {
        Enc_Code[i] = NTL::PowerMod(generator, message, modulus * modulus) *
        NTL::PowerMod(random, modulus, modulus * modulus);
    }
}
//计算比较结果密文，函数输入为另一方的编码密文和自己的隐私输入，输出为
void Party::Get_LT_Result(NTL::ZZ& EncResult, NTL::ZZ* Ano_Enc_Code) {
    //选择一个随机数ra
    srand(time(0));
    NTL::ZZ r = rand();  //rand()只剩成最多32比特的随机数
    NTL::ZZ exp_modulus = modulus*modulus;
    //ElGamal密码体制有两个密文
    EncResult.first = (NTL::ZZ PowerMod(Ano_Enc_Code[input_index].first, codes[input_index], exp_modulus) * NTL::ZZ MulMod(g, r, exp_modulus)) % (exp_modulus);
    EncResult.second = (NTL::ZZ PowerMod(Ano_Enc_Code[input_index].second, codes[input_index], exp_modulus) * NTL::ZZ MulMod(h, r, exp_modulus)) % (exp_modulus);    
}


