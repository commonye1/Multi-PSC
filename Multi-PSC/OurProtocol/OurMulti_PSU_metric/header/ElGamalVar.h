#include <NTL/ZZ.h>
#include <NTL/ZZ_pXFactoring.h>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <vector>

//之前未加域名空间时，会出现找不到vector的问题
using namespace std;
using namespace NTL;

//定义ElGamal密文结构体，fir是第一分量，sec是第二分量
struct ElGamal_Cipher {
    NTL::ZZ fir;
    NTL::ZZ sec;
};


#ifndef _ElGAMALVAR_H
#define _ELGAMALVAR_H

class ElGamalVar {
    public:
    /* Completely generate everything, from scratch */
    //生成元，私钥，公钥份额（公开），
    ElGamalVar(NTL::ZZ g, NTL::ZZ N, int number, long keyLength, NTL::ZZ& h_partial);

    //这里的number是进行加密的密文数
    void Encrypt(int number, vector<int> m, ElGamal_Cipher *pair, NTL::ZZ h, int x);
    //生成加密对:number：所要进行加密的元素个数（全集中的元素个数）;m：隐私输入集合;pair：密文对数组
    
    //得到该密文对应的解密份额
    void getDe_partial(NTL::ZZ c_pair1, NTL::ZZ& de_paitial);

    //使用自己的解密份额以及对方的解密份额进行解密
    void Decrypt(NTL::ZZ& plaintext, NTL::ZZ c_pair2, NTL::ZZ de_partial1, NTL::ZZ de_partial2);

    void plainMul(ElGamal_Cipher pair, int num, ElGamal_Cipher& cs_pair);

    void plainAdd(ElGamal_Cipher c_pair1, ElGamal_Cipher c_pair2, ElGamal_Cipher &cs_pair);

    void getCom_Ciresult(ElGamal_Cipher c_pair, int code, ElGamal_Cipher &result);

    void mul_input(ElGamal_Cipher c_pair, ElGamal_Cipher &cs_pair);

    void step_45(ElGamal_Cipher &cs, ElGamal_Cipher cs1, ElGamal_Cipher SComResult, ElGamal_Cipher TComResult);

    void add_GT_Code(ElGamal_Cipher *Pair, vector<int> U, NTL::ZZ Splaintext, ElGamal_Cipher &AC_result, int &index);

    bool if_equal_x(NTL::ZZ plaintext);

    NTL::ZZ g ,h, N, exp_N;
    NTL::ZZ h_partial;
    int k;  //私钥    为了进行ZKP设为公开
    int index;

    private:
    /* modulus = pq, where p and q are primes */
    NTL::ZZ* randNum;
    int x;  //隐私数据
    
    
};
#endif
void GenPrimePair(NTL::ZZ& p, NTL::ZZ& q, long keyLength); 

