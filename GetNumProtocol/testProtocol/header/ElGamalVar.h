#include <NTL/ZZ.h>
#include <NTL/ZZ_pXFactoring.h>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <vector>

//之前未加域名空间时，会出现找不到vector的问题
using namespace std;
using namespace NTL;

#ifndef _ElGAMALVAR_H
#define _ELGAMALVAR_H

class ElGamalVar {
    public:
    /* Completely generate everything, from scratch */
    //生成元，私钥，公钥份额（公开），
    ElGamalVar(NTL::ZZ g, NTL::ZZ N, int number, long keyLength, NTL::ZZ& h_partial);

    //这里的number是进行加密的密文数
    void Encrypt(int number, vector<int> m, NTL::ZZ* pair1, NTL::ZZ* pair2, NTL::ZZ h, int x);
    //生成加密对:number：所要进行加密的元素个数（全集中的元素个数）;m：隐私输入集合;pair1：数组对中第一个元素的数组;pair2：数组对中第二个元素的数组
    
    //得到该密文对应的解密份额
    void getDe_partial(NTL::ZZ c_pair1, NTL::ZZ& de_paitial);

    //使用自己的解密份额以及对方的解密份额进行解密
    void Decrypt(NTL::ZZ& plaintext, NTL::ZZ c_pair2, NTL::ZZ de_partial1, NTL::ZZ de_partial2);

    void plainMul(NTL::ZZ pair1, NTL::ZZ pair2, int num, NTL::ZZ &cs_pair1, NTL::ZZ &cs_pair2);

    void plainAdd(NTL::ZZ c_pair11, NTL::ZZ c_pair12, NTL::ZZ c_pair21, NTL::ZZ c_pair22, NTL::ZZ &cs_pair1, NTL::ZZ &cs_pair2);

    void getCom_Ciresult(NTL::ZZ c_pair1, NTL::ZZ c_pair2, int code, NTL::ZZ &result1, NTL::ZZ &result2);

    void mul_input(NTL::ZZ c_pair1, NTL::ZZ c_pair2, NTL::ZZ &cs_pair1, NTL::ZZ &cs_pair2);

    void step_45(NTL::ZZ &cs_1, NTL::ZZ &cs_2, NTL::ZZ cs1_1, NTL::ZZ cs1_2, NTL::ZZ SComResult1, NTL::ZZ SComResult2, NTL::ZZ TComResult1, NTL::ZZ TComResult2);

    

    NTL::ZZ g ,h, N, exp_N;
        
    private:
    /* modulus = pq, where p and q are primes */
    NTL::ZZ h_partial;
    NTL::ZZ* randNum;
    int k;  //私钥
    int x;  //隐私数据
};

#endif
void GenPrimePair(NTL::ZZ& p, NTL::ZZ& q, long keyLength); 
