#include <cstdlib>
#include <time.h>
#include <vector>
#include <iostream>
#include <numeric>

#include "../header/ElGamalVar.h"

using namespace std;
using namespace NTL;

//生成元:g   N:模数   number:进行加密的数据量    keylongth：密钥长度
ElGamalVar::ElGamalVar(NTL::ZZ g, NTL::ZZ N, int number, long keyLength, NTL::ZZ& h_partial)
{
    /* Length in bits. */
    this->exp_N = N*N;
    //cout << "p:" << p << "  q:" << q << endl;
    
    //srand(time(0));///////////////////////////k取随机数有问题
    k = rand();
    cout << "k:" << k << endl;
    h_partial = NTL::PowerMod(g, k, this->exp_N);
    //(1 + k*N) % exp_N;
    randNum = new NTL::ZZ[number];
    for(int i = 0; i < number; i++) {
        srand(i+1);
        randNum[i] = rand();  //rand()只剩成最多32比特的随机数
        //cout << "randNum:" << randNum[i] << endl; 
    }
    this->g = g;
    this->N = N;
    // cout << "exp_N:" << this->exp_N << endl;
    // cout << "N:" << this->N << endl;
    // cout << "g:" << this->g << endl;
    
}

//对多个数据进行加密
void ElGamalVar::Encrypt(int number, vector<int> m, NTL::ZZ* pair1, NTL::ZZ* pair2, NTL::ZZ h, int x) {
    this->h = h;
    this->x = x;
    for(int i = 0; i < number; i++) {
        //直接使用定义对象时生成的随机数
        pair1[i] = NTL::PowerMod(this->g, randNum[i], this->exp_N);
        pair2[i] = ((1 + N*m[i]) * (NTL::PowerMod(this->h, randNum[i], this->exp_N))) % this->exp_N;
        //cout << "(" << pair1[i] << "," << pair2[i] << ")   "; 
    }
    
    //cout << "this->h:" << this->h << endl;
}

void ElGamalVar::getDe_partial(NTL::ZZ c_pair1, NTL::ZZ& de_paitial) {
    de_paitial = NTL::PowerMod(c_pair1, this->k, this->exp_N);
    //cout << "k:" << this->k << endl;  //k是正常的，但是de_partial为0
}

//对一个密文进行解密，需要双方分别公布解密密钥联合进行解密，因此一方需要另一方的解密份额和自己的解密份额
//密文对c，de_partial是自己的解密份额，de_partial2是另一方提供的解密份额。
void ElGamalVar::Decrypt(NTL::ZZ& plaintext, NTL::ZZ c_pair2, NTL::ZZ de_partial1, NTL::ZZ de_partial2) {
    NTL::ZZ de = NTL::MulMod(de_partial1, de_partial2, this->exp_N); 
    
    // NTL::ZZ a = NTL::InvMod(ZZ(5), ZZ(31));
    // cout << "a:" << a << endl;


    //NTL::ZZ deInv = NTL::InvMod(de, exp_N);     //////无法求逆元，由于ElGamal的模数是素数，因此可以求逆元。需要保证g与N^2互素
    NTL::ZZ deInv = NTL::PowerMod(de, (this->N)-1, this->exp_N);
    NTL::ZZ temp = NTL::PowerMod(de, this->N, this->exp_N);
    cout << "test: " << temp << endl;

    plaintext = (NTL::MulMod(c_pair2, deInv, this->exp_N)-1) / N;

    cout << "plaintext:" << plaintext << endl;
}

//明文相乘
void ElGamalVar::plainMul(NTL::ZZ pair1, NTL::ZZ pair2, int num, NTL::ZZ& cs_pair1, NTL::ZZ& cs_pair2) {
    int r = rand();
    NTL::ZZ cs_pair11 = PowerMod(pair1, num, this->exp_N);
    NTL::ZZ cs_pair12 = PowerMod(this->g, r, this->exp_N);
    cs_pair1 = MulMod(cs_pair11, cs_pair12, this->exp_N);
    NTL::ZZ cs_pair21 = PowerMod(pair2, num, this->exp_N);
    NTL::ZZ cs_pair22 = PowerMod(this->h, r, this->exp_N);
    cs_pair2 = MulMod(cs_pair21, cs_pair22, this->exp_N);         
}

//由于协议中该步骤都是在参与方内部进行或者需要进行验证，因此不需要添加随机数
void ElGamalVar::plainAdd(NTL::ZZ c_pair11, NTL::ZZ c_pair12, NTL::ZZ c_pair21, NTL::ZZ c_pair22, NTL::ZZ &cs_pair1, NTL::ZZ &cs_pair2) {
    cs_pair1 = NTL::MulMod(c_pair11, c_pair21, this->exp_N);
    cs_pair2 = NTL::MulMod(c_pair12, c_pair22, this->exp_N);
}

void ElGamalVar::getCom_Ciresult(NTL::ZZ c_pair1, NTL::ZZ c_pair2, int code, NTL::ZZ &result1, NTL::ZZ &result2) {
    plainMul(c_pair1, c_pair2, code, result1, result2);
} 

void ElGamalVar::mul_input(NTL::ZZ c_pair1, NTL::ZZ c_pair2, NTL::ZZ& cs_pair1, NTL::ZZ& cs_pair2) {
    //cout << "this->x:" << this->x << endl;
    plainMul(c_pair1, c_pair2, this->x, cs_pair1, cs_pair2);
    //cout << "结合输入后密文：" << cs_pair1 << "," << cs_pair2 << endl;
}

void ElGamalVar::step_45(NTL::ZZ &cs_1, NTL::ZZ &cs_2, NTL::ZZ cs1_1, NTL::ZZ cs1_2, NTL::ZZ SComResult1, NTL::ZZ SComResult2, NTL::ZZ TComResult1, NTL::ZZ TComResult2) {
    NTL::ZZ temp1_1, temp1_2, temp2_1, temp2_2;
    plainAdd(SComResult1, SComResult2, TComResult1, TComResult2, temp1_1, temp1_2);
    temp2_1 = temp1_1;
    temp2_2 = NTL::MulMod(temp1_2, 1-N, this->exp_N);
    //目前为止还是相等的，但是添加上-1之后无法正确解密，解决解密问题之后导致出现的是+1
    temp1_1 = NTL::PowerMod(temp2_1, (this->N) - (this->x), this->exp_N);
    temp1_2 = NTL::PowerMod(temp2_2, this->N - this->x, this->exp_N);
    

    //以上计算ca1
    //以下结合ca1,c1
    plainAdd(temp1_1, temp1_2, cs1_1, cs1_2, cs_1, cs_2);  //此处明文相同，密文是不相同的
    //cout << "za+zb-1:" << cs_1 << "," << cs_2 << endl;

}
  



