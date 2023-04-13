#include <cstdlib>
#include <time.h>
#include <vector>
#include <iostream>
#include <numeric>

#include "../header/ElGamalVar.h"

using namespace std;
using namespace NTL;


//生成元:g   N:模数   number:进行加密的数据量    keylongth：密钥长度     h_partial:部分公钥
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
void ElGamalVar::Encrypt(int number, vector<int> m, ElGamal_Cipher *pair, NTL::ZZ h, int x) {
    this->h = h;
    this->x = x;
    for(int i = 0; i < number; i++) {
        //直接使用定义对象时生成的随机数
        pair[i].fir = NTL::PowerMod(this->g, randNum[i], this->exp_N);
        pair[i].sec = ((1 + N*m[i]) * (NTL::PowerMod(this->h, randNum[i], this->exp_N))) % this->exp_N;
        //cout << "(" << pair1[i] << "," << pair2[i] << ")   "; 
    }
    
    //cout << "this->h:" << this->h << endl;
}

//输入为密文对的第一个元素
void ElGamalVar::getDe_partial(NTL::ZZ c_pair1, NTL::ZZ& de_paitial) {
    de_paitial = NTL::PowerMod(c_pair1, this->k, this->exp_N);
    //cout << "k:" << this->k << endl;  //k是正常的，但是de_partial为0
}

//对一个密文进行解密，需要双方分别公布解密密钥联合进行解密，因此一方需要另一方的解密份额和自己的解密份额
//密文对的第二个分量c_pair2=cpair.sec，de_partial是自己的解密份额，de_partial2是另一方提供的解密份额。
void ElGamalVar::Decrypt(NTL::ZZ& plaintext, NTL::ZZ c_pair2, NTL::ZZ de_partial1, NTL::ZZ de_partial2) {
    NTL::ZZ de = NTL::MulMod(de_partial1, de_partial2, this->exp_N); 
    
    // NTL::ZZ a = NTL::InvMod(ZZ(5), ZZ(31));
    // cout << "a:" << a << endl;


    //NTL::ZZ deInv = NTL::InvMod(de, exp_N);     //////无法求逆元，由于ElGamal的模数是素数，因此可以求逆元。需要保证g与N^2互素
    NTL::ZZ deInv = NTL::PowerMod(de, (this->N)-1, this->exp_N);
    NTL::ZZ temp = NTL::PowerMod(de, this->N, this->exp_N);
    //cout << "test: " << temp << endl;

    plaintext = (NTL::MulMod(c_pair2, deInv, this->exp_N)-1) / N;

    //cout << "plaintext:" << plaintext << endl;
}

//明文相乘对应密文求幂次，输入为一个密文对以及一个明文
void ElGamalVar::plainMul(ElGamal_Cipher pair, int num, ElGamal_Cipher& cs_pair) {
    int r = rand();
    NTL::ZZ cs_pair11 = PowerMod(pair.fir, num, this->exp_N);
    NTL::ZZ cs_pair12 = PowerMod(this->g, r, this->exp_N);
    cs_pair.fir = MulMod(cs_pair11, cs_pair12, this->exp_N);
    NTL::ZZ cs_pair21 = PowerMod(pair.sec, num, this->exp_N);
    NTL::ZZ cs_pair22 = PowerMod(this->h, r, this->exp_N);
    cs_pair.sec = MulMod(cs_pair21, cs_pair22, this->exp_N);         
}

//由于协议中该步骤都是在参与方内部进行或者需要进行验证，因此不需要添加随机数
//输入为两个密文对
void ElGamalVar::plainAdd(ElGamal_Cipher c_pair1, ElGamal_Cipher c_pair2, ElGamal_Cipher &cs_pair) {
    cs_pair.fir = NTL::MulMod(c_pair1.fir, c_pair2.fir, this->exp_N);
    cs_pair.sec = NTL::MulMod(c_pair1.sec, c_pair2.sec, this->exp_N);
}

//得到比较结果密文
void ElGamalVar::getCom_Ciresult(ElGamal_Cipher c_pair, int code, ElGamal_Cipher &result) {
    plainMul(c_pair, code, result);
}

//得到比较结果与隐私数据结合的密文结果
void ElGamalVar::mul_input(ElGamal_Cipher c_pair, ElGamal_Cipher &cs_pair) {
    //cout << "this->x:" << this->x << endl;
    plainMul(c_pair, this->x, cs_pair);
    //cout << "结合输入后密文：" << cs_pair1 << "," << cs_pair2 << endl;
}
//////////////////////
void ElGamalVar::step_45(ElGamal_Cipher &cs, ElGamal_Cipher cs1, ElGamal_Cipher SComResult, ElGamal_Cipher TComResult) {
    ElGamal_Cipher temp1, temp2;
    plainAdd(SComResult, TComResult, temp1);
    temp2.fir = temp1.fir;
    temp2.sec = NTL::MulMod(temp1.sec, 1-N, this->exp_N);
    //目前为止还是相等的，但是添加上-1之后无法正确解密，解决解密问题之后导致出现的是+1
    temp1.fir = NTL::PowerMod(temp2.fir, (this->N) - (this->x), this->exp_N);
    temp1.sec = NTL::PowerMod(temp2.sec, this->N - this->x, this->exp_N);
    

    //以上计算ca1
    //以下结合ca1,c1
    plainAdd(temp1, cs1, cs);  //此处明文相同，密文是不相同的
    //cout << "za+zb-1:" << cs_1 << "," << cs_2 << endl;

}
//将编码中的前index个密文对相加最终得到密文之和进行验证  
void ElGamalVar::add_GT_Code(ElGamal_Cipher *Pair, vector<int> U, NTL::ZZ Splaintext, ElGamal_Cipher &AC_result, int &index) {
    //Steven首先要得到解密得到的明文所在位置
    int num = U.size();
    int i = 0;
    while(U[i] != Splaintext) {
        ++i;
    }
    index = i;
    //cout << "密文所在位置：" << i;
    //而后将编码密文相乘(从后往前) 
    ElGamal_Cipher result, temp;
    temp.fir = Pair[i].fir;
    temp.sec = Pair[i].sec;
    for(++i; i < num; ++i) {
        plainAdd(temp, Pair[i], result);
        temp = result;
    }
    AC_result.fir = result.fir;
    AC_result.sec = result.sec;
}

bool ElGamalVar::if_equal_x(NTL::ZZ plaintext) {
    return plaintext == this->x;
}

//原本是用来选择paillier算法的随机数r
NTL::ZZ generateCoprimeNumber(const NTL::ZZ& n) {
    NTL::ZZ ret;
    while (true) {
        ret = RandomBnd(n);
        //随机数r属于Zn*，即r<n且与n互素
        if (NTL::GCD(ret, n) == 1) { return ret; }
    }
}

//生成p,q,n
void GenPrimePair(NTL::ZZ& p, NTL::ZZ& q, long keyLength) {
     while (true) {
        long err = 80;
        p = NTL::GenPrime_ZZ(keyLength/2, err); 
        q = NTL::GenPrime_ZZ(keyLength/2, err);
        while (p == q) {
            q = NTL::GenPrime_ZZ(keyLength/2, err);
        }
        NTL::ZZ n = p * q;
        NTL::ZZ phi = (p - 1) * (q - 1);
        if (NTL::GCD(n, phi) == 1 && (p % 4 == 3) && (q % 4 == 3) && NTL::GCD(p-1, q-1) == 2) 
            return;
    }
}

ZZ lcm(ZZ x, ZZ y)
{
  ZZ ans = (x * y) / NTL::GCD(x, y);
  return ans;
}

// 2轮通信，6次模指数
bool ZeroProof(ElGamalVar prover, ElGamalVar verifier, NTL::ZZ alpha, NTL::ZZ g,
               NTL::ZZ belta, NTL::ZZ h, const NTL::ZZ &N, int x) // x有可能是隐私输入也有可能是lambda，所以用ZZ
{
  long err = 80;
  NTL::ZZ p = N * N; // q|p-1
  // 由示证者执行Prover
  srand(time(0));
  int s = rand();
  NTL::ZZ a = PowerMod(g, s, p);
  NTL::ZZ b = PowerMod(h, s, p);
  NTL::ZZ e = (g + h + alpha + belta + a + b) % p;
  // cout << "a:" << a << endl << "b:" << b << endl;
  NTL::ZZ y = s + e * x; /////////////////不能模N！！！！！！！！！

  NTL::ZZ e1, a1, a11, a12, a13, b1, b11, b12, b13;
  a11 = PowerMod(g, y, p);
  a12 = PowerMod(alpha, e, p);
  a13 = InvMod(a12, p); // 求逆元
  a1 = MulMod(a11, a13, p);

  b11 = PowerMod(h, y, p);
  b12 = PowerMod(belta, e, p); // 正确
  b13 = InvMod(b12, p);
  b1 = MulMod(b11, b13, p); // g^(csx)

  // cout << "a1:" << a1 << endl << "b1:" << b1 << endl;
  e1 = (g + h + alpha + belta + a1 + b1) % p;

  if (e == e1)
  {
    // cout << "The ZeroProof success!" << endl;
    return 1;
  }
  else
  {
    cout << "The ZeroProof failed!" << endl;
    return 0;
  }
}

//input:隐私数据   U:全集
//求较大值是前为0，后为1
void Encode_GT(int input, vector<int> U, int &index, vector<int>& codes) {
    //在隐私数据一定是全集中元素的基础上，为了减少遍历次数，直接比较输入和集合元素进行编码
    //通用方式，首先假设codes中所有元素的初始值为0
    int i = 0;
    int length = U.size();

    while(i < length && U[i] < input) {
        codes[i] = 0;
        ++i;
    }
    index = i;
    //cout << "index: " << index << endl;
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




