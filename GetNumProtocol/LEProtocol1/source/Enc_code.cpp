#include <iostream>
#include <cstdlib>
#include <numeric>
#include <vector>
#include <algorithm>
#include <functional>

//#include "../header/ElGamalVar.h"   此时解决了类重定义的问题
#include "../source/ElGamalVar.cpp"

using namespace std;
using namespace NTL;

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
               NTL::ZZ belta, NTL::ZZ h, const NTL::ZZ &N, NTL::ZZ x) // x有可能是隐私输入也有可能是lambda，所以用ZZ
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
void Encode_LT(int input, vector<int> U, int &index, vector<int>& codes) {
    //在隐私数据一定是全集中元素的基础上，为了减少遍历次数，直接比较输入和集合元素进行编码
    //通用方式，首先假设codes中所有元素的初始值为0
    int i = 0;
    int length = U.size();

    while(i < length && U[i] <= input) {
        codes[i] = 1;
        ++i;
    }
    index = i-1;
    cout << "index: " << index << endl;
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



// 测试编码算法的正确性
int main()
{
  // 设置重数公共数组（1~100）
  // iota采用递增的方式构造数组
  int maxNum = 100; // 将集合基数作为重数的最大值
  vector<int> U(100, 0);
  vector<int> code1(maxNum, 0);
  vector<int> code2(maxNum, 0);
  int Sindex, Tindex; //双方隐私输入在全集U中的位置（下标）
  iota(U.begin(), U.end(), 1);
  cout << "Universal Set:" << endl;
  for(int i = 0; i < maxNum; ++i) {
    cout << U[i] << " ";
  }
  cout << endl;
  
  int input1, input2;
  cout << endl << "P1:Please input the private value:";
  cin >> input1;
  cout << endl << "P2:Please input the private value:";
  cin >> input2;
  int length = U.size();
  

  Encode_LT(input1, U, Sindex, code1);
  Encode_LT(input2, U, Tindex, code2);

  //双方共同协商ElGamal所需要的g和N
  NTL::ZZ N;
  NTL::ZZ g;  //循环群的生成元
  NTL::ZZ p, q;
  long keyLength = 512;

  GenPrimePair(p, q, keyLength);
  N = p * q;
  // srand(time(0));
  // alpha = rand();
  // g = MulMod(alpha, alpha, N*N);
  // NTL::ZZ phi = (p - 1) * (q - 1);
  //   // LCM(p, q) = p * q / GCD(p, q);
  //NTL::ZZ nlambda = N * (phi / NTL::GCD(p - 1, q - 1));
  g = N + 1;
  // NTL::ZZ temp = PowerMod(g, N, N*N);
  // cout << "testInv:" << temp << endl;
  int number = maxNum; //生成的计算对的个数
  NTL::ZZ hs, ht, h;
  //密钥长度
  
  ZZ *Spair1 = new ZZ[number];
  ZZ *Spair2 = new ZZ[number];
  ZZ *Tpair1 = new ZZ[number];
  ZZ *Tpair2 = new ZZ[number];
  
  //cout << endl;
  ElGamalVar Steven(g, N, number, keyLength, hs);
  ElGamalVar Tom(g, N, number, keyLength, ht);
  h = MulMod(hs, ht, N*N);
  cout << "h:" << h << endl;

  //双方对编码进行加密
  Steven.Encrypt(number, code1, Spair1, Spair2, h, input1);
  Tom.Encrypt(number, code2, Tpair1, Tpair2, h, input2);

  //获得比较结果（能够正确解密）
  NTL::ZZ SComResult1, SComResult2, TComResult1, TComResult2; 
  Steven.getCom_Ciresult(Tpair1[Sindex], Tpair2[Sindex], code1[Sindex], SComResult1, SComResult2);
  Tom.getCom_Ciresult(Spair1[Tindex], Spair2[Tindex], code2[Tindex], TComResult1, TComResult2);


  //获得比较结果之后，结合隐私数据
  NTL::ZZ cs_x1, cs_x2;
  Steven.mul_input(SComResult1, SComResult2, cs_x1, cs_x2);
  NTL::ZZ ct_y1, ct_y2;
  Tom.mul_input(TComResult1, TComResult2, ct_y1, ct_y2);
  

  //公开结合隐私数据的密文之后，各自进行明文相加
  NTL::ZZ cs1_1, cs1_2, ct1_1, ct1_2;
  Steven.plainAdd(cs_x1, cs_x2, ct_y1, ct_y2, cs1_1, cs1_2);
  Tom.plainAdd(cs_x1, cs_x2, ct_y1, ct_y2, ct1_1, ct1_2);

  //协议第4、5步，计算ca1=Enc(x(1-za-zb)), cb1=Enc(y(1-za-zb))
  NTL::ZZ cs_1, cs_2, ct_1, ct_2;/////////////////////////
  Steven.step_45(cs_1, cs_2, cs1_1, cs1_2, SComResult1, SComResult2, TComResult1, TComResult2);
  Tom.step_45(ct_1, ct_2, ct1_1, ct1_2, SComResult1, SComResult2, TComResult1, TComResult2);
  //判断cs和ct是否相等，由于g和h会有x进行改变，因此两个数不会相等！！！！！！！！！！！11
  // if(cs_1 != ct_1 || cs_2 != ct_2) {
  //   cout << "exist the malicious party!" << endl;
  // }
  
  //验证门限密码体制的正确性
  //对比较结果，双方分别得到解密份额
  NTL::ZZ Sde_partial1, Tde_partial1, Sde_partial2, Tde_partial2;
  Steven.getDe_partial(cs_1, Sde_partial1);
  Tom.getDe_partial(cs_1, Tde_partial1);
  Steven.getDe_partial(ct_1, Sde_partial2);
  Tom.getDe_partial(ct_1, Tde_partial2);
  //解密是成功的
  // Steven.getDe_partial(Spair1[Tindex], Sde_partial1);
  // Tom.getDe_partial(Spair1[Tindex], Tde_partial1);
  // Steven.getDe_partial(Tpair1[Sindex], Sde_partial2);
  // Tom.getDe_partial(Tpair1[Sindex], Tde_partial2);

  
  //双方分别进行解密
  NTL::ZZ Splaintext, Tplaintext;
  Steven.Decrypt(Splaintext, cs_2, Sde_partial1, Tde_partial1);
  Tom.Decrypt(Tplaintext, ct_2, Sde_partial2, Tde_partial2);

  //解密是正确的
  // Steven.Decrypt(Splaintext, Spair2[Tindex], Sde_partial1, Tde_partial1);
  // Tom.Decrypt(Tplaintext, Tpair2[Sindex], Sde_partial2, Tde_partial2);

  return 0;
}