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

// 测试编码算法的正确性
int main()
{
  // 设置重数公共数组（1~100）
  // iota采用递增的方式构造数组
  int maxNum = 100; // 将集合基数作为重数的最大值
  vector<int> U(100, 0);
  iota(U.begin(), U.end(), 1);
  cout << "Universal Set:" ;
  for(int i = 0; i < maxNum; ++i) {
    cout << U[i] << " ";
  }
  cout << endl;
  
  vector<int> inputNum1 = {1, 2, 5, 8, 2, 5, 4, 10, 8, 6, 3, 5};
  vector<int> inputNum2 = {5, 6, 2, 4, 3, 6, 8, 7, 13, 7, 6, 10};
  //不需要进行输入，因为本质上这是在协议最初预处理时已经定义完成的
  int eleNum = inputNum1.size();  //交集中元素个数
  //多重交集元素重数数组CW
  NTL::ZZ *CU = new ZZ[eleNum];
  //双方共同协商ElGamal所需要的g和N
  NTL::ZZ N;
  NTL::ZZ g;  //循环群的生成元
  NTL::ZZ p, q;
  long keyLength = 512;

  GenPrimePair(p, q, keyLength);
  N = p * q;
  g = N + 1;
  int number = maxNum; //生成的计算对的个数
  NTL::ZZ hs, ht, h;
  ElGamalVar Steven(g, N, number, keyLength, hs);
  ElGamalVar Tom(g, N, number, keyLength, ht);
  h = MulMod(hs, ht, N*N);
  cout << "h:" << h << endl;

  //在进行比较的全过程使用的是同一个密钥，且即使得到结果也不会泄露密钥，因此除了生成ElGamal密钥之外，
  //其他操作还是每对数据进行比较即可，最终只需要得到较小的数值并将其存入结果数组中
  
  for(int i = 0; i < eleNum; ++i) {
    vector<int> code1(maxNum, 1);
    vector<int> code2(maxNum, 1);
    int Sindex, Tindex; //双方隐私输入在全集U中的位置（下标）
    //编码
    Encode_GT(inputNum1[i], U, Sindex, code1);
    Encode_GT(inputNum2[i], U, Tindex, code2);
    
    //双方对编码进行加密，同时对参与方所拥有的数据进行了赋值
    ElGamal_Cipher *Spair = new ElGamal_Cipher[number];
    ElGamal_Cipher *Tpair = new ElGamal_Cipher[number];
    Steven.Encrypt(number, code1, Spair, h, inputNum1[i]);
    Tom.Encrypt(number, code2, Tpair, h, inputNum2[i]);

    //获得比较结果（能够正确解密）
    ElGamal_Cipher SComResult, TComResult; 
    Steven.getCom_Ciresult(Tpair[Sindex], code1[Sindex], SComResult);
    Tom.getCom_Ciresult(Spair[Tindex], code2[Tindex], TComResult);

    //获得比较结果之后，结合隐私数据(解密结果是正确的)
    ElGamal_Cipher cs_x;
    Steven.mul_input(SComResult, cs_x);
    ElGamal_Cipher ct_y;
    Tom.mul_input(TComResult, ct_y);

    //公开结合隐私数据的密文之后，各自进行明文相加（加解密正确）
    ElGamal_Cipher cs1, ct1;
    Steven.plainAdd(cs_x, ct_y, cs1);
    Tom.plainAdd(cs_x, ct_y, ct1);

    //协议第4、5步，计算ca1=Enc(x(1-za-zb)), cb1=Enc(y(1-za-zb))
    ElGamal_Cipher cs, ct;
    Steven.step_45(cs, cs1, SComResult, TComResult);
    Tom.step_45(ct, ct1, SComResult, TComResult);

    //验证门限密码体制的正确性
    //对比较结果，双方分别得到解密份额
    NTL::ZZ Sde_partial1, Tde_partial1, Sde_partial2, Tde_partial2;
    Steven.getDe_partial(cs.fir, Sde_partial1);
    Tom.getDe_partial(cs.fir, Tde_partial1);
    Steven.getDe_partial(ct.fir, Sde_partial2);
    Tom.getDe_partial(ct.fir, Tde_partial2);

    //对解密份额进行零知识证明
    //验证Steven提供的ct的解密份额(Sde_partial2)是否正确
    if(!ZeroProof(Steven, Tom, hs, g, Sde_partial2, ct.fir, N, Steven.k)) {
      cout << "Steven is malicious!" << endl;
      return 0;
    }
    //验证Tom提供的cs的解密份额(Tde_partial1)是否正确
    if(!ZeroProof(Tom, Steven, ht, g, Tde_partial1, cs.fir, N, Tom.k)) {
      cout << "Tom is malicious!" << endl;
      return 0;
    }
    //双方分别进行解密
    NTL::ZZ Splaintext, Tplaintext;
    Steven.Decrypt(Splaintext, cs.sec, Sde_partial1, Tde_partial1);
    Tom.Decrypt(Tplaintext, ct.sec, Sde_partial2, Tde_partial2);

    //协议第7步，验证结果的正确性
    //定义这些函数if_equal_x,JointDecrypt(该函数在主函数或者在类外定义)
    //JointDecrypt(Steven, Tom, AC1.result, Plaintext);
    ElGamal_Cipher AC1_result, AC2_result; 
    NTL::ZZ bs, at, de_partial1, de_partial2, bs_1, at_1;

    //Steven进行验证
    //Steven计算bi(i=1,...,s')的乘积，即明文之和
    Steven.add_GT_Code(Tpair, U, Splaintext, AC1_result, Sindex);
    Steven.getDe_partial(AC1_result.fir, de_partial1);
    Tom.getDe_partial(AC1_result.fir, de_partial2);
    //ZKP证明解密份额正确性
    Steven.Decrypt(bs, AC1_result.sec, de_partial1, de_partial2);
    if(bs != number - Splaintext + 1) {
      //cout << "bs:" << bs << "     Splaintext:" << Splaintext << endl;
      cout << "result is fault" << endl;
      return 0;
    }
    //Steven判断结果是否为x，若不为x则进行下一步判断
    if(!Steven.if_equal_x(Splaintext)) {
      Steven.getDe_partial(Tpair[Sindex - 1].fir, de_partial1);
      Tom.getDe_partial(Tpair[Sindex - 1].fir, de_partial2);
      Steven.Decrypt(bs_1, Tpair[Sindex - 1].sec, de_partial1, de_partial2);
      if(bs_1 != 0) {
        cout << "Tom is malicious in final" << endl;
        return 0;
      }
    }
    
    //Tom进行验证
    //Tom计算ai(i=1,...,t')的乘积，即明文之和
    Tom.add_GT_Code(Spair, U, Tplaintext, AC2_result, Tindex);
    Steven.getDe_partial(AC2_result.fir, de_partial1);
    Tom.getDe_partial(AC2_result.fir, de_partial2);
    //ZKP证明解密份额正确性
    Tom.Decrypt(at, AC2_result.sec, de_partial1, de_partial2);
    if(at != number - Tplaintext + 1) {
      cout << "result is fault" << endl;
      return 0;
    }
    
    //Tom判断结果是否为y，若不为y则进行下一步判断
    if(!Tom.if_equal_x(Tplaintext)) {
      Steven.getDe_partial(Spair[Tindex - 1].fir, de_partial1);
      Tom.getDe_partial(Spair[Tindex - 1].fir, de_partial2);
      Tom.Decrypt(at_1, Spair[Tindex - 1].sec, de_partial1, de_partial2);
      if(at_1 != 0) {
        cout << "Steven is malicious in final" << endl;
        return 0;
      }
    }
    if(Splaintext == Tplaintext) {
      CU[i] = Splaintext;
      //cout << "The less number is " << Splaintext << endl;
    }
  }

  cout << "CU = {";
  for(int i = 0; i < eleNum; ++i) {
    cout << " " << CU[i];
  }
  cout << "}" << endl;
  return 0;
}