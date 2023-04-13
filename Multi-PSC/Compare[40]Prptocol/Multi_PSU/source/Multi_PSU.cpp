#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <functional>
#include <algorithm>
#include <time.h>
//#include "../header/ElGamalVar.h"   此时解决了类重定义的问题
#include "../source/paillier.cpp"

using namespace std;
using namespace NTL;


void Encode(vector<vector<int>> &Code, vector<int> Freq, vector<int> Data); 

void Encode(vector<vector<int>> &Code, vector<int> Freq, vector<int> Data) {
    int DataNum = Data.size();
    int FreqNum = Code[0].size();
    //cout << "编码的数量：" << DataNum << endl;
    //cout << "编码长度：" << FreqNum << endl;
    int i,j;

    //先找到元素对应的位置，然后依据频数来进行赋1操作
    //Code[i][0]=1表示集合中第i中元素的个数为1
    for(i = 0; i < DataNum; ++i) {
        for(j = 0; j+1 <= Freq[i]; ++j) {
            Code[i][j] = 0;
        }
    }
}

int main()
{
  //首先读取重数文件数据, 以空格为间隔
  fstream file;
  //这里的文件路径不是以.cpp文件为依据，若使用的是"../data"则会打不开
  file.open("./data/S_Freq.csv", ios::in);
  vector<int> S_Freq;
  string tmp;
  while (file >> tmp)
  {
    S_Freq.push_back(stoi(tmp, 0, 10));
  }
  file.close();
  file.open("./data/T_Freq.csv", ios::in);
  vector<int> T_Freq;
  while (file >> tmp)
  {
    T_Freq.push_back(stoi(tmp, 0, 10));
  }
  file.close();
  file.open("./data/Universe_Data.csv", ios::in);
  vector<int> U_Data;
  while (file >> tmp)
  {
    U_Data.push_back(stoi(tmp, 0, 10));
  }
  file.close();

  // 本程序略过了参与方根据自己的数据集和全集构造频数的过程
  int maxNum = 100; // 将集合基数作为重数的最大值，矩阵的列数
  int Data_kinds = U_Data.size();    //全集中元素的个数为矩阵的行数
  
  // 初始化编码空间
  vector<vector<int>> Code1(Data_kinds, vector<int> (maxNum,1));
  vector<vector<int>> Code2(Data_kinds, vector<int> (maxNum,1));
  //cout << "列数" << Code1[0].size() << endl;
  
  clock_t start,end;//定义clock_t变量
  start = clock(); //开始时间
          
  //进行编码
  Encode(Code1, S_Freq, U_Data);
  Encode(Code2, T_Freq, U_Data);
  
  // cout << "Steven的编码: " << endl;
  // for (int j = 0; j < Data_kinds; ++j) {
  //   cout << S_Freq[j] << ":";
  //   for(int i = 0; i < maxNum; ++i) {
  //     cout << Code1[j][i] << " "; 
  //   }
  //   cout << endl;
  // }
  // cout << endl;
  // cout << "Tom的编码: " << endl;
  // for (int j = 0; j < Data_kinds; ++j) {
  //   cout << T_Freq[j] << ":";
  //   for(int i = 0; i < maxNum; ++i) {
  //     cout << Code2[j][i] << " "; 
  //   }
  //   cout << endl;
  // }
  // cout << endl;


//Steven构造Paillier密钥对，并加密编码
  NTL::ZZ N;
  NTL::ZZ g;  //循环群的生成元
  NTL::ZZ ds; //解密份额
  long keyLength = 512;

  Paillier Steven(g, N, ds, keyLength);
  ZZ **Enc_Code1 = new ZZ*[Data_kinds];
  for(int i = 0; i < Data_kinds; ++i) {
    Enc_Code1[i] = new ZZ[maxNum];
  }
  Steven.encrypt(Enc_Code1, Code1);

  //ZZ temp;
  // cout << "Steven第10个数的编码解密结果：";
  // for(int i = 0; i < maxNum; ++i) {
  //   Steven.decrypt(temp, Enc_Code1[9][i]);
  //   cout << temp << " ";
  // }
  //cout << endl;
//Tom计算明文相乘之后的和值
  ZZ *Result_Cipher = new ZZ[Data_kinds];
  Compute_Cipher(Result_Cipher, Enc_Code1, Code2, N, Data_kinds, maxNum);
  // ZZ tmp1, tmp2, tmp3, retmp;
  // tmp1 = NTL::PowerMod(Enc_Code1[9][0], Code2[9][0], N*N);
  // tmp2 = NTL::PowerMod(Enc_Code1[9][1], Code2[9][1], N*N);
  // tmp3 = NTL::MulMod(tmp1, tmp2, N*N);
  // Steven.decrypt(retmp, tmp3);
  // cout << "code11:" << Code1[9][0] << "code12" << Code1[9][1] << endl;
  // cout << "code21:" << Code2[9][0] << "code22" << Code2[9][1] << endl;
  // cout << "前一个密文：" << tmp2 << endl;
  // cout << "后一个密文：" << tmp1 << endl; 
  // cout << "测试解密结果：" << retmp << endl;

//接收到Tom发送的结果密文后，Steven对密文进行解密，得到最终每个元素对应的重数
  ZZ *CU1 = new ZZ[Data_kinds];
  ZZ *CU = new ZZ[Data_kinds];
  Steven.decrypt(CU1, Result_Cipher, Data_kinds);
  for(int i = 0; i < Data_kinds; ++i) {
    CU[i] = maxNum-CU1[i];
  }

  //并集元素重数
  cout << "CU = {";
  for(int i = 0; i < Data_kinds; ++i) {
    cout << CU[i] << " ";
  }
  cout <<"}" << endl;

  //结合全集得到最终多重并集
  vector<int> Mul_U;
  long temp;
  for(int i = 0; i < Data_kinds; ++i) {
    for(ZZ j; j < CU[i]; ++j) {
      Mul_U.push_back(U_Data[i]);
    }
  }

  end = clock();//结束时间



  //将结果保存至文件中
  file.open("./data/Multi_Union_Data.csv", ios::out);
  if(file && file.is_open()) {
      //cout << "file is opened" << endl;
  }else {
      cout << "failure" << endl;
      return 0;
  }
  file.clear();
  cout << "多重并集结果：";
  for(auto & temp : Mul_U) {
    file <<" " << temp;
    cout << temp << " ";
  }
  cout << endl;
  file.close();
  return 0;
}