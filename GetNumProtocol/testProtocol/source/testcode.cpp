#include <iostream>
#include <cstdlib>
#include <numeric>
#include <vector>

#include "../header/paillier.h"
#include "../source/paillier.cpp"

using namespace std;
using namespace NTL;


ZZ lcm(ZZ x, ZZ y)
{
  ZZ ans = (x * y) / NTL::GCD(x, y);
  return ans;
}

// 2轮通信，6次模指数
bool ZeroProof(Paillier prover, Paillier verifier, NTL::ZZ alpha, NTL::ZZ g,
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
void Encode_GT(int input, vector<int> &U, vector<int>& codes) {
    //在隐私数据一定是全集中元素的基础上，为了减少遍历次数，直接比较输入和集合元素进行编码
    //通用方式，首先假设codes中所有元素的初始值为0
    int i = 0;
    int length = U.size();

    while(i < length && U[i] <= input) {
        codes[i] = 1;
        ++i;
    }
    //改进方式：
    //首先，假设全集就是从min~max的所有值，那么input在全集中的位置就是input-min
    /*
    int i = 0;
    int length = input - min + 1;
    while(i < length) {
        codes[i] = 1;
    }
    */
    // cout << "Encode result:" << endl;
    // for(i = 0; i < U.size(); ++i) {
    //     cout << codes[i] << " ";
    // }
    // cout << endl;
}



// 测试编码算法的正确性
int main()
{
  // 设置重数公共数组（1~100）
  // iota采用递增的方式构造数组
  int maxNum = 100; // 将集合基数作为重数的最大值
  vector<int> U(100, 0);  //直接共有不各自生成
  vector<int> code1(100, 0);
  vector<int> code2(100, 0);
  iota(U.begin(), U.end(), 1);
  cout << "Universal Set:" << endl;
  for (int i = 0; i < 100; ++i)
  {
    cout << U[i] << " ";
  }

  int input1, input2;
  cout << endl << "Please input the private value:";
  cin >> input1;
  cout << "input:" << input1 << endl;
  int length = U.size();

  Encode_GT(input1, U, code1);
//void Encode_GT(int input, vector<int> U, vector<int>& codes) {
  return 0;
}