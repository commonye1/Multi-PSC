#include "../header/paillier.h"
#include <cstdlib>
#include <time.h>
using namespace std;

NTL::ZZ generateCoprimeNumber(const NTL::ZZ& n) {
    NTL::ZZ ret;
    while (true) {
        ret = RandomBnd(n);
        //随机数r属于Zn*，即r<n且与n互素
        if (NTL::GCD(ret, n) == 1) { return ret; }
    }
}



//generator:生成元   modulus:模数N    number:生成的密文对数  u:解密份额   keylongth：密钥长度
Paillier::Paillier(NTL::ZZ &generator, NTL::ZZ &modulus, int number, NTL::ZZ &ds, long keyLength)
{
    /* Length in bits. */
    NTL::ZZ p, q;
    GenPrimePair(p, q, keyLength);
    modulus = p * q;
    this->modulus = modulus;
    //cout << "p:" << p << "  q:" << q << endl;
    generator = modulus + 1;
    this->generator = generator;
    NTL::ZZ phi = (p - 1) * (q - 1);
    // LCM(p, q) = p * q / GCD(p, q);
    lambda = phi / 2;
    lambdaInverse = NTL::InvMod(lambda, modulus);
    randNum = new NTL::ZZ[number];  //由于N为512比特，因此输入和随机数都应该小于255比特
    for(int i = 0; i < number; i++) {
        srand(i+1);
        randNum[i] = rand();  //rand()只剩成最多32比特的随机数
        //cout << "randNum:" << randNum[i] << endl; 
    }
     ds = (1 + modulus*lambda)%(modulus*modulus);  //u = g^lambda mod n*n
    
        
}

//生成p,q,n
void Paillier::GenPrimePair(NTL::ZZ& p, NTL::ZZ& q, long keyLength) {
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
    /*while (true) {
        long err = 80;
        p = NTL::GenPrime_ZZ(keyLength/2, err); 
        q = NTL::GenPrime_ZZ(keyLength/2, err);
        while (p == q) {
            q = NTL::GenPrime_ZZ(keyLength/2, err);
        }
        NTL::ZZ n = p * q;
        NTL::ZZ phi = (p - 1) * (q - 1);
        if (NTL::GCD(n, phi) == 1) 
            return;
    }*/
}

//生成(c1,c2)和(s1,s2)，其中(c1,c2)和rc是分开存储的
void Paillier::GenPair(int number, long& m, NTL::ZZ* pair1, NTL::ZZ* pair2) {
    for(int i = 0; i < number; i++) {
        //直接使用定义对象时生成的随机数
        pair1[i] = (1 + modulus*randNum[i]*m) % (modulus*modulus);
        pair2[i] = (1 + modulus*randNum[i]) % (modulus*modulus);
        //cout << "(" << pair1[i] << "," << pair2[i] << ")   "; 
    }
}

//选择方所提供的是随机下标
void Paillier::selectPair(const NTL::ZZ* Spair1, const NTL::ZZ* Spair2, NTL::ZZ* SSPair1,
    NTL::ZZ* SSPair2, bool *i, int num) {
    int k = 0;
    int conum = num*2;
    srand(time(0));
    int randNum = rand() % 3 + 1;
    for(int j = 0; j < num; j++) {
        k = (j * randNum) % conum;
        i[k] = true;    //记录标签
    }
    //记录加密对
    int j = 0;
    for(int k = 0; k < conum; ++k) {
        if(i[k]){
            SSPair1[j] = Spair1[k];  
            SSPair2[j] = Spair2[k];  
            ++j;
            //cout << "j:" << j << endl;
        }
    }

}
//公开被选择打开的加密对    
//i：所选择的下标集合
void Paillier::publishNum(bool* i, NTL::ZZ* SSNum, NTL::ZZ* SSRanNum, long m, int num){
    int j = 0;
    int conum = num * 2;
    for(int k = 0; k < conum; k++) {
        if(i[k] && j < num){
            SSRanNum[j] = randNum[k];
            SSNum[j] = randNum[k]*m;
            j++;
        }
        //cout << "j:" << j << "  k:" << k << endl;
    }
}
//测试参数正确性
bool Paillier::test(NTL::ZZ* SNum, NTL::ZZ* Spair1, NTL::ZZ N, NTL::ZZ g, int number) {
    bool flag;
    for(int j = 0; j < number; j++) {
        NTL::ZZ tmp = (1 + SNum[j] * N) % (N*N);
        if(SNum[j] > N/2 || SNum[j] == 0 || tmp != Spair1[j]){
            return false;
        }
    }
    return true;
}
//Tom计算Steven的密文
void Paillier::computeCipherS(NTL::ZZ* Spair1, NTL::ZZ* Spair2, bool *Si, NTL::ZZ &Scipher, 
int number, long y, NTL::ZZ SN, NTL::ZZ& Srandom, NTL::ZZ &r, NTL::ZZ &t, long keyLength) {
    int randomi;
    srand(time(0));
    randomi = rand()%(number*2);
    //若随机数与之前的重复，则继续取随机数。
    while(Si[randomi]){
        randomi = (randomi + 1) % (number*2);
    }
    //NTL::sqr(a) = a*a;
    long err = 80;
    t = NTL::GenPrime_ZZ(keyLength/2-1, err); 
    //cout << "N:" << SN << endl;
    //cout << "t:"<< t <<endl;
    Srandom = randNum[randomi];
    r = generateCoprimeNumber(SN);
    Scipher = (NTL::PowerMod(Spair2[randomi], -t*y, SN*SN) * 
             NTL::PowerMod(Spair1[randomi], t, SN*SN) * 
             NTL::PowerMod(r, SN, SN*SN)) % (SN*SN); 
    //cout << "cipher:" << Scipher << endl;
}

//Steven计算Tom的密文
void Paillier::computeCipherT(NTL::ZZ* Tpair1, NTL::ZZ* Tpair2, bool *Ti, NTL::ZZ &Tcipher, 
int number, long x, NTL::ZZ TN, NTL::ZZ& Trandom, NTL::ZZ &r,NTL::ZZ &s, long keyLength) {
    int randomi;
    srand(time(0));
    randomi = rand()%(number*2);
    //若随机数与之前的重复，则继续取随机数。
   while(Ti[randomi]){
        randomi = (randomi + 1) % (number*2);
    }
    //NTL::ZZ t = RandomBnd(SN);
    long err = 80;
    s = NTL::GenPrime_ZZ(keyLength/2-1, err); 
    Trandom = randNum[randomi];
    r = generateCoprimeNumber(TN);
    Tcipher = (NTL::PowerMod(Tpair2[randomi], s*x, TN*TN) * 
             NTL::PowerMod(Tpair1[randomi], -s, TN*TN) * /////////////////-t
             NTL::PowerMod(r, TN, TN*TN)) % (TN*TN); 
    
}

//参与方测试对方选择的加密对是否已经被打开过
bool Paillier::testOpnened(NTL::ZZ SplainNum,NTL::ZZ* SSRanNum ,int number) {
    if(SplainNum == 0) {
        return true;
    }
    for(int z = 0; z < number; z++) {
        if(SplainNum % SSRanNum[z] == 0)
            return false;
    }
    return true;
}


void Paillier::computeLmb(NTL::ZZ& m, NTL::ZZ cipher) {
    m = NTL::PowerMod(cipher, lambda, modulus*modulus);
}

//Deresult:是解密结果 result:判断大小结果
void Paillier::getResult(NTL::ZZ ms, NTL::ZZ u, NTL::ZZ t, NTL::ZZ N, NTL::ZZ &Deresult, int &result) {
    NTL::ZZ temp1 = L_function(ms, N);
    NTL::ZZ temp2 = NTL::InvMod(L_function(u, N), N);  //逆元正确 = lambdaInverse
    NTL::ZZ temp3 = (temp1*temp2) % N;
    
    Deresult = temp3;
    NTL::ZZ temp;
    if(temp3 < N/2){
        temp = temp3 / t;   //x>y
    } else {
        temp = (temp3-N) / t % N;
    }
    
    if(temp == 0){
        result = 0;// x=y
    } else if(temp > N/2) {
        result = -1;// x<y
    } else if(temp < N/2) {
        result = 1; //x>y
    }
        
}

NTL::ZZ Paillier::encrypt(const NTL::ZZ& message) {
    NTL::ZZ random = generateCoprimeNumber(modulus);
    NTL::ZZ ciphertext = 
        NTL::PowerMod(generator, message, modulus * modulus) *
        NTL::PowerMod(random, modulus, modulus * modulus);
    return ciphertext % (modulus * modulus);
}
//用户自定义随机数
NTL::ZZ Paillier::encrypt(const NTL::ZZ& message, const NTL::ZZ& random) {
    NTL::ZZ ciphertext = 
        NTL::PowerMod(generator, message, modulus * modulus) *
        NTL::PowerMod(random, modulus, modulus * modulus);
    return ciphertext % (modulus * modulus);
}

NTL::ZZ Paillier::decrypt(const NTL::ZZ& ciphertext) {
    /* NOTE: NTL::PowerMod will fail if the first input is too large
     * (which I assume means larger than modulus).
     */
    NTL::ZZ deMasked = NTL::PowerMod(
            ciphertext, lambda, modulus * modulus);
    NTL::ZZ power = L_function(deMasked, modulus);
    return (power * lambdaInverse) % modulus;
}

