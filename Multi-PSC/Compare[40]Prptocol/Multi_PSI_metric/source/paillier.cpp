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
Paillier::Paillier(NTL::ZZ &generator, NTL::ZZ &modulus, NTL::ZZ &ds, long keyLength)
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
    lambda = phi / NTL::GCD(p - 1, q - 1);
    lambdaInverse = NTL::InvMod(lambda, modulus);
    ds = PowerMod(generator, lambda, modulus*modulus);  //u = g^lambda mod n*n
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
}

void Paillier::encrypt(NTL::ZZ** &Cipher, vector<vector<int>> message) {
    int row = message.size();;
    int col = message[0].size();
    NTL::ZZ exp_N = modulus * modulus;
    //cout << "行数：" << row << "  列数：" << col << endl;
    for (int i = 0; i < row; ++i){
        for(int j = 0; j < col; ++j) {
            NTL::ZZ random = generateCoprimeNumber(modulus);
            Cipher[i][j] =  (NTL::PowerMod(generator, message[i][j], exp_N) *
                NTL::PowerMod(random, modulus, exp_N)) % exp_N;
        }
    }
}

//数组解密
void Paillier::decrypt(NTL::ZZ* &Plaintext, NTL::ZZ* ciphertext, int num) {
    NTL::ZZ deMasked, power;
    NTL::ZZ exp_N = modulus * modulus;
    for(int i = 0; i < num; ++i) {
        deMasked = NTL::PowerMod(ciphertext[i], lambda, exp_N);
        power = L_function(deMasked, modulus);
        Plaintext[i] = (power * lambdaInverse) % modulus;
    } 
}

//单个数据解密
void Paillier::decrypt(NTL::ZZ &Plaintext, NTL::ZZ ciphertext) {
    NTL::ZZ deMasked, power;
    NTL::ZZ exp_N = modulus * modulus;
    deMasked = NTL::PowerMod(ciphertext, lambda, exp_N);
    power = L_function(deMasked, modulus);
    Plaintext = (power * lambdaInverse) % modulus;
} 




void Compute_Cipher(NTL::ZZ* &Re_Cipher, NTL::ZZ** Cipher, vector<vector<int>> data, NTL::ZZ N, int row, int col) {
    NTL::ZZ *row_Data = new NTL::ZZ[col];    //用来存储结合S和T的每一行数据
    NTL::ZZ tmp1, tmp2; //tmp用来存储密文相乘的临时数据
    NTL::ZZ exp_N = N*N;
    //cout << "行数：" << row << "  列数：" << col << endl;
    for (int i = 0; i < row; ++i){
        tmp1 = NTL::PowerMod(Cipher[i][0], data[i][0], exp_N);
        for(int j = 1; j < col; ++j) {
            tmp2 = NTL::PowerMod(Cipher[i][j], data[i][j], exp_N);
            tmp1 = NTL::MulMod(tmp1, tmp2, exp_N);
        }
        Re_Cipher[i] = tmp1;
    }         
}



