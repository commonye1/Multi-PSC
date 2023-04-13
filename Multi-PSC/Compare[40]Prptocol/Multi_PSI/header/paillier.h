#include <NTL/ZZ.h>
#include <NTL/ZZ_pXFactoring.h>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <vector>

#ifndef _PAILLIER_H
#define _PAILLIER_H

using namespace std;

class Paillier {
    public:
    /* Completely generate everything, from scratch */
    //协议第1步
    Paillier(NTL::ZZ &generator, NTL::ZZ &modulus, NTL::ZZ &u, long keyLength);
    void encrypt(NTL::ZZ** &Cipher, vector<vector<int>> message); 
    void decrypt(NTL::ZZ* &Plaintext, NTL::ZZ* ciphertext, int num); 
    //单数据解密
    void decrypt(NTL::ZZ &Plaintext, NTL::ZZ ciphertext);
    NTL::ZZ L_function(const NTL::ZZ& x, NTL::ZZ N) { return (x - 1) / N; }
    void GenPrimePair(NTL::ZZ& p, NTL::ZZ& q, long keyLength); 
    

    private:
    /* modulus = pq, where p and q are primes */
    NTL::ZZ modulus;
    NTL::ZZ generator;
    NTL::ZZ lambdaInverse;
    NTL::ZZ* randNum;
    NTL::ZZ lambda;  ///本来是私有的

};

void Compute_Cipher(NTL::ZZ* &Re_Cipher, NTL::ZZ** Cipher, vector<vector<int>> data, NTL::ZZ N, int row, int col);


#endif
