/*
Notes on datastructures used:
1 Use uint32_t instead of unsigned int because unsigned int is not 32 bytes for all architecture.
  uint32_t is a macro and always is a 32 bits unsigned integer. 
*/

//#include "stdafx.h"
#include <iostream>
#include <fstream>
#include <stdint.h>
#include <stdlib.h>
#include <vector>
#include <iomanip>
#ifndef SCRYPT_H
#define SCRYPT_H
#include <cstring>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <time.h>


#define SCRYPT_BUFFER_SIZE (131072 + 63)
unsigned char* scrypt_blockhash(const uint8_t* input);
#endif
using namespace std;
bool check_preheader(istream& block);
bool check_header(istream& block);
uint64_t varint(istream& block);
bool get_transactions(ifstream& block);
bool get_ip_txn(ifstream& block);
bool get_op_txn(ifstream& block);
int main(int argv, char **argc)
{
	ifstream block;
	if(argv==2)
	{
			block.open(argc[1], ios::binary);
	}
	else{
		printf("Usage is parser <block>\n");
		return -99;
	}
	cout << "NovaCoin Block Parser"<<endl;
	if (!block.is_open())
	{
		cout << "file not open" << endl;
		return -99;
	}
	if(!check_preheader(block))
		return -99;
	if(!check_header(block))
		return -99;
	uint64_t n_t;
	n_t=varint(block);
	cout<<"Number of Transactions "<<n_t<<endl;
	cout<<"-------------------------------------------------------"<<endl;
	for(uint64_t i = 0;i<n_t;i++)
	{
		cout<<"transaction "<<i+1<<endl;
		get_transactions(block);
	}
}
bool check_preheader(istream& block)
{
	uint32_t magic= 0;
	uint32_t bsize = 0;
	/* gist.github.com/molpopgen/9123133   Illustrates some of the various quirks/annoyances to read/write binary stuff in C++ */
	block.read(reinterpret_cast<char *>(&magic), sizeof(magic));
#ifdef _DEBUG
	cout << "Magic Number read:"<< hex << magic << endl;
#endif // DEBUG	

	block.read(reinterpret_cast<char *>(&bsize), sizeof(bsize));
#ifdef _DEBUG
	cout <<"File Size read:"<< dec << bsize << endl;
#endif // DEBUG
	if (magic != 0xe5e9e8e4)
	{
		cout << "Incorrect Magic in header" << endl;
		return false;
	}
	uint32_t beg = 0,bfsize=0;
	beg = block.tellg();  //position begining of block header. can hardcode value 8, but this seems cleaner
	block.seekg(0,block.end);  //end of file to calculate size
	bfsize = uint32_t(block.tellg() ) -  beg ; //size in field is sizeof_file - 8bytes(4 bytes magic, 4 bytes size)
#ifdef _DEBUG
	cout <<"File Size Calculated:"<< bfsize<<endl;
#endif
	if (bfsize != bsize)
	{
		cout << "Incorrect Size in header" << endl;
		return false;
	}
	block.clear();
	block.seekg(beg,block.beg);
	unsigned char* input;
	unsigned char* hash;
	input=(unsigned char*)malloc(bfsize*sizeof(unsigned char));
	hash=(unsigned char*)malloc(32*sizeof(unsigned char));
	block.read(reinterpret_cast<char *>(&input[0]), bfsize*sizeof(unsigned char));
	/*for(unsigned int i=0; i<bfsize; ++i)
		cout <<std::setw(2)<<hex<<setfill('0')<<(int) input[i];*/
	hash = scrypt_blockhash(input);
	cout<<"hash calculated"<<endl;
	for(unsigned int i=0; i<32; ++i)
		cout <<std::setw(2)<<hex<<setfill('0')<<(int) hash[31-i];
	
	cout<<endl<<"----preheader complete----"<<endl;
	block.clear();
	block.seekg(beg,block.beg);
	return true;
}

bool check_header(istream& block)
{
	uint32_t nVersion;
	unsigned char hashPrevBlock[32];
	unsigned char hashMerkleRoot[32]	;
	uint32_t nTime;
	uint32_t nBits;
	uint32_t nNonce;
	
	block.read(reinterpret_cast<char *>(&nVersion), sizeof(nVersion));
	block.read(reinterpret_cast<char *>(&hashPrevBlock[0]), 32*sizeof(unsigned char));
	block.read(reinterpret_cast<char *>(&hashMerkleRoot[0]), 32*sizeof(unsigned char));
	block.read(reinterpret_cast<char *>(&nTime), sizeof(nTime));
    block.read(reinterpret_cast<char *>(&nBits), sizeof(nBits));
	block.read(reinterpret_cast<char *>(&nNonce), sizeof(nNonce));
	for(unsigned int i=0; i<32; ++i)
		cout <<std::setw(2)<<hex<<setfill('0')<<(int) hashPrevBlock[31-i];
	cout<<endl;
	for(unsigned int i=0; i<32; ++i)
		cout <<std::setw(2)<<hex<<setfill('0')<<(int) hashMerkleRoot[31-i];
	cout<<endl;
	return true;
	
}




uint64_t varint(istream& block)
{
	uint8_t s1;
	uint16_t s2;
	uint32_t s3;
	uint64_t s4;
	block.read(reinterpret_cast<char *>(&s1), sizeof(s1));
	if(s1<0xfd)
		return (uint64_t)s1;
	else if (s1==0xfd)
	{
		block.read(reinterpret_cast<char *>(&s2), sizeof(s2));
		return (uint64_t)s2;
	}
	else if(s1==0xfe)
	{
		block.read(reinterpret_cast<char *>(&s3), sizeof(s3));
		return (uint64_t)s2;
	}
	else if(s1==0xff)
	{
		block.read(reinterpret_cast<char *>(&s4), sizeof(s4));
		return (uint64_t)s2;
		
	}
}


bool get_transactions(ifstream& block)
{
	
	uint32_t version;
	uint32_t timestamp,lock_time;
	uint64_t ip_n,op_n;
	int tx_start = block.tellg();
	block.read(reinterpret_cast<char *>(&version), sizeof(version));
	block.read(reinterpret_cast<char *>(&timestamp), sizeof(timestamp));
	
	ip_n=varint(block);
	cout<<"Version "<<version<<endl;
	cout<<"time "<<dec<<timestamp<<endl;
	time_t tx_time=timestamp;
	cout<<"TX_TIME "<<ctime(&tx_time)<<endl;
	cout<<"Number of inputs "<<ip_n<<endl;
	for(uint64_t i =0;i<ip_n;i++)
	{
		//cout<<"input "<<i+1<<endl;
		get_ip_txn(block);
	}
	op_n=varint(block);
	cout<<"Number of outputs "<<op_n<<endl;
	for(uint64_t i =0;i<op_n;i++)
	{
		//cout<<"output "<<i+1<<endl;
		get_op_txn(block);
	}
	
    block.read(reinterpret_cast<char *>(&lock_time), sizeof(lock_time));
	cout<<"LockTime "<<lock_time << endl;
	int tx_end =block.tellg();
	unsigned int tx_size=tx_end - tx_start;
	cout<<"Transaction size "<<dec<<tx_size << endl;
	block.seekg(tx_start,block.beg);
	unsigned char* tx;
	unsigned char* tx_hash1,*tx_hash2,*tx_hash;
	tx_hash1=(unsigned char*)malloc(32*sizeof(unsigned char));
	tx_hash2=(unsigned char*)malloc(32*sizeof(unsigned char));
	tx_hash=(unsigned char*)malloc(32*sizeof(unsigned char));
	tx = (unsigned char*)malloc(tx_size*sizeof(unsigned char));
	block.read(reinterpret_cast<char *>(&tx[0]), tx_size*sizeof(unsigned char));
	SHA256(tx, tx_size,tx_hash1);
	SHA256(tx_hash1, 32,tx_hash2);
	for(unsigned int i=0; i<32; ++i)
		cout <<std::setw(2)<<hex<<setfill('0')<<(int) tx_hash2[31-i];
	cout<<endl<<"--------------------------------------------"<<endl;
}

bool get_ip_txn(ifstream& block)
{
	unsigned char txid[32];
	unsigned char *scriptSig;
	uint32_t n,nsequence;
	uint64_t scriptSigLength;
	block.read(reinterpret_cast<char *>(&txid[0]), 32*sizeof(unsigned char));
	block.read(reinterpret_cast<char *>(&n), sizeof(n));
	scriptSigLength=varint(block);
	scriptSig =(unsigned char*)malloc(scriptSigLength*sizeof(unsigned char));
	block.read(reinterpret_cast<char *>(&scriptSig[0]), scriptSigLength*sizeof(unsigned char));
	block.read(reinterpret_cast<char *>(&nsequence), sizeof(nsequence));
	
	//cout<< "n "<<n<<endl;
	//cout<< "scriptSigLength "<<scriptSigLength<<endl;
	//cout<< "nsequence "<<nsequence<<endl;
	/*for(unsigned int i=0; i<32; ++i)
		cout <<std::setw(2)<<hex<<setfill('0')<<(int) txid[31-i];
	cout<<endl;
	for(uint64_t i=0; i<scriptSigLength; ++i)
		cout <<std::setw(2)<<hex<<setfill('0')<<(int) scriptSig[i];
	cout<<endl;*/
}
bool get_op_txn(ifstream& block)
{
	unsigned char *scriptPubKey;
	uint64_t nValue;
	uint64_t scriptPubKeyLength;
	block.read(reinterpret_cast<char *>(&nValue), sizeof(nValue));
	scriptPubKeyLength=varint(block);
	scriptPubKey =(unsigned char*)malloc(scriptPubKeyLength*sizeof(unsigned char));
	block.read(reinterpret_cast<char *>(&scriptPubKey[0]), scriptPubKeyLength*sizeof(unsigned char));
	cout<<"value of transaction "<<(float)((nValue*1.0)/1000000)<<endl;
	/*for(uint64_t i=0; i<scriptPubKeyLength; ++i)
		cout <<std::setw(2)<<hex<<setfill('0')<<(int) scriptPubKey[i];
	cout<<endl;*/
	
}
static inline void xor_salsa8(uint32_t B[16], const uint32_t Bx[16])
{
    uint32_t x00,x01,x02,x03,x04,x05,x06,x07,x08,x09,x10,x11,x12,x13,x14,x15;
    int8_t i;

    x00 = (B[0] ^= Bx[0]);
    x01 = (B[1] ^= Bx[1]);
    x02 = (B[2] ^= Bx[2]);
    x03 = (B[3] ^= Bx[3]);
    x04 = (B[4] ^= Bx[4]);
    x05 = (B[5] ^= Bx[5]);
    x06 = (B[6] ^= Bx[6]);
    x07 = (B[7] ^= Bx[7]);
    x08 = (B[8] ^= Bx[8]);
    x09 = (B[9] ^= Bx[9]);
    x10 = (B[10] ^= Bx[10]);
    x11 = (B[11] ^= Bx[11]);
    x12 = (B[12] ^= Bx[12]);
    x13 = (B[13] ^= Bx[13]);
    x14 = (B[14] ^= Bx[14]);
    x15 = (B[15] ^= Bx[15]);
    for (i = 0; i < 8; i += 2) {
#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
        /* Operate on columns. */
        x04 ^= R(x00+x12, 7); x09 ^= R(x05+x01, 7);
        x14 ^= R(x10+x06, 7); x03 ^= R(x15+x11, 7);

        x08 ^= R(x04+x00, 9); x13 ^= R(x09+x05, 9);
        x02 ^= R(x14+x10, 9); x07 ^= R(x03+x15, 9);

        x12 ^= R(x08+x04,13); x01 ^= R(x13+x09,13);
        x06 ^= R(x02+x14,13); x11 ^= R(x07+x03,13);

        x00 ^= R(x12+x08,18); x05 ^= R(x01+x13,18);
        x10 ^= R(x06+x02,18); x15 ^= R(x11+x07,18);

        /* Operate on rows. */
        x01 ^= R(x00+x03, 7); x06 ^= R(x05+x04, 7);
        x11 ^= R(x10+x09, 7); x12 ^= R(x15+x14, 7);

        x02 ^= R(x01+x00, 9); x07 ^= R(x06+x05, 9);
        x08 ^= R(x11+x10, 9); x13 ^= R(x12+x15, 9);

        x03 ^= R(x02+x01,13); x04 ^= R(x07+x06,13);
        x09 ^= R(x08+x11,13); x14 ^= R(x13+x12,13);

        x00 ^= R(x03+x02,18); x05 ^= R(x04+x07,18);
        x10 ^= R(x09+x08,18); x15 ^= R(x14+x13,18);
#undef R
    }
    B[0] += x00;
    B[1] += x01;
    B[2] += x02;
    B[3] += x03;
    B[4] += x04;
    B[5] += x05;
    B[6] += x06;
    B[7] += x07;
    B[8] += x08;
    B[9] += x09;
    B[10] += x10;
    B[11] += x11;
    B[12] += x12;
    B[13] += x13;
    B[14] += x14;
    B[15] += x15;
}

/* cpu and memory intensive function to transform a 80 byte buffer into a 32 byte output
   scratchpad size needs to be at least 63 + (128 * r * p) + (256 * r + 64) + (128 * r * N) bytes
   r = 1, p = 1, N = 1024
 */
unsigned char* scrypt_blockhash(const uint8_t* input)
{
    uint8_t scratchpad[SCRYPT_BUFFER_SIZE];
    uint32_t X[32];
    unsigned char* result;
	result=(unsigned char*)malloc(32*sizeof(unsigned char));
    uint32_t *V = (uint32_t *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));

    PKCS5_PBKDF2_HMAC((const char*)input, 80, input, 80, 1, EVP_sha256(), 128, (unsigned char *)X);

    for (uint16_t i = 0; i < 1024; i++) {
        memcpy(&V[i * 32], X, 128);
        xor_salsa8(&X[0], &X[16]);
        xor_salsa8(&X[16], &X[0]);
    }
    for (uint16_t i = 0; i < 1024; i++) {
        uint16_t j = 32 * (X[16] & 1023);
        for (uint16_t k = 0; k < 32; k++)
            X[k] ^= V[j + k];
        xor_salsa8(&X[0], &X[16]);
        xor_salsa8(&X[16], &X[0]);
    }

    PKCS5_PBKDF2_HMAC((const char*)input, 80, (const unsigned char*)X, 128, 1, EVP_sha256(), 32, (unsigned char*)result);
    return result;
}
