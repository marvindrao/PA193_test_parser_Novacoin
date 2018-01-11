#include "block.h"
#include <iostream>
#include <math.h>
#include <fstream>
#include <stdint.h>
#include <stdlib.h>
#include <vector>
#include <iomanip>
#include <cstring>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <time.h>
#include "functions.h"
#include <iomanip>
//code modification for pull request testing!!!
bool verify_timestamp(uint32_t timestamp)
{
	const uint32_t tm = 60*60;
	uint32_t currentTime = static_cast<uint32_t>(time(NULL));
    return (timestamp-tm)<currentTime;
}


bool verify_transaction(transaction *tx)
{
	if(tx->ip_n==0 || tx->op_n == 0)
		return false;
	//if(verify_timestamp(tx->timestamp))
		//return false;
	return true;
}
bool isCoinbase(transaction *tx)
{
	if(tx->ip_n!=1)
	{
		return false;
	}
	unsigned char zero_hash[32];
	memset(zero_hash,0,32);
	if(memcmp(tx->tx_input->txid,zero_hash,32)!=0)
		return false;
	return true;
}
	

void destroy_transaction_out(struct transaction_out *tout)
{
	free(tout->scriptPubKey);
	//free(tout);
}
void destroy_transaction_in(struct transaction_in *tin)
{
	free(tin->scriptSig);
	//free(tin);
}
void destroy_transaction(struct transaction *tx)
{
	uint64_t ip_n;
	ip_n=tx->ip_n;
	for(uint64_t i = 0;i<ip_n;i++)
	{
		destroy_transaction_in(&tx->tx_input[i]);
	}
	uint64_t op_n;
	op_n=tx->op_n;
	for(uint64_t i = 0;i<op_n;i++)
	{
		destroy_transaction_out(&tx->tx_output[i]);
	}
	free(tx->tx_input);
	free(tx->tx_output);
}
void destroy_block(struct block_header *b)
{
	uint64_t n_t;
	n_t=b->n_t;
	for(uint64_t i = 0;i<n_t;i++)
	{
		destroy_transaction(&b->tx[i]);
	}
	free(b->tx);
}
void verify_block(struct block_header *b)
{
	if(!isCoinbase(&b->tx[0]))
		cout<<"First transaction of block is not coinbase"<<endl;
	for(uint64_t i=1;i<b->n_t;i++)
	{
		if(isCoinbase(&b->tx[i]))
			cout<<"Invalid Transaction. Transaction other than first coinbase"<<endl;
	}
	for(uint64_t i=0;i<b->n_t;i++)
	{
		if(!verify_transaction(&b->tx[i]))
			cout<<"Invalid Transaction. Zero input/output encountered or timestamp not valid."<<endl;
	}
	if(b->n_t == 0)
		cout<<"Invalid Block since number of transactions 0"<<endl;
	//if(verify_timestamp(b->nTime))
	//	cout<<"Invalid timestamp in blockheader"<<endl;
}
void verify_block_pair(struct block_header *b,struct block_header *pb) //this function verify block by compairing privious hash of block with previous hash
{
	if(!verify_merkle_root(b))
	{
		cout<<"Merkle Root of block invalid"<<endl;
	}
	if(!verify_merkle_root(pb))
	{
		cout<<"Merkle Root of previous block invalid"<<endl;
	}
	if(memcmp(b->hashPrevBlock,pb->b_hash,32)!=0)
		cout<<"Previous block hash invalid"<<endl;
	verify_block(b);
	verify_block(pb);
	
	
}
//this function use to read block
void read_block(ifstream& block,struct block_header *b)
{
	struct transaction *t=NULL;
	check_preheader(block,b);
	check_header(block,b);
	cout<<endl;
	b->n_t=varint(block);
	t=(struct transaction *)malloc(b->n_t*sizeof(struct transaction));
	for(uint64_t i = 0;i<b->n_t;i++)
	{
		get_transactions(block,&t[i]);
	}
	b->tx=t;
	print_block(b);
}//this function use to check header of block
bool check_header(istream& block,struct block_header *b)
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
	
	b->nVersion=nVersion;
	b->nTime=nTime;
	b->nBits=nBits;
	b->nNonce=nNonce;
	for(unsigned int i=0; i<32; ++i)
		b->hashPrevBlock[i] = hashPrevBlock[31-i];
	for(unsigned int i=0; i<32; ++i)
		b->hashMerkleRoot[i]= hashMerkleRoot[31-i];
	return true;
	
}
void rev_hash(unsigned char* hash, int len)
{
	unsigned char *tmp;
	tmp=(unsigned char*)malloc(len*sizeof(unsigned char));
	for(int i=0;i<len;i++)
	{
		tmp[i]=hash[len-i-1];
	}
	memcpy(hash,tmp,len);
	free(tmp);
}
//print hash of block
void print_hash(unsigned char* hash, int len)
{
	for(int i=0; i<len; ++i)
		cout <<setw(2)<<hex<<setfill('0')<<(int)hash[i];
}
//print all component of block like hash number of transaction....etc
void print_block(struct block_header *b)
{
	cout<<"nVersion "<<b->nVersion<<endl;
	cout<<"nBits "<<b->nBits<<endl;
	cout<<"nNonce "<<b->nNonce<<endl;
	time_t tx_time=b->nTime;
	cout<<"nTime "<<ctime(&tx_time);
	cout<<"Number of Transactions "<<b->n_t<<endl;
	cout<<"PrevHash: ";
	print_hash(b->hashPrevBlock,32);
	cout<<endl;
	cout<<"MerkleRoot: ";
	print_hash(b->hashMerkleRoot,32);
	cout<<endl;
	cout<<"Block Hash: ";
	print_hash(b->b_hash,32);
	cout<<endl;
	cout<<"BlockSize "<<dec<<b->block_size<<endl;
	for(uint64_t i=0;i<b->n_t;i++)
	{
		cout<<"Transaction "<<i+1 << endl;
		print_transaction(&b->tx[i]);
	}

}
//this function print Number of input and output Transaction in a block
void print_transaction(struct transaction *t)
{
	cout<<"Version "<<t->version<<endl;
	time_t tx_time=t->timestamp;
	cout<<"Transaction Time "<<ctime(&tx_time);
	cout<<"Number of inputs "<<dec<<t->ip_n<<endl;
	cout<<"Number of outputs "<<t->op_n<<endl;
	//tx_time=t->lock_time;
	///cout<<"Transaction Lock Time/Height "<<dec<<t->lock_time<<endl;
	cout<<"Transaction Length "<<t->len<<endl;
	cout<<"Transaction Hash :";
	print_hash(t->tid,32);
	cout<<endl;
	/*for(int i=0;i<t->ip_n;i++)
	{
		cout<<"Input "<<dec<<i+1<<endl;
		print_transaction_in(&t->tx_input[i]);
	}
	for(int i=0;i<t->op_n;i++)
	{
		cout<<"Output "<<dec<<i+1<<endl;
		print_transaction_out(&t->tx_output[i]);
	}*/
}
//
void print_transaction_in(struct transaction_in *in)
{
	cout<<"Referred TxId :";
	print_hash(in->txid,32);
	cout<<endl;
	cout<<"Referred output in TxId :"<<dec<<in->n<<endl;

}
void print_transaction_out(struct transaction_out *out)
{
	cout<<"Value :"<<std::fixed << std::setprecision( 10 ) <<float(out->value/1000000.0)<<endl;
	
}
void double_SHA256(unsigned char *input, int ip_size, unsigned char *output)
{
	unsigned char temp[32],temp2[32];
	SHA256(input, ip_size,temp);
	SHA256(temp, 32,temp2);
	for(unsigned int i=0; i<32; ++i)
		output[i] = temp2[31-i];
}
void compute_merkle_root(struct block_header *b, unsigned char *merkle_root)
{
	uint64_t n_t;
	n_t=b->n_t;
	if(n_t==1)
	{
			memcpy(merkle_root,b->tx[0].tid,32);
			return;
	}
	n_t = ((b->n_t%2==0)?b->n_t:(b->n_t+1));
	
	unsigned char **tids= (unsigned char**) malloc(n_t*sizeof(unsigned char*));
	for (uint64_t i = 0; i < n_t; i++ )
	{
    tids[i] = (unsigned char*) malloc(32*sizeof(char));
	}
	
	for(uint64_t i=0; i <b->n_t;i++)
	{
		memcpy(tids[i],b->tx[i].tid,32);
	}
	memcpy(tids[n_t-1],b->tx[b->n_t-1].tid,32);
	uint64_t lev=n_t;
	while(lev!=1)
	{
		int j=0;
		for(uint64_t i=0;i<lev;i=i+2)
		{
			
			unsigned char temp[64];
			memcpy(temp,tids[i],32);
			rev_hash(temp,32);
			memcpy(&temp[32],tids[i+1],32);
			rev_hash(&temp[32],32);
			double_SHA256(temp,64,tids[j]);
			j++;
		}
		if(j%2 != 0 && j != 1)
		{
			memcpy(tids[j],tids[j-1],32);
			j++;
		}
		lev=j;
	}
	memcpy(merkle_root,tids[0],32);
	for (uint64_t i = 0; i < n_t; i++ )
	{
		free(tids[i]);
	}
	free(tids);
}
bool verify_merkle_root(struct block_header *b)
{
	unsigned char merkle_root[32];
	compute_merkle_root(b,merkle_root);
	if(memcmp(merkle_root,b->hashMerkleRoot,32)==0)
		return true;
	return false;
		
}
//header of previous block 
bool check_preheader(istream& block,struct block_header *b)
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
	//hash=(unsigned char*)malloc(32*sizeof(unsigned char));
	block.read(reinterpret_cast<char *>(&input[0]), bfsize*sizeof(unsigned char));
	/*for(unsigned int i=0; i<bfsize; ++i)
		cout <<std::setw(2)<<hex<<setfill('0')<<(int) input[i];*/
	hash = scrypt_blockhash(input);
	for(unsigned int i=0; i<32; ++i)
	{
		b->b_hash[i]=hash[31-i];
	}
	cout<<endl;
	b->block_size = bfsize;
	block.clear();
	block.seekg(beg,block.beg);
	free(input);
	free(hash);
	return true;
}
//this function read header parameter
void get_header(istream& block,struct block_header *b)
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
	
	b->nVersion=nVersion;
	b->nTime=nTime;
	b->nBits=nBits;
	b->nNonce=nNonce;
	for(unsigned int i=0; i<32; ++i)
		b->hashPrevBlock[i] = hashPrevBlock[31-i];
	for(unsigned int i=0; i<32; ++i)
		b->hashMerkleRoot[i]= hashMerkleRoot[31-i];
	return;
	
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
	return 0;
}


void get_transactions(ifstream& block,struct transaction *t)
{
	
	uint32_t version;
	uint32_t timestamp,lock_time;
	uint64_t ip_n,op_n;
	struct transaction_in *in;
	struct transaction_out *out;
	int tx_start = block.tellg();
	block.read(reinterpret_cast<char *>(&version), sizeof(version));
	block.read(reinterpret_cast<char *>(&timestamp), sizeof(timestamp));
	ip_n=varint(block);
	in=(struct transaction_in *)malloc(ip_n*sizeof(struct transaction_in));
	for(uint64_t i =0;i<ip_n;i++)
	{
		get_ip_txn(block,&in[i]);
	}
	op_n=varint(block);
	out=(struct transaction_out *)malloc(op_n*sizeof(struct transaction_out));
	
	for(uint64_t i =0;i<op_n;i++)
	{
		get_op_txn(block,&out[i]);
	}
	
    block.read(reinterpret_cast<char *>(&lock_time), sizeof(lock_time));
	int tx_end =block.tellg();
	unsigned int tx_size=tx_end - tx_start;
	block.seekg(tx_start,block.beg);
	unsigned char *tx;
	unsigned char *tx_hash;
	tx_hash=(unsigned char*)malloc(32*sizeof(unsigned char));//allocate memory
	tx = (unsigned char*)malloc(tx_size*sizeof(unsigned char));//allocate memory
	block.read(reinterpret_cast<char *>(&tx[0]), tx_size*sizeof(unsigned char));
	double_SHA256(tx,tx_size,tx_hash);
	t->version=version;
	t->timestamp=timestamp;
	t->lock_time=lock_time;
	t->len=tx_size;
	t->ip_n=ip_n;
	t->op_n=op_n;
	t->tx_input=in;
	t->tx_output=out;
	memcpy(t->tid,tx_hash,32);
	free(tx);
	free(tx_hash);
	}
	
//input transaction transaction parameter 	
void get_ip_txn(ifstream& block,struct transaction_in *in)
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
	in->n =n;
	in->scriptSigLength =scriptSigLength;
	in->nSequence=nsequence;
	in->scriptSig=scriptSig;
	for(int i=0;i<32;i++)
		in->txid[i]=txid[31-i];
}
//to read o/p transaction parameter
void get_op_txn(ifstream& block,struct transaction_out *out)
{
	unsigned char *scriptPubKey;
	uint64_t nValue;
	uint64_t scriptPubKeyLength;
	block.read(reinterpret_cast<char *>(&nValue), sizeof(nValue));
	scriptPubKeyLength=varint(block);
	scriptPubKey =(unsigned char*)malloc(scriptPubKeyLength*sizeof(unsigned char));
	block.read(reinterpret_cast<char *>(&scriptPubKey[0]), scriptPubKeyLength*sizeof(unsigned char));
	//cout<<"value of transaction "<<(float)((nValue*1.0)/1000000)<<endl;
	out->value=nValue;
	out->scriptPubKeyLength=scriptPubKeyLength;
	out->scriptPubKey=scriptPubKey;
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
