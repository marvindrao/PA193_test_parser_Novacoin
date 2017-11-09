/*
Notes on datastructures used:
1 Use uint32_t instead of unsigned int because unsigned int is not 32 bytes for all architecture.
  uint32_t is a macro and always is a 32 bits unsigned integer. 
*/

//#include "stdafx.h"
#include "block.h"
#include "Novacoin_block_parser_F.cpp"
/*
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


//#define SCRYPT_BUFFER_SIZE (131072 + 63)
//unsigned char* scrypt_blockhash(const uint8_t* input);
#endif
*/
using namespace std;
struct transaction;
struct block_header;
struct transaction_out;
struct transaction_in;

//bool Test_check_preheader(istream& block,struct block_header *b);
bool Test_check_preheader();

//bool Test_check_header(istream& block,struct block_header *b);
bool Test_check_header();

//bool Test_get_transactions(ifstream& block,struct transaction *t);
bool Test_get_transactions();
/*
//uint64_t varint(istream& block);

bool Test_get_ip_txn(ifstream& block,struct transaction_in *in);
bool Test_get_op_txn(ifstream& block,struct transaction_out *out);
void Test_print_hash(unsigned char* hash, int i);
void Test_print_block(struct block_header *b);
void Test_print_transaction(struct transaction *t);
void Test_print_transaction_in(struct transaction_in *in);
void Test_print_transaction_out(struct transaction_out *out);
*/

//int main(int argv, char **argc)
int main()
{
	ifstream block;
	struct block_header b;
	struct transaction *t;
	/*
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
	*/
	//if(!Test_check_preheader(block,&b))
	if(!Test_check_preheader())
		return -99;
	else
		cout<<"Preheader Check Function Test Passed"<<endl;
	
	cout<<endl;
	
	if(!Test_check_header())
		return -99;
	else
		cout<<"header Check Function Test Passed"<<endl;
		cout<<endl;
	if(!Test_get_transactions())
		return -99;
	else
		cout<<"Get Transaction, Print_Hash & Print_Transaction Functions Test Passed"<<endl;
	/*
	cout<<endl;
	b.n_t=varint(block);
	t=(struct transaction *)malloc(b.n_t*sizeof(struct transaction));
	for(uint64_t i = 0;i<b.n_t;i++)
	{
		get_transactions(block,&t[i]);
	}
	b.tx=t;
	print_block(&b);
	*/
}
/*
void Test_print_hash(unsigned char* hash, int len)
{
	for(unsigned int i=0; i<len; ++i)
		cout <<setw(2)<<hex<<setfill('0')<<(int)hash[i];
}
*/
/*
void Test_print_block(struct block_header *b)
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
	for(int i=0;i<b->n_t;i++)
	{
		cout<<"Transaction "<<i+1 << endl;
		print_transaction(&b->tx[i]);
	}

}

*/
/*
void Test_print_transaction(struct transaction *t)
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
	for(int i=0;i<t->ip_n;i++)
	{
		cout<<"Input "<<dec<<i+1<<endl;
		print_transaction_in(&t->tx_input[i]);
	}
	for(int i=0;i<t->op_n;i++)
	{
		cout<<"Output "<<dec<<i+1<<endl;
		print_transaction_out(&t->tx_output[i]);
	}
}
*/
/*
void Test_print_transaction_in(struct transaction_in *in)
{
	cout<<"Referred TxId :";
	print_hash(in->txid,32);
	cout<<endl;
	cout<<"Referred output in TxId :"<<dec<<in->n<<endl;

}
*/
/*
void Test_print_transaction_out(struct transaction_out *out)
{
	cout<<"Value :"<<float(out->value/1000000.0)<<endl;
	
}
*/
//bool Test_check_preheader(istream& test_block,struct block_header *test_b)
bool Test_check_preheader()
{
	//uint32_t test_magic= 0;
	uint64_t test_bsize = 0;
	ifstream test_block,test1_block;
	struct block_header test_b, test1_b;
	unsigned char* test_hash,test1_hash;
	test_hash=(unsigned char*)malloc(32*sizeof(unsigned char));
	int blockHashMatch =0;
	bool cpHeader;
	
	// Expected Value of magic Number
	//test_magic= 0xe5e9e8e4;
		
	
	// Testing test_block_1

	// Test 1 Valid Preheader
	cout << "*******************************************"<< endl;	
	cout << "Testing check_preheader"<< endl;	
	cout << "*******************************************"<< endl;	
	
	test_block.open("test_block_1",ios::binary);
	if (!test_block.is_open())
	{
		cout << "Test Block file not Found" << endl;
		return false;
	}
	
	unsigned char test_hash_c[32]= {0x00, 0x00,0x00,0x19,0xb1,0xc2,0xd2,0xa5,0xae,0x57,0xc7,0xb4,0xbc,0xb9,0xe0,0x46,0x0a,0x18,0x86,0x6a,0x26,0x9c,0x4b,0xf4,0xa2,0xea,0x7f,0x55,0x26,0xff,0xa1,0xa8};
		// Expected Value of Block Size
	test_bsize = 192;
	
	cout << "Testing check_preheader:Test1 with Valid Preheader"<< endl;	
	memcpy(test_hash,test_hash_c,32);
	/*
	if(!check_preheader(test_block,&test_b))
	{
		cout << "Test1 check_preheader Function Result"<< endl;	
	}
	else	//return true;
	{
		cout << "Test1 check_preheader Function Result"<< endl;	
		//return -99;
		//return false;
	}
	*/
	cpHeader=check_preheader(test_block,&test_b);
	cout << "Test1 : check_preheader: Started"<< endl;		
	
	//	cout << "Test1 check_preheader: Passed"<< endl;	
		//cout << "Magic Number read:"<< hex << magic << endl;
		cout <<"Test 1: Expected Size of File:"<< dec << test_bsize<< endl;
		cout <<"Test 1: File Size from parser:"<< dec << test_b.block_size<< endl;
		if(test_bsize != test_b.block_size)
		{
			cout << "Test1 : check_preheader: Failed : ERROR IN BlockSize"<< endl;	
			//return(-99);
			return false;
		}
		else
		{
			cout << "Test1 check_preheader: Passed : BlockSize Calculated Correctly"<< endl;	
		}
		blockHashMatch =0;
		for(int i=0; i<32; ++i)
		{
			//cout <<std::setw(2)<<hex<<setfill('0')<<(int) hash[31-i];
			if (test_b.b_hash[i]==test_hash[i])
			blockHashMatch++;
		}
		if(blockHashMatch != 32)
		{
			cout << "Test1 : check_preheader: Failed : ERROR IN BlockHash"<< endl;	
			//return(-99);
			return false;
		}
		else
		{
			cout << "Test1 : check_preheader: Passed : BlockHash Calculated Correctly"<< endl;	
			print_hash(test_b.b_hash,32);
		}
		cout<<endl;
			
	
	cout << "*******************************************"<< endl;		
	
	//Test 2 Invalid Preheader
	cout << "Testing check_preheader:Test2"<< endl;	
	
	// Testing test_block_1

	// Test 1 Valid Preheader
	
	test1_block.open("test_block_3a",ios::binary);
	if (!test1_block.is_open())
	{
		cout << "Test 2 Block file not Found" << endl;
		return false;
	}
	
	//unsigned char test_hash_c[32]= {0x00, 0x00,0x00,0x19,0xb1,0xc2,0xd2,0xa5,0xae,0x57,0xc7,0xb4,0xbc,0xb9,0xe0,0x46,0x0a,0x18,0x86,0x6a,0x26,0x9c,0x4b,0xf4,0xa2,0xea,0x7f,0x55,0x26,0xff,0xa1,0xa8};
		// Expected Value of Block Size
	test_bsize = 192;
	
	cout << "Test 2:Testing check_preheader: with InValid Preheader"<< endl;	
	memcpy(test_hash,test_hash_c,32);
	/*
	if(!check_preheader(test_block,&test_b))
	{
		cout << "Test1 check_preheader Function Result"<< endl;	
	}
	else	//return true;
	{
		cout << "Test1 check_preheader Function Result"<< endl;	
		//return -99;
		//return false;
	}
	*/
	 cpHeader=check_preheader(test_block,&test1_b);
	cout << "Test 2:check_preheader: Started"<< endl;		
	
	//	cout << "Test1 check_preheader: Passed"<< endl;	
		//cout << "Magic Number read:"<< hex << magic << endl;
		cout <<"Test 2: Expected Size of File:"<< dec << test_bsize<< endl;
		cout <<"Test 2: File Size from parser:"<< dec << test1_b.block_size<< endl;
		if(test_bsize != test1_b.block_size)
		{
			cout << "Test 2:check_preheader: Passed : ERROR IN BlockSize"<< endl;	
			//return(-99);
			
		}
		else
		{
			cout << "Test 2:check_preheader: Failed : BlockSize Calculated Correctly"<< endl;	
			return false;
		}
		blockHashMatch =0;
		for(int i=0; i<32; ++i)
		{
			//cout <<std::setw(2)<<hex<<setfill('0')<<(int) hash[31-i];
			if (test1_b.b_hash[i]==test_hash[i])
			blockHashMatch++;
		}
		if(blockHashMatch != 32)
		{
			cout << "Test 2:check_preheader: Passed : ERROR IN BlockHash"<< endl;	
			//return(-99);
			//return false;
		}
		else
		{
			cout << "Test 2:check_preheader: Failed : BlockHash Calculated Correctly"<< endl;	
			print_hash(test1_b.b_hash,32);
		}
		
		cout << endl;
	/*
	if(!check_preheader(test2_block,&test_b))
		cout << "Test2 check_preheader: Passed"<< endl;	
	else
		cout << "Test2 check_preheader: Failed"<< endl;	
	*/
	return true;
	
}

//bool Test_check_header(istream& test_block,struct block_header *test_b)
bool Test_check_header()
{
	uint32_t nVersionT;
	//unsigned char hashPrevBlockT[32];
	//unsigned char hashMerkleRootT[32]	;
	uint32_t nTimeT;
	uint32_t nBitsT;
	uint32_t nNonceT;
	int hpMatch=0;
	int hmMatch=0;
	struct block_header test_b, test1_b;
	ifstream test_block, test1_block;
	bool cHeader;
	//test_block.open("test_block_1-Header",ios::binary);
	cout << "*******************************************"<< endl;	
	cout << "Testing check_header"<< endl;	
	cout << "*******************************************"<< endl;	
	
	cout << "Test1 : check_header: Started"<< endl;		
	
	test_block.open("test_block_1",ios::binary);
	test_block.seekg(8, ios::beg);
	
	if (!test_block.is_open())
	{
		cout << "Test Block file not Found" << endl;
		return false;
	}
	
	
	nVersionT=2;
	//time_t tx_time=b->nTime;
	//cout<<"nTime "<<ctime(&tx_time);
	nTimeT = 1360426982; //Sat Feb  9 17:23:02 2013;
	unsigned char hashPrevBlockT[32]= {0x00,0x00,0x04,0xa7,0xc2,0xe3,0x86,0x28,0xf7,0x98,0xa6,0xb5,0xe6,0x17,0x0d,0xd7,0x96,0x76,0x2d,0x47,0x40,0x46,0x5a,0x64,0xdf,0xf2,0x69,0xab,0x31,0x8f,0xab,0x0e};
	unsigned char hashMerkleRootT[32]= {0xef,0x87,0x75,0x18,0xde,0x4f,0x43,0xd7,0xb5,0x9f,0x3c,0x12,0xc1,0x5e,0xe3,0x39,0xe2,0x89,0xd2,0xad,0x8f,0x8e,0xd2,0x1b,0x3c,0xde,0xbd,0x78,0x2f,0x1b,0x5c,0xdb};
	nBitsT = 504363236;
	nNonceT = 3579149981;
	hpMatch=0;
	hmMatch=0;
	//check_preheader(test_block,&test_b);
	cHeader=check_header(test_block,&test_b);
	
	if(nVersionT == test_b.nVersion)
	{
		cout<<"Test1: nVersion Matches"<<endl;
		
	}
	else{
		cout<<"Test1: nVersion Not Matches"<<endl;
		//return false;
	}
	
	for(unsigned int i=0; i<32; ++i){
		
		if(test_b.hashPrevBlock[i] == hashPrevBlockT[i])
			hpMatch++;
		if(test_b.hashMerkleRoot[i] == hashMerkleRootT[i])
			hmMatch++;
	}
	
	if(hpMatch == 32)
	{
		cout<<"Test1: hash Previous Matches"<<endl;
		
	}
	else{
		cout<<"Test1: hash Previous Not Matches"<<endl;
		return false;
	}
	
	
	if(hmMatch == 32)
	{
		cout<<"Test1: hash merkel Matches"<<endl;
		
	}
	else{
		cout<<"Test1: hash merkel Not Matches"<<endl;
		return false;
	}

	if(nTimeT == test_b.nTime)
	{
		cout<<"Test1: Time Matches"<<endl;
		
	}
	else{
		cout<<"Test1: Time Not Matches"<<endl;
		return false;
	}
	
	if(nBitsT == test_b.nBits)
	{
		cout<<"Test1: nBits Matches"<<endl;
		
	}
	else{
		cout<<"Test1: nBits Not Matches"<<endl;
		return false;
	}
	if(nNonceT == test_b.nNonce)
	{
		cout<<"Test1: nNonce Matches"<<endl;
		
	}
	else{
		cout<<"Test1: nNonce Not Matches"<<endl;
		return false;
	}
	
	cout<<endl;
	
	
	
	//test_block.close();
	
	cout << "*******************************************"<< endl;	
	
	cout << "Test2 : check_header: Started"<< endl;		
	
	test1_block.open("block2",ios::binary);
	test1_block.seekg(8, ios::beg);
	
	if (!test1_block.is_open())
	{
		cout << "Test Block 2 file not Found" << endl;
		return false;
	}
	
	
	nVersionT=6;
	//time_t tx_time=b->nTime;
	//cout<<"nTime "<<ctime(&tx_time);
	nTimeT = 1477442541; //Sat Feb  9 17:23:02 2013;
	unsigned char hashPrevBlockT1[32]= {0x8a,0x4f,0xa8,0x85,0xcd,0x47,0x71,0x2f,0x8e,0x55,0x8c,0x43,0x10,0x6c,0xdf,0x01,0x56,0x84,0xe3,0x12,0x41,0xa0,0x96,0xda,0xf0,0x48,0x90,0x0a,0x5c,0x18,0x7d,0xa7};
	unsigned char hashMerkleRootT1[32]= {0xa0,0x65,0xef,0x17,0x93,0xf5,0x3e,0x53,0x18,0x1d,0x6e,0x62,0x7d,0xbd,0xf6,0x7b,0x31,0xb6,0x89,0xa1,0x3b,0x32,0x37,0xb2,0x5b,0x82,0x26,0x26,0x94,0xe3,0x7f,0x0f};
	nBitsT = 473003220;
	nNonceT = 0;
	hpMatch=0;
	hmMatch=0;
	//check_preheader(test_block,&test1_b);
	cHeader=check_header(test1_block,&test1_b);
	//memcpy(hashPrevBlockT,hashPrevBlockT1,32);
	//memcpy(hashMerkleRootT,hashMerkleRootT1,32);
	
	if(nVersionT == test1_b.nVersion)
	{
		cout<<"Test2: nVersion Matches"<<endl;
		
	}
	else{
		cout<<"Test2: nVersion Not Matches"<<endl;
		return false;
	}
	
	for(unsigned int i=0; i<32; ++i){
		
		if(test1_b.hashPrevBlock[i] == hashPrevBlockT1[i])
			hpMatch++;
		if(test1_b.hashMerkleRoot[i] == hashMerkleRootT1[i])
			hmMatch++;
	}
	
	if(hpMatch == 32)
	{
		cout<<"Test2: hash Previous Matches"<<endl;
		
	}
	else{
		cout<<"Test2: hash Previous Not Matches"<<endl;
		return false;
	}
	
	
	if(hmMatch == 32)
	{
		cout<<"Test2: hash merkel Matches"<<endl;
		
	}
	else{
		cout<<"Test2: hash merkel Not Matches"<<endl;
		return false;
	}

	if(nTimeT == test1_b.nTime)
	{
		cout<<"Test2: Time Matches"<<endl;
		
	}
	else{
		cout<<"Test2: Time Not Matches"<<endl;
		return false;
	}
	
	if(nBitsT == test1_b.nBits)
	{
		cout<<"Test2: nBits Matches"<<endl;
		
	}
	else{
		cout<<"Test2: nBits Not Matches"<<endl;
		return false;
	}
	if(nNonceT == test1_b.nNonce)
	{
		cout<<"Test2: nNonce Matches"<<endl;
		
	}
	else{
		cout<<"Test2: nNonce Not Matches"<<endl;
		return false;
	}
	
	return true;
}



bool Test_get_transactions()
{
	uint64_t n_tT; 
	struct transaction *tT;
	uint32_t versionT;
	uint32_t timestampT;//,lock_timeT;
	uint32_t lenT;		
	uint64_t ip_nT,op_nT;
	struct transaction_in *inT;
	struct transaction_out *outT;
		
	
	//unsigned char *scriptSigT;
	uint32_t nT; //,nsequenceT;
	//uint64_t scriptSigLengthT;
	
	//uint64_t nValueT;
	//uint64_t scriptPubKeyLengthT;
	//unsigned char *scriptPubKeyT;
	
	//int tx_startT = block.tellg();
	struct block_header test_b; //, test1_b;
	ifstream test_block, test1_block;
	
	
	// Checking Transaction No. 6 Input No. 100 of Block
	
	cout << "*******************************************"<< endl;	
	
	cout << "Test : Transaction Details: Started"<< endl;		
	
	cout << "*******************************************"<< endl;	
	
	test_block.open("block2",ios::binary);
	test_block.seekg(88, ios::beg);
	
	if (!test_block.is_open())
	{
		cout << "Test Block 2 file not Found" << endl;
		return false;
	}
	
	test_b.n_t=varint(test_block);
	tT=(struct transaction *)malloc(test_b.n_t*sizeof(struct transaction));
	for(uint64_t i = 0;i<test_b.n_t;i++)
	{
		get_transactions(test_block,&tT[i]);
	}
	
	//unsigned char txidT[32],refTransHashT[32];
	unsigned char txidT[32]= {0xed,0xa0,0x40,0x89,0x78,0x35,0x60,0x4a,0xce,0xea,0x96,0xe4,0xd5,0x0e,0x5a,0x3d,0x3f,0xc9,0x7f,0x35,0x58,0x47,0xd4,0x33,0xce,0x09,0xb0,0xb9,0x12,0x1a,0xcf,0x5b};
	
	unsigned char refTransHashT[32]= {0x13,0x76,0x6f,0x95,0xe4,0xa0,0x5e,0x9a,0x60,0xe9,0x54,0x74,0x19,0xee,0xb4,0x95,0x52,0x4c,0x96,0x65,0xae,0x53,0xb8,0x0b,0x55,0x32,0xc3,0xb4,0xfe,0xfe,0x0d,0x6f};
	
	test_b.tx=tT;
	n_tT = 6;
	//transaction *tT;
	versionT=1;
	timestampT=1477440956 ;
	//lock_timeT;
	ip_nT=290;
	op_nT=1;
	lenT = 51507;
	//*inT;
	//*outT;
	
	nT = 1;
	float outputValT = 50;
	
	cout<<"Number of Transactions : "<<test_b.n_t<<endl; // Number of Transactions
	//print_transaction(&test_b->tx[5]);
	
	//cout<<"Version "<<(test_b.tx[5]).version<<endl;
	struct transaction *t;
	t = &(test_b.tx[5]);
	cout<<"Transaction Version : "<<t->version<<endl;
	time_t tx_time=t->timestamp;
	if(tx_time == timestampT)
	{
		cout<<"Transaction Time: Matches "<<ctime(&tx_time);
	}
	else
	{
		cout<<"Transaction Time: NOt Matches "<<endl;
		return false;
	}
	cout<<"Transaction Time "<<ctime(&tx_time);
	if(t->ip_n == ip_nT)
	{
		cout<<"Number of inputs: Matches "<<dec<<t->ip_n<<endl;
	}
	else
	{
		cout<<"Number of inputs: Not Matches"<<endl;//dec<<t->ip_n<<endl;
		return false;
	}
	if(t->op_n == op_nT)
	{
		cout<<"Number of outputs: Matches "<<dec<<t->op_n<<endl;
	}
	else
	{
		cout<<"Number of outputs: Not Matches"<<endl; //<<dec<<t->ip_n<<endl;
		return false;
	}
	
	//tx_time=t->lock_time;
	///cout<<"Transaction Lock Time/Height "<<dec<<t->lock_time<<endl;
	
	if(t->len == lenT)
	{
		cout<<"Transaction Length: Matches "<<dec<<t->len<<endl;
	}
	else
	{
		cout<<"Transaction Length: Not Matches"<<endl; //<<dec<<t->ip_n<<endl;
		return false;
	}
	//cout<<"Transaction Length "<<t->len<<endl;
	
	//int refTransOutIDT;
	//bool txnStatus = true;
	// Compare Here Transaction Hash
	cout<<"Transaction Hash :";
	print_hash(t->tid,32);
	cout<<endl;
	// Compare Here Input Hash
	cout<<"Input: "<<dec<<99+1<<endl;
	print_transaction_in(&t->tx_input[99]);
	cout<<"Output: "<<dec<<0+1<<endl;
	print_transaction_out(&t->tx_output[0]);
	
	
	/*
	*scriptSigT;
	nT,nsequenceT;
	scriptSigLengthT;
	
	nValueT;
	scriptPubKeyLengthT;
	*scriptPubKeyT;
	*/
	/*
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
	unsigned char* tx;
	unsigned char* tx_hash1,*tx_hash2,*tx_hash;
	tx_hash1=(unsigned char*)malloc(32*sizeof(unsigned char));
	tx_hash2=(unsigned char*)malloc(32*sizeof(unsigned char));
	tx_hash=(unsigned char*)malloc(32*sizeof(unsigned char));
	tx = (unsigned char*)malloc(tx_size*sizeof(unsigned char));
	block.read(reinterpret_cast<char *>(&tx[0]), tx_size*sizeof(unsigned char));
	SHA256(tx, tx_size,tx_hash1);
	SHA256(tx_hash1, 32,tx_hash2);
	t->version=version;
	t->timestamp=timestamp;
	t->lock_time=lock_time;
	t->len=tx_size;
	t->ip_n=ip_n;
	t->op_n=op_n;
	t->tx_input=in;
	t->tx_output=out;
	for(unsigned int i=0; i<32; ++i)
		t->tid[i] = tx_hash2[31-i];
	*/
	return true;
}

/*
bool Test_get_ip_txn(ifstream& block,struct transaction_in *in)
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

*/

/*
bool Test_get_op_txn(ifstream& block,struct transaction_out *out)
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
*/
/* cpu and memory intensive function to transform a 80 byte buffer into a 32 byte output
   scratchpad size needs to be at least 63 + (128 * r * p) + (256 * r + 64) + (128 * r * N) bytes
   r = 1, p = 1, N = 1024
 */
 /*
unsigned char* Test_scrypt_blockhash(const uint8_t* input)
{
    const uint8_t* test_input;
    unsigned char* test_result;
	unsigned char* expected_test_result;
	//Expected Output
	//00000019b1c2d2a5ae57c7b4bcb9e0460a18866a269c4bf4a2ea7f5526ffa1a8
//	expected_test_result = {0x00, 0x00,0x00,0x19,0xb1,0xc2,0xd2,0xa5,0xae,0x57,0xc7,0xb4,0xbc,0xb9,0xe0,0x46,0x0a,0x18,0x86,0x6a,0x26,0x9c,0x4b,0xf4,0xa2,0xea,0x7f,0x55,0x26,0xff,0xa1,0xa8};
	// Hash from print_hash function 
	test_result=(unsigned char*)malloc(32*sizeof(unsigned char));
	test_result = scrypt_blockhash(test_input);
	print_hash(test_result,32);
	//Compare expected ourtput from result
	//expected_test_result
	
}
*/