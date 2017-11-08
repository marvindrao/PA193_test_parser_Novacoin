/*
Notes on datastructures used:
1 Use uint32_t instead of unsigned int because unsigned int is not 32 bytes for all architecture.
  uint32_t is a macro and always is a 32 bits unsigned integer. 
*/

//#include "stdafx.h"
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
using namespace std;

//void get_tx_list(struct block_header *b, unsigned char **)
int main(int argv, char **argc)
{
	ifstream block,prevblock;
	struct block_header b,pb;
	
	if(argv==3)
	{
			block.open(argc[1], ios::binary);
			prevblock.open(argc[2],ios::binary);
	}
	else{
		printf("Usage is parser <block> <prevblock>\n");
		return -99;
	}
	cout << "NovaCoin Block Parser"<<endl;
	if (!block.is_open() || !prevblock.is_open())
	{
		cout << "file not open" << endl;
		return -99;
	}
	read_block(block,&b);
	read_block(prevblock,&pb);
	verify_block(&b,&pb);	
	destroy_block(&b);
	destroy_block(&pb);

	//print_block(&b);
	//compute_merkle_root(&b);
	
	/*block number 45323 merkle root calculaions 
	unsigned char h1[32]={0x7f,0x6b,0xb1,0x09,0xb9,0x43,0x7c,0xe2,0x5b,0x81,0x53,0x93,0x3d,0x02,0x14,0x75,0x36,0x21,0x09,0xd7,0xa8,0xfb,0x73,0x2c,0x91,0x76,0xe3,0xb0,0x0f,0x4f,0x84,0xe3};
	unsigned char h2[32]={0x23,0xea,0x28,0x3d,0x9e,0x94,0x82,0xe7,0x28,0xe3,0x1a,0xbb,0x6f,0xe0,0x0c,0x21,0xe1,0xfa,0x78,0x55,0x40,0x01,0xcd,0x8a,0x5e,0x9a,0xd3,0x90,0xf3,0x12,0xee,0x51};
	rev_hash(h1,32);
	rev_hash(h2,32);
	unsigned char tmp[64];
	unsigned char hash[32];
	memcpy(tmp,h1,32);
	memcpy(&tmp[32],h2,32);
	double_SHA256(tmp,64,hash);
	print_hash(hash,32);
	cout<<endl;*/
}

