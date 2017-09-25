// Novacoin_block_parser.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include <fstream>
#include <direct.h>
using namespace std;

int main()
{
	ifstream block;
	cout << "NovaCoin Block Parser"<<endl;
	block.open("block2", ios::binary);
	if (!block.is_open())
	{
		cout << "file not open" << endl;
		return -99;
	}
	uint32_t magic= 0;
	uint32_t bsize = 0;

	block.read(reinterpret_cast<char *>(&magic), sizeof(magic));
	cout << hex << magic<<endl;

	block.read(reinterpret_cast<char *>(&bsize), sizeof(bsize));
	cout << dec<<bsize << endl;
	if (magic != 0xe5e9e8e4)
	{
		cout << "Incorrect Magic in header" << endl;
		exit(-100);
	}
	uint32_t beg = 0,bfsize=0;
	beg = block.tellg();
	block.seekg(0,block.end);
	bfsize = uint32_t(block.tellg() ) -  beg;
	cout << bfsize<<endl;
	if (bfsize != bsize)
	{
		cout << "Incorrect Size in header" << endl;
		exit(-100);
	}
	block.seekg(beg);

}

