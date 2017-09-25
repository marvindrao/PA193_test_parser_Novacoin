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
	block.open("block1", ios::binary);
	if (!block.is_open())
	{
		cout << "file not open" << endl;
		return -99;
	}
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
		exit(-100);
	}
	uint32_t beg = 0,bfsize=0;
	beg = block.tellg();
	block.seekg(0,block.end);
	bfsize = uint32_t(block.tellg() ) -  beg ;
#ifdef _DEBUG
	cout <<"File Size Calculated:"<< bfsize<<endl;
#endif
	if (bfsize != bsize)
	{
		cout << "Incorrect Size in header" << endl;
		exit(-101);
	}
	block.seekg(beg);

}

