/*
Notes on datastructures used:
1 Use uint32_t instead of unsigned int because unsigned int is not 32 bytes for all architecture.
  uint32_t is a macro and always is a 32 bits unsigned integer. 
*/

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
	beg = block.tellg();  //position begining of block header. can hardcode value 8, but this seems cleaner
	block.seekg(0,block.end);  //end of file to calculate size
	bfsize = uint32_t(block.tellg() ) -  beg ; //size in field is sizeof_file - 8bytes(4 bytes magic, 4 bytes size)
#ifdef _DEBUG
	cout <<"File Size Calculated:"<< bfsize<<endl;
#endif
	if (bfsize != bsize)
	{
		cout << "Incorrect Size in header" << endl;
		exit(-101);
	}
	//checking for integer overflow of size
	block.clear();
	block.seekg(bfsize+beg,block.beg);   
	cout << block.tellg() << endl;
	uint32_t detect=0;
	block.read(reinterpret_cast<char *>(&detect),sizeof(detect));
	if (!block.eof())
	{
		cout << "integer overflow by Block Size detected";
	}

	//reset stream pointer to beginning of block header
	block.clear();
	block.seekg(beg,block.beg);
}

