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
using namespace std;
bool check_preheader(istream& block);
int main(int argv, char **argv)
{
	ifstream block;
	if(argv==2)
	{
			block.open("block2_m", ios::binary);
	}
	else{
		printf("Usage is parser <block>\n");
	}
	cout << "NovaCoin Block Parser"<<endl;
	if (!block.is_open())
	{
		cout << "file not open" << endl;
		return -99;
	}
	if(!check_preheader(block))
		return -99;
}
bool check_preheader(istream& block)
{
	//ifstream block;
	//block = *bp;
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
	block.seekg(beg,block.beg);
	return true;
}

