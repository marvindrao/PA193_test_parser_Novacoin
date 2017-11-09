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
#define SCRYPT_BUFFER_SIZE (131072 + 63)

using namespace std;

struct transaction;
struct block_header;
struct transaction_out;
struct transaction_in;
bool check_preheader(istream& block,struct block_header *b);
bool check_header(istream& block,struct block_header *b);
uint64_t varint(istream& block);
void get_transactions(ifstream& block,struct transaction *t);
void get_ip_txn(ifstream& block,struct transaction_in *in);
void get_op_txn(ifstream& block,struct transaction_out *out);
void print_hash(unsigned char* hash, int i);
void print_block(struct block_header *b);
void print_transaction(struct transaction *t);
void print_transaction_in(struct transaction_in *in);
void print_transaction_out(struct transaction_out *out);
void double_SHA256(unsigned char *input, int ip_size, unsigned char *output);
bool verify_merkle_root(struct block_header *b);
void compute_merkle_root(struct block_header *b,unsigned char* merkle_root);
void rev_hash(unsigned char* hash, int len);
void read_block(ifstream& block,struct block_header *b);
void verify_block_pair(struct block_header *b,struct block_header *pb);
void verify_block(struct block_header *b);
unsigned char* scrypt_blockhash(const uint8_t* input);
void destroy_transaction_out(struct transaction_out *tout);
void destroy_transaction_in(struct transaction_in *tin);
void destroy_transaction(struct transaction *tx);
void destroy_block(struct block_header *b);
bool verify_transaction(transaction *tx);
bool isCoinbase(transaction *tx);
bool verify_timestamp(uint32_t timestamp);