#ifndef block_h
#define block_h
#include <stdint.h>
struct transaction_in{
    unsigned char txid[32];
    uint32_t n;
    uint64_t scriptSigLength;  
    unsigned char *scriptSig;
    uint32_t nSequence;
} ;

struct transaction_out {
    uint64_t value; 
    uint64_t scriptPubKeyLength; 
    unsigned char *scriptPubKey;
} ;

struct transaction {

    uint32_t version;
    uint32_t timestamp;
	uint64_t ip_n;
    struct transaction_in *tx_input;
    uint64_t op_n;  
    struct transaction_out *tx_output;
    uint32_t lock_time;
    unsigned char tid[32];		
    uint32_t len;			
} ;

struct block_header {
	uint64_t block_size;
    uint32_t nVersion;
    unsigned char hashPrevBlock[32];
	unsigned char b_hash[32];
    unsigned char hashMerkleRoot[32];
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
    uint64_t n_t; 
    struct transaction *tx;
	unsigned char header_signature[72];
    
} ;
#endif /* BLOCK_H */