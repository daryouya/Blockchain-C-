#pragma once

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <time.h>

#define DATA_SIZE 64
#define BLOCKCHAIN_SIZE 32

struct block_core {
  size_t index;                  // the index of the block in the blockchain
  struct timespec timestamp;     // the time when the block was created
  unsigned char data[DATA_SIZE]; // the data that the block contains
  unsigned char p_hash[SHA256_DIGEST_LENGTH]; // the hash of the previous block
  uint32_t nonce; // a number to satisfy the difficulty
};

struct block {
  struct block_core core;
  unsigned char hash[SHA256_DIGEST_LENGTH]; // the hash of the current block.
};

struct blockchain {
  struct block blocks[BLOCKCHAIN_SIZE];
  size_t count;
  unsigned char difficulty[SHA256_DIGEST_LENGTH]; // the difficulty that each
                                                  // hash needs to satisfy.
};

int bc_init(struct blockchain *bc,
            unsigned char difficulty[SHA256_DIGEST_LENGTH]);
int bc_add_block(struct blockchain *bc, const unsigned char data[DATA_SIZE]);
int bc_verify(struct blockchain *bc);

