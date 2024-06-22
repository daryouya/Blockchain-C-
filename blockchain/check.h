#pragma once

#include "blockchain.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <string.h>
/*
 * The test cases internally use the following functions to check the
 * correctness of the blockchain implementation.
 */
void compute_hash(const unsigned char *data, size_t data_len,
                  unsigned char *hash) {}

int set_difficulty(size_t num_zeros,
                   unsigned char difficulty[SHA256_DIGEST_LENGTH]);
int check_block(size_t index, struct block *b, unsigned char data[DATA_SIZE],
                unsigned char p_hash[SHA256_DIGEST_LENGTH]);
int check_blockchain(struct blockchain *bc,
                     unsigned char data[BLOCKCHAIN_SIZE][DATA_SIZE]);
