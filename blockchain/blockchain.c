#define _POSIX_C_SOURCE 199309L
#define _GNU_SOURCE
#include "../include/blockchain.h"
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

void calculateHash(const unsigned char *data,
                   unsigned char hash[SHA256_DIGEST_LENGTH],
                   const size_t length) {
  EVP_MD_CTX *ctx = NULL;
  unsigned int len = 0;
  EVP_MD *sha256 = NULL;

  ctx = EVP_MD_CTX_new();
  if (ctx == NULL) {
    printf("ctx error\n");
    goto err;
  }

  sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);
  if (sha256 == NULL) {
    printf("sha256 error\n");
    goto err;
  }

  if (!EVP_DigestInit_ex(ctx, sha256, NULL)) {
    printf("digest init error\n");
    goto err;
  }

  if (!EVP_DigestUpdate(ctx, data, length)) {
    printf("digest update error\n");
    goto err;
  }

  if (!EVP_DigestFinal_ex(ctx, hash, &len)) {
    printf("digest final error\n");
    goto err;
  }

err:
  EVP_MD_free(sha256);
  EVP_MD_CTX_free(ctx);
}

int bc_init(struct blockchain *chain,
            unsigned char difficulty[SHA256_DIGEST_LENGTH]) {
  if (chain == NULL) {
    return -1;
  }

  chain->count = 0;

  if (difficulty == NULL) {
    memset(chain->difficulty, 0, SHA256_DIGEST_LENGTH);
  } else {
    memcpy(chain->difficulty, difficulty, SHA256_DIGEST_LENGTH);
  }
  return 0;
}

int bc_add_block(struct blockchain *chain,
                 const unsigned char data[DATA_SIZE]) {
  if (chain == NULL || data == NULL || chain->count >= BLOCKCHAIN_SIZE) {
    return -1;
  }

  uint32_t nonce = 0;

  memcpy(chain->blocks[chain->count].core.data, data, DATA_SIZE);
  chain->blocks[chain->count].core.index = chain->count;
  struct timespec current_time;
  clock_gettime(CLOCK_REALTIME, &current_time);
  chain->blocks[chain->count].core.timestamp = current_time;

  if (chain->count == 0) {
    memset(chain->blocks[chain->count].core.p_hash, 0, SHA256_DIGEST_LENGTH);
  } else {
    memcpy(chain->blocks[chain->count].core.p_hash,
           chain->blocks[chain->count - 1].hash, SHA256_DIGEST_LENGTH);
  }
  chain->blocks[chain->count].core.nonce = nonce;

  memset(chain->blocks[chain->count].hash, 0, SHA256_DIGEST_LENGTH);
  unsigned char hash1[sizeof(struct block_core)];
  memcpy(hash1, &chain->blocks[chain->count].core, sizeof(struct block_core));

  calculateHash(hash1, chain->blocks[chain->count].hash,
                sizeof(struct block_core));
  int done = 0;

  while (!done) {
    char *block_hash = (char *)chain->blocks[chain->count].hash;
    char *block_diff = (char *)chain->difficulty;

    if (strcmp(block_hash, block_diff) > 0) {
      chain->blocks[chain->count].core.nonce++;
      memcpy(hash1, &chain->blocks[chain->count].core,
             sizeof(struct block_core));
      calculateHash(hash1, chain->blocks[chain->count].hash,
                    sizeof(struct block_core));
    } else if (strcmp(block_hash, block_diff) <= 0) {
      done = 1;
    } else if (chain->blocks[chain->count].core.nonce == 0) {
      return -1;
    }
  }

  chain->count++;
  return 0;
}

int bc_verify(struct blockchain *chain) {
  if (chain == NULL) {
    return -1;
  }

  for (int i = 0; i < chain->count; i++) {
    unsigned char hash1[sizeof(struct block_core)];
    memcpy(hash1, &chain->blocks[i].core, sizeof(struct block_core));
    calculateHash(hash1, chain->blocks[i].hash, sizeof(struct block_core));

    char *block_hash = (char *)chain->blocks[i].hash;
    char *target_hash_dif = (char *)chain->difficulty;

    if (strcmp(block_hash, target_hash_dif) > 0) {
      return -1;
    }

    if (i != chain->count - 1) {
      char *prev_hash = (char *)chain->blocks[i + 1].core.p_hash;
      char *cur_hash = (char *)chain->blocks[i].hash;

      if (strcmp(cur_hash, prev_hash) != 0) {
        return -1;
      }
    }
  }
  return 0;
}
