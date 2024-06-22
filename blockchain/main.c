#include "../include/blockchain.h"
#include "../include/check.h"
#include <limits.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

#define MAX_POINTS 100
#define NUM_TRIALS 4

int total_pts = 0;

void print_test_result(int id, unsigned int pts) {
  if (pts == 0) {
    printf("Test %d failed\n", id);
  } else {
    total_pts += pts;
    printf("Test %d passed: %d pts / %d pts\n", id, total_pts, MAX_POINTS);
  }
}

int setup(struct blockchain *bc, int num_zeros) {
  unsigned char difficulty[SHA256_DIGEST_LENGTH];

  if (set_difficulty(num_zeros, difficulty) != 0) {
    fprintf(stderr, "set_difficulty failed\n");
    exit(EXIT_FAILURE);
  }
  if (bc_init(bc, difficulty) != 0) {
    fprintf(stderr, "bc_init failed\n");
    return -1;
  }

  return 0;
}

int add_block(struct blockchain *bc, unsigned char data[DATA_SIZE], int value) {
  memset(data, value, DATA_SIZE);
  if (bc_add_block(bc, data) != 0) {
    fprintf(stderr, "bc_add_block failed\n");
    return -1;
  }

  return 0;
}

int test0(void) {
  printf("Running test 0 (adding the first block with no difficulty)\n");

  struct blockchain bc;

  if (setup(&bc, 0) != 0) {
    return 0;
  }

  unsigned char data[DATA_SIZE];

  if (add_block(&bc, data, 1) != 0) {
    return 0;
  }

  return check_block(0, &bc.blocks[0], data, NULL) == 0 ? 20 : 0;
}

int test1(void) {
  printf("Running test 1 (adding multiple blocks with no difficulty)\n");

  struct blockchain bc;

  if (setup(&bc, 0) != 0) {
    return 0;
  }

  unsigned char data[BLOCKCHAIN_SIZE][DATA_SIZE];

  for (size_t i = 0; i < BLOCKCHAIN_SIZE; i++) {
    if (add_block(&bc, data[i], i) != 0) {
      return 0;
    }
  }

  return check_blockchain(&bc, data) == 0 ? 20 : 0;
}

int test2(void) {
  printf("Running test 2 (adding one block with a difficulty)\n");

  size_t trials = NUM_TRIALS;
  struct blockchain bc;

  for (size_t i = 0; i < trials; i++) {
    if (setup(&bc, i) != 0) {
      return 0;
    }

    unsigned char data[DATA_SIZE];
    if (add_block(&bc, data, 2) != 0) {
      return 0;
    }

    if (check_block(0, &bc.blocks[0], data, NULL) != 0)
      return 0;
  }
  return 20;
}

int test3(void) {
  printf("Running test 3 (adding multiple blocks with a difficulty)\n");

  size_t trials = NUM_TRIALS;
  struct blockchain bc;

  for (size_t i = 0; i < trials; i++) {
    if (setup(&bc, i) != 0) {
      return 0;
    }

    unsigned char data[BLOCKCHAIN_SIZE][DATA_SIZE];

    for (size_t i = 0; i < BLOCKCHAIN_SIZE; i++) {
      if (add_block(&bc, data[i], i) != 0) {
        return 0;
      }
    }

    if (check_blockchain(&bc, data) != 0)
      return 0;
  }
  return 20;
}

int test4(void) {
  printf("Running test 4 (verifying a blockchain)\n");

  struct blockchain bc;

  if (setup(&bc, 2) != 0) {
    return 0;
  }

  unsigned char data[BLOCKCHAIN_SIZE][DATA_SIZE];

  for (size_t i = 0; i < BLOCKCHAIN_SIZE; i++) {
    if (add_block(&bc, data[i], i * 2) != 0) {
      return 0;
    }
  }

  if (check_blockchain(&bc, data) != 0)
    return 0;

  if (bc_verify(&bc) != 0)
    return 0;

  struct blockchain test_bc;
  memcpy(&test_bc, &bc, sizeof(struct blockchain));
  memset(test_bc.blocks[BLOCKCHAIN_SIZE - 1].core.data, 0, DATA_SIZE);

  if (bc_verify(&test_bc) != -1)
    return 0;

  memcpy(&test_bc, &bc, sizeof(struct blockchain));
  memset(test_bc.blocks[0].core.data, 1, DATA_SIZE);

  if (bc_verify(&test_bc) != -1)
    return 0;

  memcpy(&test_bc, &bc, sizeof(struct blockchain));
  memset(test_bc.blocks[1].core.data, 0, DATA_SIZE);

  if (bc_verify(&test_bc) != -1)
    return 0;

  memcpy(&test_bc, &bc, sizeof(struct blockchain));
  memset(test_bc.blocks[BLOCKCHAIN_SIZE / 2].core.p_hash, 8,
         SHA256_DIGEST_LENGTH);

  if (bc_verify(&test_bc) != -1)
    return 0;

  return 20;
}

int (*tests[])(void) = {test0, test1, test2, test3, test4};

int main(int argc, char *argv[]) {
  if (argc > 2) {
    fprintf(stderr, "Usage: %s [test #]\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  time_t start = time(NULL);

  int test_num = (argc == 2) ? atoi(argv[1]) : -1;
  int num_tests = sizeof(tests) / sizeof(tests[0]);
  if (!(test_num < num_tests)) {
    fprintf(stderr, "Invalid test number\n");
    exit(EXIT_FAILURE);
  }

  if (test_num != -1) {
    print_test_result(test_num, tests[test_num]());
  } else {
    for (int i = 0; i < num_tests; i++) {
      print_test_result(i, tests[i]());
    }
  }

  time_t end = time(NULL);
  printf("Total time: %ld seconds\n", end - start);

  return 0;
}
