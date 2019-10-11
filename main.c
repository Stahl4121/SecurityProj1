#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "ab_common.h"

void print_usage_exit(const char *prog)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  %s generate-dhparams <dhparams-file>\n", prog);
  fprintf(stderr, "  %s generate-keys <dhparams-file> <rsa-keypair-file> <rsa-pubkey-file> <dh-keypair-file> <dh-pubkey-file> <sig-file>\n", prog);
  fprintf(stderr, "  %s derive <peer-rsa-pubkey-file> <dh-key-file> <peer-dh-pubkey-file> <sig-file> <key-file> <iv-file>\n", prog);
  fprintf(stderr, "  %s encrypt <key-file> <iv-file> <plaintext-file> <ciphertext-file>\n", prog);
  fprintf(stderr, "  %s decrypt <key-file> <iv-file> <ciphertext-file> <plaintext-file>\n", prog);
  exit(0);
}

int main (int argc, char *argv[])
{
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  // 1. parse command line arguments and execute desired command
  if (argc < 2) {
    fprintf(stderr, "Must specify a command to run!\n");
    print_usage_exit(argv[0]);
  }

  int res = -1;
  if (strcmp(argv[1], "generate-dhparams") == 0) {
    // generate and output DH parameters
    if (argc != 3) {
      fprintf(stderr, "Command '%s' takes exactly 1 argument!\n", argv[1]);
      print_usage_exit(argv[0]);
    }

    res = ab_generate_dhparams(argv[2]);
  }
  else if (strcmp(argv[1], "generate-keys") == 0) {
    // generate and output keys and signature
    if (argc != 8) {
      fprintf(stderr, "Command '%s' takes exactly 6 arguments!\n", argv[1]);
      print_usage_exit(argv[0]);
    }

    res = ab_generate_keys(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7]);
  }
  else if (strcmp(argv[1], "derive") == 0) {
    // compute and output shared secret key
    if (argc != 8) {
      fprintf(stderr, "Command '%s' takes exactly 6 arguments!\n", argv[1]);
      print_usage_exit(argv[0]);
    }

    res = ab_derive_secret_key(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7]);
  }
  else if (strcmp(argv[1], "encrypt") == 0) {
    // encrypt plaintext with secret key
    if (argc != 6) {
      fprintf(stderr, "Command '%s' takes exactly 4 arguments!\n", argv[1]);
      print_usage_exit(argv[0]);
    }

    res = ab_encrypt(argv[2], argv[3], argv[4], argv[5]);
  }
  else if (strcmp(argv[1], "decrypt") == 0) {
    // decrypt ciphertext with secret key
    if (argc != 6) {
      fprintf(stderr, "Command '%s' takes exactly 4 arguments!\n", argv[1]);
      print_usage_exit(argv[0]);
    }

    res = ab_decrypt(argv[2], argv[3], argv[4], argv[5]);
  }
  else {
    fprintf(stderr, "Invalid command: %s\n", argv[1]);
    print_usage_exit(argv[0]);
  }


  if (res == 0)
    fprintf(stderr, "Command '%s' successful.\n", argv[1]);
  else
    fprintf(stderr, "Command '%s' failed!\n", argv[1]);

  ERR_free_strings();
  EVP_cleanup();

  return 0; 
}

