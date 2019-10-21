#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>


static void __hexdump(FILE *fp, const char *label, uint8_t *buf, size_t buf_len)
{
  if (fp == NULL || buf == NULL || buf_len == 0)
    return;

  if (label != NULL && strlen(label) > 0)
    fprintf(fp, "*** %s ***\n", label);

  size_t num_left = buf_len;
  size_t num_printed = 0;
  size_t i;

  while (num_left > 0) {
    size_t num_to_print = (num_left >= 16) ? 16 : num_left;
    
    fprintf(fp, "%08x  ", num_printed);

    for (i = 0; i < num_to_print; i++) {
      fprintf(fp, "%02x ", buf[num_printed+i]);

      if (i == 7)
        fprintf(fp, " ");
    }

    for (i = num_to_print; i < 16; i++) {
      fprintf(fp, "   ");

      if (i == 7)
        fprintf(fp, " ");
    }

    fprintf(fp, " |");

    for (i = 0; i < num_to_print; i++)
      fprintf(fp, "%c", isprint(buf[num_printed+i]) ? buf[num_printed+i] : '.');

    fprintf(fp, "|\n");

    num_left -= num_to_print;
    num_printed += num_to_print;
  }

  fprintf(fp, "%08x\n", num_printed);
}


/*
 * Generates DH parameters
 *
 * @dhparams_file: filename to write PEM-encoded DH parameters to
 *
 * Returns 0 on success, -1 on failure
 */
int ab_generate_dhparams(const char *dhparams_file)
{
  int err = 1;
  BIO *dhparams_bio;
  dhparams_bio = BIO_new_file(dhparams_file, "w");
  if(!dhparams_bio) goto cleanup; /* Error occurred */
  
  /* Create the context for generating the parameters */
  EVP_PKEY_CTX *pctx = NULL;
  EVP_PKEY *dh_params = NULL;
  if(!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL))) goto cleanup;
  if(!EVP_PKEY_paramgen_init(pctx)) goto cleanup;
  /* Set a prime length of 2048 */
  if(!EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx, 2048)) goto cleanup;
  /* Generate parameters */
  if (!EVP_PKEY_paramgen(pctx, &dh_params)) goto cleanup; 
  /* write the params to the file */
  PEM_write_bio_Parameters(dhparams_bio, dh_params);
  err = 0;
  
  cleanup:
    /* Clean up */
    EVP_PKEY_CTX_free(pctx);
    BIO_free(dhparams_bio);

    /* Do some error handling */
    if (err){
      fprintf(stderr, "error in ab_generate_dhparams");
      return -1;
    }
    
  return 0;
}


/*
 * Generates RSA key pair, DH key pair, and DH key signature 
 *
 * @dhparams_file: filename to read PEM-encoded DH parameters from
 * @rsapair_file: filename to write PEM-encoded RSA key pair to
 * @rsapub_file: filename to write PEM-encoded RSA public key to
 * @dhpair_file: filename to write PEM-encoded DH key pair to
 * @dhpub_file: filename to write PEM-encoded DH public key to
 * @sig_file: filename to write raw DH parameter/public key signature to
 *
 * Returns 0 on success, -1 on failure
 */
int ab_generate_keys(const char *dhparams_file, const char *rsapair_file, 
                     const char *rsapub_file, const char *dhpair_file, 
                     const char *dhpub_file, const char *sig_file)
{
  //Booleans for error messages
  int keyErr = 1;
  int sigErr = 1;
  
  //Setup for signature 
  EVP_MD_CTX *mdctx = NULL;
  uint8_t *sig = NULL;
  size_t slen;

  //Open Files
  BIO *dhparams_bio = BIO_new_file(dhparams_file, "r");
  if(!dhparams_bio) goto cleanup; /* Error occurred */
  BIO *rsapair_bio = BIO_new_file(rsapair_file, "w");
  if(!rsapair_bio) goto cleanup; /* Error occurred */
  BIO *rsapub_bio = BIO_new_file(rsapub_file, "w");
  if(!rsapub_bio) goto cleanup; /* Error occurred */
  BIO *dhpair_bio = BIO_new_file(dhpair_file, "w");
  if(!dhpair_bio) goto cleanup; /* Error occurred */
  BIO *dhpub_bio = BIO_new_file(dhpub_file, "w");
  if(!dhpub_bio) goto cleanup; /* Error occurred */
  FILE *sig_bin = fopen(sig_file, "wb+");
  if(!sig_bin) goto cleanup; /* Error occurred */


  EVP_PKEY_CTX *rsa_ctx = NULL;
  EVP_PKEY_CTX *dh_ctx = NULL;
  
  EVP_PKEY *dhpair_key = NULL;
  EVP_PKEY *rsapair_key = NULL;

  EVP_PKEY *dh_params = PEM_read_bio_Parameters(dhparams_bio, NULL);
  if(!(dh_ctx = EVP_PKEY_CTX_new(dh_params, NULL))) goto cleanup; 
  if(!EVP_PKEY_keygen_init(dh_ctx)) goto cleanup; 
  // Generate the dh key pair 
  if (!EVP_PKEY_keygen(dh_ctx, &dhpair_key)) goto cleanup;

  // RSA 
  if(!(rsa_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL))) goto cleanup;
  if(!EVP_PKEY_keygen_init(rsa_ctx)) goto cleanup; 
  // RSA keys set the key length during key generation rather than parameter generation! 
  if(!EVP_PKEY_CTX_set_rsa_keygen_bits(rsa_ctx, 2048)) goto cleanup;
  // Generate the rsa key pair
  if (!EVP_PKEY_keygen(rsa_ctx, &rsapair_key)) goto cleanup;

  // write to the files 
  if (!PEM_write_bio_PrivateKey(dhpair_bio, dhpair_key, NULL, NULL, 0, 0, NULL)) goto cleanup;
  if (!PEM_write_bio_PrivateKey(rsapair_bio, rsapair_key, NULL, NULL, 0, 0, NULL)) goto cleanup;
  if (!PEM_write_bio_PUBKEY(dhpub_bio, dhpair_key)) goto cleanup;
  if (!PEM_write_bio_PUBKEY(rsapub_bio, rsapair_key)) goto cleanup;

  keyErr = 0;

  /*
   * Generate DH parameter/public key signature
   * 
  */

  BIO *dhpub_mem_bio = BIO_new(BIO_s_mem());
  if(!dhpub_mem_bio) goto cleanup; /* Error occurred */

  if (!PEM_write_bio_PUBKEY(dhpub_mem_bio, rsapair_key)) goto cleanup;

  char *dh_pub_char = NULL;
  long data_amt = BIO_get_mem_data(dhpub_mem_bio, &dh_pub_char);
  
  // Create the Message Digest Context 
  if(!(mdctx = EVP_MD_CTX_create())) fprintf(stderr, "a");//goto cleanup;

  // Initialise the DigestSign operation - SHA-256 has been selected as the message digest function
  if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, rsapair_key)) goto cleanup;

  // Call update with the memory buffer pointer 
  if(1 != EVP_DigestSignUpdate(mdctx, dh_pub_char, data_amt)) goto cleanup;

  // Finalise the DigestSign operation 
  // First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the signature. 
  // Length is returned in slen 
  if(1 != EVP_DigestSignFinal(mdctx, NULL, &slen)) goto cleanup;
 
  // Allocate memory for the signature based on size in slen 
  if(!(sig = malloc(slen))) goto cleanup;
 
  // Obtain the signature 
  if(1 != EVP_DigestSignFinal(mdctx, sig, &slen)) goto cleanup;  
 
  // write sig to a file 
  if(0 >= fwrite(sig, slen, 1, sig_bin)) goto cleanup;
  
  sigErr = 0;

  cleanup:
    if(sig) OPENSSL_free(sig);
    if(mdctx) EVP_MD_CTX_destroy(mdctx);
    EVP_PKEY_CTX_free(dh_ctx);
    EVP_PKEY_CTX_free(rsa_ctx);
    EVP_PKEY_free(dh_params);
    EVP_PKEY_free(dhpair_key);
    EVP_PKEY_free(rsapair_key);
    BIO_free(dhparams_bio);
    BIO_free(rsapair_bio);
    BIO_free(rsapub_bio);
    BIO_free(dhpair_bio);
    BIO_free(dhpub_bio);
    BIO_free(dhpub_mem_bio);
    fclose(sig_bin);
    if(keyErr){
      fprintf(stderr, "error in key generation");
    }
    else if(sigErr){
      fprintf(stderr, "error in signing");
    }

  //Returns -1 if either error is true
  return -1*(keyErr || sigErr);
}


/*
 * Computes a shared secret key using DH key exchange and output symmetric encryption key and IV
 *
 * @rsapub_file: filename to read PEM-encoded peer RSA public key from
 * @dhpair_file: filename to read PEM-encoded DH key pair from
 * @dhpub_file: filename to read PEM-encoded peer DH public key from
 * @sig_file: filename to read raw DH public key signature from
 * @key_file: filename to write raw symmetric encryption key to
 * @iv_file: filename to write raw symmetric encryption IV to
 *
 * Returns 0 on success, -1 on failure
 */
int ab_derive_secret_key(const char *rsapub_file, const char *dhpair_file, 
                         const char *dhpub_file, const char *sig_file, 
                         const char *key_file, const char *iv_file)
{
  EVP_PKEY_CTX *dh_ctx;
  unsigned char *skey;
  size_t skeylen;

  //Open Files
  BIO *rsapub_bio = BIO_new_file(rsapub_file, "r");
  if(!rsapub_bio) goto cleanup; /* Error occurred */
  BIO *dhpair_bio = BIO_new_file(dhpair_file, "r");
  if(!dhpair_bio) goto cleanup; /* Error occurred */
  BIO *dhpub_bio = BIO_new_file(dhpub_file, "r");
  if(!dhpub_bio) goto cleanup; /* Error occurred */
  FILE *sig_bin = fopen(sig_file, "r");
  if(!sig_bin) goto cleanup; /* Error occurred */
  FILE *key_bin = fopen(key_file, "wb+");
  if(!key_bin) goto cleanup; /* Error occurred */
  FILE *iv_bin = fopen(iv_file, "wb+");
  if(!iv_bin) goto cleanup; /* Error occurred */
  if(err) goto cleanup;
  //Read PEM-encoded keys into EVP_PKEY structures
  EVP_PKEY *dh_key_pair = PEM_read_bio_PrivateKey(dhpair_bio, NULL, 0, NULL);
  EVP_PKEY *rsa_pub_key = PEM_read_bio_PUBKEY(rsapub_bio, NULL, 0, NULL);
  EVP_PKEY *dh_pub_key = PEM_read_bio_PUBKEY(dhpub_bio, NULL, 0, NULL);
  if (!dh_key_pair || !rsa_pub_key || !dh_pub_key) goto cleanup; /* Error occurred */
  fprintf(stderr,"keys passed\n");

  //Setup context
  if(!(dh_ctx = EVP_PKEY_CTX_new(dh_key_pair, NULL))) goto cleanup; /* Error */
  if (EVP_PKEY_derive_init(dh_ctx) <= 0) goto cleanup; /* Error */
  if (EVP_PKEY_derive_set_peer(dh_ctx, dh_pub_key) <= 0){
    char *buf = malloc(sizeof(unsigned char) * (80));
    ERR_error_string(ERR_get_error(), buf);
    fprintf(stderr, "failed: %s\n", buf);// "b");//goto cleanup;
  }// goto cleanup; /* Error */
  fprintf(stderr,"context passed\n");

  /* Determine buffer length */
  if (EVP_PKEY_derive(dh_ctx, NULL, &skeylen) <= 0) goto cleanup; /* Error */

  //Allocate memory
  if (!(skey = OPENSSL_malloc(skeylen))) goto cleanup; /* Error, malloc failure */

  //Derive secret key
  if (EVP_PKEY_derive(dh_ctx, skey, &skeylen) <= 0) goto cleanup; /* Error */

  //TODO: Don't know how to do this correctly
  //Write first 256 bytes of skey to a file (matches DH keysize of 2048bits)
  if(0 >= fwrite(skey, 1, 256, key_bin)) goto cleanup;
  if(0 >= fwrite(skey, 1, 16, iv_bin)) goto cleanup;

  err = 0;

  cleanup:
    if(skey) OPENSSL_free(skey);
    EVP_PKEY_CTX_free(dh_ctx);
    EVP_PKEY_free(dh_key_pair);
    EVP_PKEY_free(rsa_pub_key);
    EVP_PKEY_free(dh_pub_key);
    BIO_free(rsapub_bio);
    BIO_free(dhpair_bio);
    BIO_free(dhpub_bio);
    fclose(sig_bin);
    fclose(key_bin);
    fclose(iv_bin);

    if(err){
      fprintf(stderr, "error");
    }

  //Returns -1 if error occured
  return -1 * err;
}

/*
 * Encrypts plaintext using symmetric encryption
 *
 * @key_file: filename to read raw symmetric encryption key from
 * @iv_file: filename to read raw symmetric encryption IV from
 * @ptext_file: filename to read raw plaintext from
 * @ctext_file: filename to write raw ciphertext to
 *
 * Returns 0 on success, -1 on failure
 */
int ab_encrypt(const char *key_file, const char *iv_file, const char *ptext_file, const char *ctext_file)
{
  FILE *key_bin = fopen(key_file, "rb");
  if(!key_bin) goto cleanup; 
  FILE *iv_bin = fopen(iv_file, "rb");
  if(!iv_bin) goto cleanup; 
  FILE *ptext_bin = fopen(ptext_file, "rb");
  if(!ptext_bin) goto cleanup; 
  FILE *ctext_bin = fopen(ctext_file, "wb+");
  if(!ctext_bin) goto cleanup; 

  
  const int IV_LEN = 16;
  const int KEY_LEN = 256;
  const int plaintext_len = 1000;
  ///////////////////////////////////////////////////////////
  //// ^^^^  CHECK THIS WITH DR. AL MOAKAR FOR LEN OF MSG ////
  ///////////////////////////////////////////////////////////
  char iv[IV_LEN];
  char key[KEY_LEN];
  unsigned char plaintext[plaintext_len];
  unsigned char * ciphertext = NULL;
  if(!fread(iv, IV_LEN, 1, iv_bin));
  if(!fread(key, KEY_LEN, 1, key_bin));
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  // Create and initialise the context 
  if(!(ctx = EVP_CIPHER_CTX_new())) goto cleanup;

  // Initialise the encryption operation. IMPORTANT - ensure you use a key
  // and IV size appropriate for your cipher. we are using 256  AES 
  // IV size same as the block size: 128 bits?
  if(1 != EVP_EncryptInit(ctx, EVP_aes_256_ctr(), key, iv)) goto cleanup;
  
  // Provide the message to be encrypted, and obtain the encrypted output.
  // EVP_EncryptUpdate can be called multiple times if necessary
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) goto cleanup;
  ciphertext_len = len;

  // Finalise the encryption. Further ciphertext bytes may be written at this stage.
  if(1 != EVP_EncryptFinal(ctx, ciphertext + len, &len)) goto cleanup;
  ciphertext_len += len;
  // Clean up
  EVP_CIPHER_CTX_free(ctx);

  cleanup:
    // Clean up 
    if(ctx) EVP_CIPHER_CTX_free(ctx);
    fclose(key_bin);
    fclose(iv_bin);
    fclose(ptext_bin);
    fclose(ctext_bin);

  
  return 0;
}


/*
 * Decrypts ciphertext using symmetric encryption
 *
 * @key_file: filename to read raw symmetric encryption key from
 * @iv_file: filename to read raw symmetric encryption IV from
 * @ctext_file: filename to read raw ciphertext from
 * @ptext_file: filename to write raw plaintext to
 *
 * Returns 0 on success, -1 on failure
 */
int ab_decrypt(const char *key_file, const char *iv_file, const char *ctext_file, const char *ptext_file)
{
  FILE *key_bin = fopen(key_file, "rb");
  if(!key_bin) goto cleanup; 
  FILE *iv_bin = fopen(iv_file, "rb");
  if(!iv_bin) goto cleanup; 
  FILE *ptext_bin = fopen(ptext_file, "wb+");
  if(!ptext_bin) goto cleanup; 
  FILE *ctext_bin = fopen(ctext_file, "rb");
  if(!ctext_bin) goto cleanup; 

  const int IV_LEN = 16;
  const int KEY_LEN = 256;
  int ciphertext_len = 1000;
  int plaintext_len;
  ///////////////////////////////////////////////////////////
  //// ^^^^  CHECK THIS WITH DR. AL MOAKAR FOR LEN OF MSG ////
  ///////////////////////////////////////////////////////////
  char iv[IV_LEN];
  char key[KEY_LEN];
  unsigned char ciphertext[ciphertext_len];
  unsigned char * plaintext = NULL;

  if(!fread(iv, IV_LEN, 1, iv_bin));
  if(!fread(key, KEY_LEN, 1, key_bin));
  
  EVP_CIPHER_CTX *ctx;
  int len;

  // Create and initialise the context 
  if(!(ctx = EVP_CIPHER_CTX_new())) goto cleanup;

  // Initialise the decryption operation. IMPORTANT - ensure you use a key
  // and IV size appropriate for your cipher. we are using 256 AES 
  if(1 != EVP_DecryptInit(ctx, EVP_aes_256_ctr(), key, iv)) goto cleanup;
  
  // Provide the ciphertext to be decrypted, and obtain the decrypted output.
  // EVP_DecryptUpdate can be called multiple times if necessary
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) goto cleanup;
  plaintext_len = len;

  // Finalise the encryption. Further ciphertext bytes may be written at this stage.
  if(1 != EVP_DecryptFinal(ctx, plaintext + len, &len)) goto cleanup;
  plaintext_len += len;
  // Clean up
  EVP_CIPHER_CTX_free(ctx);

  // return plaintext_len;
  cleanup:
    // Clean up 
    if(ctx) EVP_CIPHER_CTX_free(ctx);
    fclose(key_bin);
    fclose(iv_bin);
    fclose(ptext_bin);
    fclose(ctext_bin);

  return 0;
}

