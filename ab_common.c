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
  unsigned char *sig = NULL;
  size_t *slen = 0;

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
  BIO *sig_bio = BIO_new_file(sig_file, "w");
  if(!sig_bio) goto cleanup; /* Error occurred */

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

  char *dh_pub_char = NULL;
  BIO_get_mem_data(dhpub_bio, &dh_pub_char);

  //TODO: Not Sure
  //Retrieve DH public key in order to sign
  // BIO *dhpub_bio_r = BIO_new_file(dhpub_file, "r");
  // if(!dhpub_bio_r) goto cleanup; /* Error occurred */
  // EVP_PKEY *dhpub_key = PEM_read_bio_PUBKEY(dhpub_bio_r, NULL, 0, NULL);


  // Create the Message Digest Context 
  if(!(mdctx = EVP_MD_CTX_create())) fprintf(stderr, "a");//goto cleanup;
  // Initialise the DigestSign operation - SHA-256 has been selected as the message digest function
  if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, rsapair_key)){
    char *buf = malloc(sizeof(unsigned char) * (80));
    ERR_error_string(ERR_get_error(), buf);
    fprintf(stderr, "failed: %s\n", buf);// "b");//goto cleanup;
  }
  // Call update with the memory buffer pointer 
  if(1 != EVP_DigestSignUpdate(mdctx, dh_pub_char, strlen(dh_pub_char))) fprintf(stderr, "c");//goto cleanup;
  // Finalise the DigestSign operation 
  // First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the signature. 
  // Length is returned in slen 
  if(1 != EVP_DigestSignFinal(mdctx, NULL, slen)) fprintf(stderr, "d");//goto cleanup;
  // Allocate memory for the signature based on size in slen 
  if(!(sig = OPENSSL_malloc(sizeof(unsigned char) * (*slen)))) fprintf(stderr, "e");//goto cleanup;
  // Obtain the signature 
  if(1 != EVP_DigestSignFinal(mdctx, sig, slen)) fprintf(stderr, "f");//goto cleanup;  
  // write sig to a file 
  if(1 != BIO_write(sig_bio, dh_pub_char, strlen(dh_pub_char))) fprintf(stderr, "g");//goto cleanup;
  
  sigErr = 0;

  cleanup:
    if(sig && sigErr) OPENSSL_free(sig);
    // if(mdctx) EVP_MD_CTX_destroy(mdctx);
    // EVP_PKEY_CTX_free(dh_ctx);
    // EVP_PKEY_CTX_free(rsa_ctx);
    // BIO_free(dhparams_bio);
    // BIO_free(rsapair_bio);
    // BIO_free(rsapub_bio);
    // BIO_free(dhpair_bio);
    // BIO_free(dhpub_bio);
    // BIO_free(sig_bio);
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
  // 	EVP_PKEY_derive()
  // 	EVP_PKEY_derive() works on a EVP_PKEY_CTX data structure: 
  //    see EVP_PKEY_CTX_new(), 
  //    EVP_PKEY_derive_init(), 
  //    EVP_PKEY_derive_set_peer(), 
  //    and EVP_PKEY_CTX_free().
  // 	EVP_PKEY_derive() 
  return 0;
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
  //////////////////////////////
  // use AES with CTR /////////
  /////////////////////////////

  //  EVP_CIPHER_CTX_init()  EVP_CIPHER_CTX_cleanup()
  //  EVP_aes_256_ctr()
  //	EVP_EncryptInit()
  //	EVP_EncryptUpdate()
  //	EVP_EncryptFinal()
  /*
  BIO *key_bio = BIO_new_file(key_file, "r");
  if(!key_bio) goto cleanup; 
  BIO *iv_bio = BIO_new_file(iv_file, "r");
  if(!iv_bio) goto cleanup; 
  BIO *ptext_bio = BIO_new_file(ptext_file, "r");
  if(!ptext_bio) goto cleanup; 
  BIO *ctext_bio = BIO_new_file(ctext_file, "w");
  if(!ctext_bio) goto cleanup; 

  const unsigned char *iv = PEM_read_bio(iv_bio, char **name, char **header, unsigned char **data, long *len);
  const unsigned char *key =
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  // Create and initialise the context 
  if(!(ctx = EVP_CIPHER_CTX_new())) goto cleanup;

  // Initialise the encryption operation. IMPORTANT - ensure you use a key
  // and IV size appropriate for your cipher. we are using 256 bit AES (i.e. a 256 bit key). The
  // IV size for *most* modes is the same as the block size. For AES this
  // is 128 bits
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
    if(ctx) EVP_MD_CTX_destroy(ctx);
    EVP_PKEY_CTX_free(key_ctx);
    BIO_free(key_bio);
    BIO_free(iv_bio);
    BIO_free(ptext_bio);
    BIO_free(ctext_bio);

  */
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
  //////////////////////////////
  // use AES with CTR /////////
  /////////////////////////////
  
  //  EVP_CIPHER_CTX_init()  EVP_CIPHER_CTX_cleanup()
  //  EVP_aes_256_ctr()
  //	EVP_DecryptInit()
  //	EVP_DecryptUpdate()
  //	EVP_DecryptFinal()
  return 0;
}

