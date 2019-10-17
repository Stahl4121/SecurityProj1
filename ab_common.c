#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
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
  BIO *dhparams_bio;
  dhparams_bio = BIO_new_file(dhparams_file, "w");
  if(!dhparams_bio) goto err; /* Error occurred */
  
  /* Create the context for generating the parameters */
  EVP_PKEY_CTX *pctx = NULL;
  EVP_PKEY *dh_params = NULL;
  if(!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL))) goto err;
  if(!EVP_PKEY_paramgen_init(pctx)) goto err;
  /* Set a prime length of 2048 */
  if(!EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx, 2048)) goto err;
  /* Generate parameters */
  if (!EVP_PKEY_paramgen(pctx, &dh_params)) goto err; 
  /* write the params to the file */
  PEM_write_bio_Parameters(dhparams_bio, dh_params);
  
  /* Clean up */
  EVP_PKEY_CTX_free(pctx);
  BIO_free(dhparams_bio);
  return 0;
  err:
    printf("error in ab_generate_dhparams");
    /* Do some error handling */
    EVP_PKEY_CTX_free(pctx);
    return -1;
  
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
  BIO *dhparams_bio = BIO_new_file(dhparams_file, "r");
  if(!dhparams_bio) goto err; /* Error occurred */
  BIO *rsapair_bio = BIO_new_file(rsapair_file, "w");
  if(!rsapair_bio) goto err; /* Error occurred */
  BIO *rsapub_bio = BIO_new_file(rsapub_file, "w");
  if(!rsapub_bio) goto err; /* Error occurred */
  BIO *dhpair_bio = BIO_new_file(dhpair_file, "w");
  if(!dhpair_bio) goto err; /* Error occurred */
  BIO *dhpub_bio = BIO_new_file(dhpub_file, "w");
  if(!dhpub_bio) goto err; /* Error occurred */
  BIO *sig_bio = BIO_new_file(sig_file, "w");
  if(!sig_bio) goto err; /* Error occurred */

  EVP_PKEY_CTX *rsa_ctx = NULL;
  EVP_PKEY_CTX *dh_ctx = NULL;

  EVP_PKEY *dhpair_key = NULL;
  EVP_PKEY *rsapair_key = NULL;
  EVP_PKEY *dhpub_key = NULL;
  EVP_PKEY *rsapub_key = NULL;

  EVP_PKEY *dh_params = PEM_read_bio_Parameters(dhparams_bio, NULL);
  if(!(dh_ctx = EVP_PKEY_CTX_new(dh_params, NULL))) goto err; 
  if(!EVP_PKEY_keygen_init(dh_ctx)) goto err; 
  // Generate the dh key pair 
  if (!EVP_PKEY_keygen(dh_ctx, &dhpair_key)) goto err;

  // RSA 
  if(!(rsa_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL))) goto err;
  if(!EVP_PKEY_keygen_init(rsa_ctx)) goto err; 
  // RSA keys set the key length during key generation rather than parameter generation! 
  if(!EVP_PKEY_CTX_set_rsa_keygen_bits(rsa_ctx, 2048)) goto err;
  // Generate the rsa key pair
  if (!EVP_PKEY_keygen(rsa_ctx, &rsapair_key)) goto err;

  // write to the files 
  if (!PEM_write_bio_PrivateKey(dhpair_bio, dhpair_key, NULL, NULL, 0, 0, NULL)) goto err;
  if (!PEM_write_bio_PrivateKey(rsapair_bio, rsapair_key, NULL, NULL, 0, 0, NULL)) goto err;
  if (!PEM_write_bio_PUBKEY(dhpub_bio, dhpub_key)) goto err;
  if (!PEM_write_bio_PUBKEY(rsapub_bio, rsapub_key)) goto err;

  BUF_MEM *bptr;
  BIO_get_mem_ptr(dhpub_bio, &bptr);
  char * dh_pub_char = bptr->data;
  
  // set up to sign 
  EVP_MD_CTX *mdctx = NULL;
  int ret = 0;
  char *sig = NULL;
  size_t *slen = 0;
 
  // Create the Message Digest Context 
  if(!(mdctx = EVP_MD_CTX_create())) goto err;
  // Initialise the DigestSign operation - SHA-256 has been selected as the message digest function
  if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, dhpub_key)) goto err;
  // Call update with the memory buffer pointer 
  if(1 != EVP_DigestSignUpdate(mdctx, dh_pub_char, strlen(dh_pub_char))) goto err;
  // Finalise the DigestSign operation 
  // First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the signature. 
  // Length is returned in slen 
  if(1 != EVP_DigestSignFinal(mdctx, NULL, slen)) goto err;
  // Allocate memory for the signature based on size in slen 
  if(!(sig = OPENSSL_malloc(sizeof(unsigned char) * (*slen)))) goto err;
  // Obtain the signature 
  if(1 != EVP_DigestSignFinal(mdctx, sig, slen)) goto err;  
  // write sig to a file 
  BIO_write(sig_bio, dh_pub_char, strlen(dh_pub_char));
  ret = 1;
  err:
    printf("error in key generation");
    if(ret != 1)
    {
      printf("error in signing");
      // Do some error handling 
      if(*sig && !ret) OPENSSL_free(sig);
      if(mdctx) EVP_MD_CTX_destroy(mdctx);
      EVP_PKEY_CTX_free(dh_ctx);
      EVP_PKEY_CTX_free(rsa_ctx);
      BIO_free(dhpub_bio);
      return -1;
    }
    
  // Clean up 
  if(*sig && !ret) OPENSSL_free(sig);
  if(mdctx) EVP_MD_CTX_destroy(mdctx);
  EVP_PKEY_CTX_free(dh_ctx);
  EVP_PKEY_CTX_free(rsa_ctx);
  

  return 0;
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

