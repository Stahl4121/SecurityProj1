#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>


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
  return 0;
}

