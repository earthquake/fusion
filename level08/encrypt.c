#copy&paste&smash code
#only for testing the crypto

#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <string.h>
#include <time.h>

struct buffer {
  unsigned char *data;
  size_t len;
};

static void encryption_worker()
{
  struct buffer *input_buffer;
  struct buffer *output_buffer;
  unsigned char *tmp;
  unsigned char *message = "m 0777 test1";
  unsigned char peer_remote_pk[32];
  unsigned char secret_key[32];
  int i;
  unsigned char *p;

    input_buffer = calloc(sizeof(struct buffer), 1);
    input_buffer->data = message;
    input_buffer->len = strlen(message);
    output_buffer = calloc(sizeof(struct buffer), 1);
    if(output_buffer == NULL) goto failure;
    output_buffer->len = input_buffer->len + crypto_box_ZEROBYTES + crypto_box_NONCEBYTES;
    output_buffer->data = malloc(output_buffer->len);
    if(output_buffer->data == NULL) goto failure;

    memcpy(output_buffer->data, "\x49\x00\x4a\x43\x37\xf3\x4e\x69\x8b\x59\xaa\x21\x05\x99\xd5\x79\x26\xb2\xbe\x5b\x76\xef\x55\x8b", 24);

    memcpy(peer_remote_pk, "\x2d\xda\x2f\xcc\x5b\xae\x6b\xba\x6f\x7d\x27\x35\x8b\x23\x04\x6f\x6d\x73\x70\x68\x67\xc2\x79\x48\x38\x98\x75\x47\x95\x72\x0b\x44", 32);
    memcpy(secret_key, "\xbc\xcc\x7b\x0c\x7e\x5f\xd0\xf9\x15\x04\x47\x19\x2c\x8d\x2f\x56\x81\xe9\x80\x8b\x95\x7f\x9e\x2f\x11\x18\xd2\x1e\xf7\x6f\x9c\xf5", 32);
//    randombytes(output_buffer->data, crypto_box_NONCEBYTES);
//    randombytes(peer_remote_pk, 32);
//    randombytes(secret_key, 32);

    tmp = malloc(input_buffer->len + crypto_box_ZEROBYTES);
    if(! tmp) goto failure;


     printf("input_buffer is %08x\n", input_buffer);
     printf("input_buffer->data = %s, input_buffer->len = %d\n", input_buffer->data, input_buffer->len);

    memset(tmp, 0, crypto_box_ZEROBYTES);
    memcpy(tmp + crypto_box_ZEROBYTES, input_buffer->data, input_buffer->len);    

    printf("input_buffer len: %d\n", input_buffer->len+crypto_box_ZEROBYTES);
    p = tmp;
    for (i=0;i<input_buffer->len+crypto_box_ZEROBYTES;i++)
    {
        printf("%02x", *p++);
    }
    printf("\n");
    if(crypto_box(output_buffer->data + crypto_box_NONCEBYTES, tmp, crypto_box_ZEROBYTES + input_buffer->len,
      output_buffer->data, peer_remote_pk, secret_key) != 0) {
      fprintf(stderr, "crypto_box failed\n");
      goto failure;
    }

    printf("output_buffer len: %d\n", output_buffer->len);
    p = output_buffer->data;
    for (i=0;i<output_buffer->len;i++)
    {
	printf("\\x%02x", *p++);
    }
    printf("\n");
    
    goto alright;
failure:
    free(output_buffer);
alright:
    free(input_buffer);
    if(tmp) { free(tmp); tmp = NULL; }

}

static void decryption_worker()
{
  struct buffer *input_buffer;
  struct buffer *output_buffer;
  unsigned char peer_remote_pk[32];
  unsigned char secret_key[32];

  size_t tl;
  unsigned char *tmpout;
  unsigned char *message = "\xbe\xe7\xfb\x71\x4c\xe8\x9f\xd5\xaa\x84\x98\xca\x03\x55\x69\x0a\x20\x8f\x50\xc0\xd0\xce\xcd\xcb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2b\x35\x91\xd4\xb9\x99\x87\x53\xe9\x54\xe8\x63\x1c\xce\x3c\x2a\xc5\xab\xff\xda\xa5\xaa\xe6\x6f\x8a\x0f\x63\x77";

    strncpy(peer_remote_pk, "\x0c\xb6\x7f\xe5\xd8m\xcb\xfd#\xc7\x81\x83\xb8\xef?\xfd\xb4$\xc3\xa0\xc7\xa9\xdc\x8f&G\x1a?\xa0:\xcb\x10", 32);
    strncpy(secret_key, "\xf6\x93\\\x89""8\xe0yz\xb8""3R\xb6\xef@\x0b\xe8\xf7""C\x1e\xf5(\x8f""A\x8f\xb5\x13\x08S\xd6\xcdZ\x89", 32);
    input_buffer = output_buffer = NULL;
    tmpout = NULL;


    input_buffer = calloc(sizeof(struct buffer), 1);
    input_buffer->len = 68;
    input_buffer->data = message;
    tl = input_buffer->len - crypto_box_NONCEBYTES;

    tmpout = malloc(tl);
    if(! tmpout) {
      fprintf(stderr, "decryption_worker: unable to malloc %d bytes for tmpout, skipping\n", tl);
      goto failure;
    }

    output_buffer = calloc(sizeof(struct buffer), 1);
    if(! output_buffer) {
      fprintf(stderr, "decryption_worker: unable to calloc new buffer, skipping\n");
      goto failure;
    }
    output_buffer->len = tl - crypto_box_ZEROBYTES;
    output_buffer->data = malloc(output_buffer->len);
    if(! output_buffer->data) {
      fprintf(stderr, "decryption_worker: unable to malloc new data buffer of "
      "%d bytes, skipping\n", tl - crypto_box_ZEROBYTES);
      goto failure;
    }

    // printf("attempting to decrypt with length of %d bytes\n", tl);

    if(crypto_box_open(tmpout, input_buffer->data + crypto_box_NONCEBYTES, tl, input_buffer->data,
      peer_remote_pk, secret_key) != 0) {
      fprintf(stderr, "decryption_worker: unable to crypto_box_open :s, skipping\n");
      goto failure;
    }

    // printf("decryption_worker: outputting buffer\n");

    memcpy(output_buffer->data, tmpout + crypto_box_ZEROBYTES, output_buffer->len);
    
    /* Insert the buffer into the queue */

	printf(": %s", output_buffer->data);
    goto alright;
failure:
    free(output_buffer);
alright:
    free(input_buffer);
    if(tmpout) free(tmpout);
}


int main()
{
	encryption_worker();
}
