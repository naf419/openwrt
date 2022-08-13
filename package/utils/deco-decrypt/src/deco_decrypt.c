#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#ifdef USE_WOLFSSL
# include <wolfssl/options.h>
# include <wolfssl/openssl/des.h>
#else
# include <openssl/des.h>
#endif

const int DES_BLOCKSIZE = 8;
const int SECTION_HEADER_LEN = 16;
const int ENCRYPT_FLAG_OFFSET = 8;
const int ENCRYPT_KEY_LEN = 16;

unsigned char TPLINK_KEY[] = "360028C9";

void des_ecb_decrypt(unsigned char* s, int len, unsigned char* key_buf);

int main(int argc, char** argv)
{
    if (argc < 4) {
        fprintf(stderr, "USAGE: %s /dev/mtdblock# offset count\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char* mtd = argv[1];
    int offset = atoi(argv[2]);
    int len = atoi(argv[3]);

    int fd = open(mtd, O_RDONLY);
    if (fd < 0) {
        perror("open failed\n");
        exit(EXIT_FAILURE);
    }

    if (lseek(fd, offset, SEEK_SET) < 0) {
        perror("seek failed\n");
        exit(EXIT_FAILURE);
    }

    //round up len to DES_BLOCKSIZE
    int len_rounded = ((len + DES_BLOCKSIZE - 1) / DES_BLOCKSIZE ) * DES_BLOCKSIZE;
    int total_len = SECTION_HEADER_LEN + ENCRYPT_KEY_LEN + len_rounded;

    unsigned char* buf = malloc(total_len);
    if (!buf) {
        perror("malloc failed\n");
        exit(EXIT_FAILURE);
    }

    if (read(fd, buf, total_len) != total_len) {
        perror("read failed\n");
        exit(EXIT_FAILURE);
    }

    des_ecb_decrypt(&buf[SECTION_HEADER_LEN],ENCRYPT_KEY_LEN,TPLINK_KEY);
    des_ecb_decrypt(&buf[SECTION_HEADER_LEN + ENCRYPT_KEY_LEN],len_rounded,&buf[SECTION_HEADER_LEN]);

    printf("%.*s", len, &buf[SECTION_HEADER_LEN + ENCRYPT_KEY_LEN]);

    close(fd);

    free(buf);

    return EXIT_SUCCESS;
}

void des_ecb_decrypt(unsigned char* s, int len, unsigned char* key_buf)
{
    DES_key_schedule key;
    DES_set_key_unchecked((DES_cblock*)key_buf,&key);

    for (int i = 0; i < len; i+=DES_BLOCKSIZE) {
        DES_ecb_encrypt((DES_cblock*)&s[i],(DES_cblock*)&s[i],&key,0);
    }
}
