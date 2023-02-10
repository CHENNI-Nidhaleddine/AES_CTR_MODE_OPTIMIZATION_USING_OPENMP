#include <stdlib.h>
#include <memory.h>
#include <stdio.h>
#include <time.h>
#include <omp.h>
#include "aes_seq.h"


/********************************** UTILITIES FUNCTIONS *****************************************/

//Print the content of str of length len in hexadecimal values
void print_hex(BYTE str[], int len)
{
    int idx;

    for (idx = 0; idx < len; idx++)
        printf("%02x", str[idx]);
}
//Reads the content of filename into text and returns numbers of bytes
int read_file(char* filename, char** text) {
    FILE* textfile;
    long long numbytes;
    textfile = fopen(filename, "rb");
    if (textfile == NULL)
        return 1;

    fseek(textfile, 0L, SEEK_END);
    numbytes = ftell(textfile);
    fseek(textfile, 0L, SEEK_SET);

    *text = (char*)calloc(numbytes, sizeof(char));
    if (*text == NULL)
        return 1;

    fread(*text, sizeof(char), numbytes, textfile);
    fclose(textfile);
    return numbytes;

}
//writes text of length numbytes into filename
void write_file(char* filename, BYTE* text, long long numbytes) {
    FILE* textfile;
    textfile = fopen(filename, "wb");
    fwrite(text, sizeof(BYTE), numbytes, textfile);
    fclose(textfile);
}
/********************************** MAIN PROGRAM *****************************************/

int main(int argc, char* argv[])
{
    //Name of files
    char* fileToEncrypt = "image2.png";
    char* newFile = "newnew.png";

    //To calculate processing time
    clock_t start, end;
    double cpu_time_used;
    start = clock();

    //CPU Variables:
    int keysize = 256;
    BYTE iv[1][16] = { {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff} };
    BYTE key[1][32] = { 0x2b,0x7e,0x15,0x16,0x27,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c,0x09,0xcf,0x4f,0x3c,0x09,0xcf,0x4f,0x3c,0x09,0xcf,0x4f,0x3c,0x09,0xcf,0x4f,0x3c };


    char* text;
    long long numbytes = read_file(fileToEncrypt, &text);//reading file
    BYTE* plaintext = (BYTE*)malloc(numbytes * sizeof(BYTE));
    memcpy(plaintext, text, numbytes);
    BYTE* enc_buf = (BYTE*)malloc(numbytes * sizeof(BYTE));
    BYTE* ciphertext = (BYTE*)malloc(numbytes * sizeof(BYTE));

    WORD key_schedule[60];//round keys
    //Calculate round keys
    keyExpansion(key[0], key_schedule, keysize);


 
    //Start AES
    //printf("Start Encryption:\n");
// 
    //Sequential: 
   // aes_encrypt_ctr(plaintext, numbytes, enc_buf, key_schedule, keysize, iv[0]);
   
    //OR OPENMP
    aes_encrypt_ctr_openmp(plaintext, numbytes, enc_buf, key_schedule, keysize, iv[0]);
    // printf("Done with Encryption\n");

    memcpy(ciphertext, enc_buf, numbytes);

   //   printf("Start Decryption:\n");
        //Sequential: 
       // aes_encrypt_ctr(plaintext, numbytes, enc_buf, key_schedule, keysize, iv[0]);

        //OR OPENMP
        aes_encrypt_ctr_openmp(ciphertext, numbytes, enc_buf, key_schedule, keysize, iv[0]);
    //  printf("Done with Decryption\n");

    write_file(newFile, enc_buf, numbytes);

    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("time to encrypt and decrypt : %f s\n", cpu_time_used);
    return 0;
}