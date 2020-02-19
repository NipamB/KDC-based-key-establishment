#include<stdio.h>
#include<unistd.h>
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#define SA struct sockaddr
#define MAX 100

char *outfilename, *pwdfile;
unsigned char *key, *iv;

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

char clientNameArray[MAX][12], clientMasterKeyArray[MAX][12], ipaddrArray[MAX][16], clientPortNumArray[MAX][8];
int regmsg[MAX];

void func(int sockfd) {
    char buff[MAX];
    int n;

    while(1) {
        bzero(buff, MAX);

        read(sockfd, buff, sizeof(buff));

        printf("From client: %s", buff);

        int counter = 0;

        char* token = strtok(buff, "|");
        int type = atoi(token);
        if(type == 301) {
            puts("registration message");
            int i = 0, j, k;
            char **array = (char**)malloc(5*sizeof(char*));  
            while(token != NULL) {
                array[i] = token;
                token = strtok(NULL, "|");
                i++;
            }
            
            unsigned char encryptedKey[128], encodedEncKey[128];
            int encryptedKey_len = encrypt(array[3], strlen(array[3]), key, iv, encryptedKey);
            int temp = EVP_EncodeBlock((unsigned char*)encodedEncKey, encryptedKey, encryptedKey_len);

            int index = find(clientNameArray, array[4]);
            if(index != -1) {   // if found at an index
                strcpy(clientMasterKeyArray[index], encodedEncKey);
            }
            else {
                clientNameArray[counter] = array[4];
                clientMasterKeyArray[counter] = encodedEncKey;
                clientPortNumArray[counter] = array[2];
                ipaddrArray[counter] = array[1];
                regmsg[counter] = atoi(array[0]);
                counter++;

                FILE* fp;
                fp = fopen(pwdfile, "w");
                fprintf(fp,":%s:%s:%s:%s:\n", array[4], array[1], array[2], encodedEncKey);
                
                fflush(fp);

                fclose(fp);
            }
            
            buff[0] = '|';
            for(j = 0; array[0][j] != '\0'; j++) {
                buff[j+1] = array[0][j];
            }
            
            buff[j+1] = '|';
            for(k = 0; array[4][k] != '\0'; k++) {
                buff[j+2+k] = array[4][k];
            }
            buff[j+2+k] = '|';
            buff[j+3+k] = '\n';
            buff[j+4+k] = '\0';
            write(sockfd, buff, sizeof(buff));    
        }

        else if(type == 305) {
            puts("key request message");
            int i = 0, j, k;
            char **array = (char**)malloc(3*sizeof(char*));  
            while(token != NULL) {
                array[i] = token;
                token = strtok(NULL, "|");
                i++;
            }

        }
        

        if (strncmp("exit", buff, 4) == 0) { 
			printf("Server Exit...\n"); 
			break; 
		} 
    }
}

int main(int argc, char* argv[]) {
    int opt, PORT;
    
    while((opt = getopt(argc, argv, ":p:o:f:")) != -1){
        switch(opt) {
            case 'p':
                PORT = atoi(optarg);
                printf("portid = %s\n", optarg);
                break;
            case 'o':
                outfilename = optarg;
                printf("outfilename = %s\n", optarg);
                break;
            case 'f':
                pwdfile = optarg;
                printf("pwdfile = %s\n", optarg);
                break;
            case ':':
                printf("option needs a value\n");
                break;
            case '?':
                printf("unknown option: %c\n", optopt);
                break;
        }
    }

    for(; optind < argc; optind++){      
        printf("extra arguments: %s\n", argv[optind]);  
    }

    int sockfd, connfd, len;
    struct sockaddr_in servaddr, cli;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    bzero(&servaddr, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);

    bind(sockfd, (SA*)&servaddr, sizeof(servaddr));

    listen(sockfd, 5);

    len = sizeof(cli);

    connfd = accept(sockfd, (SA*)&cli, &len);

    func(connfd);

    //after communication, close this socket
    close(sockfd);

    return 0;
}
