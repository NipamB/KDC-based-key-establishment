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
#include <time.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <assert.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <arpa/inet.h>

char *clientIpAddr[1024], *clientPortNum[1024], *clientMasterKey[1024], *clientName[1024];
int numOfReg;
char* temp = "4qXeRAQBd7wzbmG";

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

int Base64Encode(const unsigned char* buffer, size_t length, char** b64text) { //Encodes a binary safe base 64 string
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *b64text=(*bufferPtr).data;

    return (0); //success
}

size_t calcDecodeLength(const char* b64input) { //Calculates the length of a decoded string
    size_t len = strlen(b64input),
        padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len-1] == '=') //last char is =
        padding = 1;

    return (len*3)/4 - padding;
}

int Base64Decode(char* b64message, unsigned char** buffer, size_t* length) { //Decodes a base64 encoded string
    BIO *bio, *b64;

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char*)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
    *length = BIO_read(bio, *buffer, strlen(b64message));
    assert(*length == decodeLen); //length should equal decodeLen, else something went horribly wrong
    BIO_free_all(bio);

    return (0); //success
}

int myencrypt(char *plaintext, unsigned char *key, unsigned char *iv, char ciphertext_base64[]){
    unsigned char ciphertext[1024];

    int ciphertext_len;

    ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
                              ciphertext);

    // printf("%s\n", ciphertext);
    // printf("%d\n", ciphertext_len);
    char *ciphertext_base;
    
    Base64Encode(ciphertext, strlen(ciphertext), &ciphertext_base);
    strcpy(ciphertext_base64,ciphertext_base);


    // it should be the length of base64_encoding of ciphrt text??
    return ciphertext_len;
}

void mydecrypt(char * ciphertext_base64, unsigned char *key, unsigned char *iv, int length, unsigned char decryptedtext[]){
    unsigned char* base64DecodeOutput;
    size_t test;
    Base64Decode(ciphertext_base64, &base64DecodeOutput, &test);

    // printf("%ld\n",strlen(base64DecodeOutput));

    // printf("%s\n", base64DecodeOutput);
    // printf("%d\n",strlen(base64DecodeOutput));

    // read(newSocket,buffer,1024);

    // int length = atoi(r[1]);

    // unsigned char decryptedtext[1024];

    int decryptedtext_len;

    decryptedtext_len = decrypt(base64DecodeOutput, length, key, iv,
                                decryptedtext);

    decryptedtext[decryptedtext_len] = '\0';
}

int find(char **array, char* reqString, int n) {
    for(int i = 0; i < n; i++) {
        if(strcmp(array[i], reqString) == 0) {
            return i;
        }
    }
    return -1;
}

void receive_message(char* port, char* outfile, char* passwdfile, int newsocket) {
    
    unsigned char *kdc_key = "asdfghjklzxcvbnm";

    unsigned char *iv = (unsigned char *)malloc(AES_BLOCK_SIZE*sizeof(unsigned char));
    // unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, AES_BLOCK_SIZE);

    char buffer[1024];
    
    read(newsocket, buffer, 1024);

    // printf("%s\n", buffer);

    char * token = strtok(buffer, "|");
    if(atoi(token) == 301) {
        puts("registration message");
        char* r[5];
        int i = 0;
        while(token != NULL) {
            r[i++] = token;
            token = strtok(NULL, "|");
        }
        int index;
        if((index = find(clientName, r[4], numOfReg)) == -1) {
            // puts("correct case");
            clientName[numOfReg] = (char*)malloc(strlen(r[4]));
            strcpy(clientName[numOfReg], r[4]);
            clientMasterKey[numOfReg] = (char*)malloc(strlen(r[3]));
            strcpy(clientMasterKey[numOfReg], r[3]);
            clientPortNum[numOfReg] = (char*)malloc(strlen(r[2]));
            strcpy(clientPortNum[numOfReg], r[2]);
            clientIpAddr[numOfReg] = (char*)malloc(strlen(r[1]));
            strcpy(clientIpAddr[numOfReg], r[1]);
            // printf("%s : %d\n", r[1], numOfReg);
            numOfReg++;
        }
        else {
            clientMasterKey[index] = r[3];
        }

         
        // instead of r[3], use encryption of r[3] using KDC's password
        
        int ciphertext_len;

        char ciphertext_base64[1024];

        ciphertext_len = myencrypt(r[3],kdc_key,iv,ciphertext_base64);

        FILE *pwd;
        pwd = fopen(passwdfile, "a");
        fprintf(pwd, ":%s:%s:%s:%s:\n", r[4], r[1], r[2], ciphertext_base64);

        fflush(pwd);

        fclose(pwd);

        strcpy(buffer, "|302|");
        strcat(buffer, r[4]);
        strcat(buffer, "|");

        write(newsocket, buffer, 1024);

        printf("%s successfully registered\n", r[4]);

    }
    else if(atoi(token) == 305) {
        puts("key request message");

        char* r[4];
        int i = 0;
        while(token != NULL) {
            r[i++] = token;
            token = strtok(NULL, "|");
        }

        char ida[20];
        strcpy(ida,r[3]);

        int indexA = find(clientName, ida, numOfReg);

        //decrypt r[1] and store it in "decrypted"
        int len = atoi(r[2]);

        unsigned char key[16];
        strcpy(key, clientMasterKey[indexA]);
        
        unsigned char decrypted[1024];
        // printf("%s\n", r[1]);
        mydecrypt(r[1],key,iv,len,decrypted);
        // char *decrypted = r[1];

        // printf("decrypted : %s\n", decrypted);

        char *s[3];

        char *token2 = strtok(decrypted, "$");
        int l = 0;
        while(token2 != NULL) {
            s[l++] = token2;
            token2 = strtok(NULL, "$");
        }

        char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        char sharedKey[16];
        srand(time(0));
        for(int j = 0; j < 16; j++) {
            sharedKey[j] = charset[rand() % 62];
        }
        sharedKey[15] = '\0';
        // strcpy(sharedKey, temp);
        // printf("shared key = %s\n", sharedKey);
        // printf("%s\n", s[1]);

        // printf("number of registrations = %d\n", numOfReg);
        // printf("clientName array = %s\t%s\n", clientName[0], clientName[1]);

        int indexB = find(clientName, s[1], numOfReg);
        // int indexA = find(clientName, s[0], numOfReg);

        // printf("%d %d\n", indexA, indexB);
        // printf("%s\n", clientIpAddr[0]);
        
        char str2[1024];
        strncpy(str2, sharedKey, 16);
        strcat(str2,"$");
        strcat(str2, s[0]);
        strcat(str2,"$");
        strcat(str2, s[1]);
        strcat(str2,"$");
        strcat(str2, s[2]);
        strcat(str2,"$");
        strcat(str2, clientIpAddr[indexA]);
        strcat(str2,"$");
        strcat(str2, clientPortNum[indexA]);

        // printf("str2 : %s\n", str2);
        // encrypt str2 using B's key

        unsigned char *key_b = "qwertyuiopasdfgh";
        int ciphertext_len;

        char ciphertext_base64[1024];

        ciphertext_len = myencrypt(str2,key_b,iv,ciphertext_base64);
       
        // strcat(buffer,ciphertext_base64);
        // strcat(buffer,"|");

        strcpy(str2,ciphertext_base64);

        char length[10];
        sprintf(length,"%d",ciphertext_len);

        strcat(str2,"$");
        strcat(str2,length);

        char str1[1024];
        strncpy(str1, sharedKey, 16);
        strcat(str1,"$");
        strcat(str1, s[0]);
        strcat(str1,"$");
        strcat(str1, s[1]);
        strcat(str1,"$");
        strcat(str1, s[2]);
        strcat(str1,"$");
        strcat(str1, clientIpAddr[indexB]);
        strcat(str1,"$");
        strcat(str1, clientPortNum[indexB]);
        strcat(str1,"$");
        strcat(str1, str2); // replace str2 with encryption of str2 with B's key

        //encrypt str1 using A's key
        strcpy(buffer, "|306|");

        // int ciphertext_len;

        // char ciphertext_base64[1024];

        ciphertext_len = myencrypt(str1,key,iv,ciphertext_base64);
       
        strcpy(str1,ciphertext_base64);
        // strcat(buffer,"|");

        // char length[10];
        sprintf(length,"%d",ciphertext_len);

        strcat(buffer, str1); // replace str1 with encryption of str1 using A's key
        strcat(buffer, "|");

        strcat(buffer,length);
        strcat(buffer,"|");

        write(newsocket, buffer, 1024);

        printf("key has been sent to %s\n", ida);
        ////////////////////////////////////////////

        // int clientSocket;
        // struct sockaddr_in serverAddr2;
        // socklen_t addr_size;

        // clientSocket = socket(PF_INET, SOCK_STREAM, 0);
        
        // serverAddr2.sin_family = AF_INET;
        // serverAddr2.sin_port = htons(atoi(clientPortNum[indexB]));
        // serverAddr2.sin_addr.s_addr = inet_addr(clientIpAddr[indexB]);

        // memset(serverAddr2.sin_zero, '\0', sizeof serverAddr2.sin_zero);
        
        // addr_size = sizeof serverAddr2;

        // connect(clientSocket, (struct sockaddr *) &serverAddr2, addr_size);

        // strcpy(buffer, "|309|");
        // strcat(buffer, str2); // instead of str2, use encryption of str2 using B's key
        // strcat(buffer, s[0]);
        // strcat(buffer, "|");

        // write(clientSocket, buffer, 1024);

        // close(clientSocket);
    }

    return;

}

int main(int argc, char* argv[]) {
    int opt;
    char *port, *outfile, *passwdfile;

    while((opt = getopt(argc, argv, ":p:o:f:")) != -1) {
        switch(opt) {
            case 'p':
                port = optarg;
                printf("port = %s\n", port);
                break;
            case 'o':
                outfile = optarg;
                printf("outfile = %s\n", outfile);
                break;
            case 'f':
                passwdfile = optarg;
                printf("passwdfile = %s\n", passwdfile);
                break;
            case ':':
                printf("option needs a value\n");
                break;
            case '?':
                printf("unknown option: %c\n", optopt);
                break;
        }
    }

    FILE* out = fopen(outfile, "w");

    int socket_id, newsocket, newsocket1;
    struct sockaddr_in serverAddr;
    struct sockaddr_storage serverStorage;
    socklen_t addr_size;

    socket_id = socket(AF_INET, SOCK_STREAM, 0);
    if(socket_id == -1) {
        fprintf(out, "socket creation failed...\n");
        exit(0);
    }
    else {
        fprintf(out, "socket successfully created...\n");
    }
    
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(atoi(port));
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

    if((bind(socket_id, (struct sockaddr *) &serverAddr, sizeof(serverAddr))) != 0) {
        fprintf(out, "socket bind failed...\n");
        exit(0);
    }
    else {
        fprintf(out, "Socket successfully binded...\n");
    }

    if (listen(socket_id, 5) != 0) {
        fprintf(out, "Listen failed...\n");
        exit(0);
    }
    else {
        fprintf(out, "Server listening...\n");
    }

    addr_size = sizeof serverStorage;

    newsocket = accept(socket_id, (struct sockaddr *) &serverStorage, &addr_size);
    if(newsocket < 0) {
        fprintf(out, "server accepted failed...\n");
        exit(0);
    }
    else {
        fprintf(out, "server accept the client...\n");
    }

    newsocket1 = accept(socket_id, (struct sockaddr *) &serverStorage, &addr_size);
    if(newsocket1 < 0) {
        fprintf(out, "server accepted failed...\n");
        exit(0);
    }
    else {
        fprintf(out, "server accept the client...\n");
    }

    fclose(out);
    
    // int m = 0;
    // while(m < 2) {
    //     receive_message(port, outfile, passwdfile, newsocket);
    //     m++;
    // }

    receive_message(port, outfile, passwdfile, newsocket);

    receive_message(port, outfile, passwdfile, newsocket1);

    receive_message(port, outfile, passwdfile, newsocket);
    
    close(newsocket);

    close(newsocket1);

    return 0;
}