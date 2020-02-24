#include <stdio.h>
#include <unistd.h>
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
#include <arpa/inet.h>

int Nonce = 1000;
unsigned char *iv;

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

int Base64Encode(const unsigned char* buffer, size_t length, char** b64text) 
{ //Encodes a binary safe base 64 string
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

size_t calcDecodeLength(const char* b64input) 
{ //Calculates the length of a decoded string
    size_t len = strlen(b64input),
        padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len-1] == '=') //last char is =
        padding = 1;

    return (len*3)/4 - padding;
}

int Base64Decode(char* b64message, unsigned char** buffer, size_t* length) 
{ //Decodes a base64 encoded string
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

    char *ciphertext_base;
    
    Base64Encode(ciphertext, strlen(ciphertext), &ciphertext_base);
    strcpy(ciphertext_base64,ciphertext_base);

    return ciphertext_len;
}

void mydecrypt(char * ciphertext_base64, unsigned char *key, unsigned char *iv, int length, unsigned char decryptedtext[]){
    unsigned char* base64DecodeOutput;
    size_t test;
    Base64Decode(ciphertext_base64, &base64DecodeOutput, &test);

    int decryptedtext_len;

    decryptedtext_len = decrypt(base64DecodeOutput, length, key, iv,
                                decryptedtext);

    decryptedtext[decryptedtext_len] = '\0';
}

int registration(char buffer[], int clientSocket, char *name, char * clientip, char *clientport, unsigned char *pwd)
{
    //301 : registration message
    strcpy(buffer,"|");

    char code[5];
    strcpy(code,"301");
    strcat(buffer,code);
    strcat(buffer,"|");

    char ipaddress[16];
    strcpy(ipaddress,clientip);
    strcat(buffer,ipaddress);
    strcat(buffer,"|");

    char clientportnum[8];
    strcpy(clientportnum,clientport);
    strcat(buffer,clientportnum);
    strcat(buffer,"|");

    char clientmasterkey[12];
    strcpy(clientmasterkey,pwd);
    strcat(buffer,clientmasterkey);
    strcat(buffer,"|");

    char clientname[12];
    strcpy(clientname,name);
    strcat(buffer,clientname);
    strcat(buffer,"|");

    //send registration message to KDC
    write(clientSocket,buffer,1024); 

    //receive confirmation message for registration from KDC
    read(clientSocket,buffer,1024);

    //break the message by delimiter
    char *received[2];
    char * token = strtok(buffer, "|");
    int i = 0;
    while( token != NULL ) {
        received[i++] = token;
        token = strtok(NULL, "|");
    }

    printf("%s registered in KDC\n", name);
    return 1;
}

void send_message(char *inputfile, char *message_b, char *name, char *ipaddr_b, int port_b, char nonce1[], char *othername, unsigned char *secert_key, unsigned char *iv)
{
    int clientSocket;
    char buffer[1024];
    struct sockaddr_in serverAddr;
    socklen_t addr_size;

    clientSocket = socket(PF_INET, SOCK_STREAM, 0);

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port_b);
    serverAddr.sin_addr.s_addr = inet_addr(ipaddr_b);
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

    //connect to B's ip address and port number
    addr_size = sizeof serverAddr;
    connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size);

    //309 : Send message received from KDC for client B to client B
    strcpy(buffer,"|309|");
    strcat(buffer,message_b);
    strcat(buffer,"|");
    strcat(buffer,name);
    strcat(buffer,"|");

    write(clientSocket,buffer,1024);

    printf("%s sending secret key to %s\n", name, othername);

    //receive confimation from B with nonce+1
    read(clientSocket,buffer,1024);

    printf("%s received an authentication message from %s\n", name, othername);

    char *r[3];
    char * token = strtok(buffer, "|");
    int i = 0;
    while( token != NULL ) {
        r[i++] = token;
        token = strtok(NULL, "|");
    }

    //check if the nonce is correct
    if(atoi(nonce1)+1 == atoi(r[1])){
        char message[1024];

        FILE *fin;

        fin = fopen(inputfile,"r");
        fgets(message,1024,fin);

        fclose(fin);

        int ciphertext_len;

        char ciphertext_base64[1024];

        ciphertext_len = myencrypt(message,secert_key,iv,ciphertext_base64);

        char len[10];
        sprintf(len,"%d",ciphertext_len);

        strcpy(buffer,ciphertext_base64);
        strcat(buffer,"|");
        strcat(buffer,len);

        printf("%s sending desired message to %s\n", name, othername);

        write(clientSocket,buffer,1024);
    }
    else
        printf("Wrong nonce\n");

    close(clientSocket);
}

void requestKey(char buffer[], int clientSocket, char *inputfile, char *name, char *othername, unsigned char *key, unsigned char *iv)
{
    //305 : Key request message
    strcpy(buffer,"|");

    char code[5];
    strcpy(code,"305");
    strcat(buffer,code);
    strcat(buffer,"|");

    //encrypt message with A's key
    char message[1024];

    char ida[10];
    strcpy(ida,name);
    strcpy(message,ida);
    strcat(message,"$");

    char idb[10];
    strcpy(idb,othername);
    strcat(message,idb);
    strcat(message,"$");

    char nonce1[10];
    sprintf(nonce1,"%d",Nonce);
    Nonce++;

    strcat(message,nonce1);

    int ciphertext_len;
    
    char ciphertext_base64[1024];

    ciphertext_len = myencrypt(message,key,iv,ciphertext_base64);

    strcat(buffer,ciphertext_base64);
    strcat(buffer,"|");

    char length[10];
    sprintf(length,"%d",ciphertext_len);

    strcat(buffer,length);
    strcat(buffer,"|");

    strcat(buffer,ida);
    strcat(buffer,"|");

    //send key request message to KDC
    write(clientSocket,buffer,1024);

    printf("Sent 305 message to KDC\n");

    //get the secret key appended with the message to be sent to the other client
    read(clientSocket,buffer,1024);

    printf("%s got the key of %s from KDC\n", name, othername);

    //break the received message from KDC
    char *r1[3];
    char * token1 = strtok(buffer, "|");
    int i = 0;
    while( token1 != NULL ) {
        r1[i++] = token1;
        token1 = strtok(NULL, "|");
    }

    int len = atoi(r1[2]);
    
    unsigned char decrypted[1024];

    mydecrypt(r1[1],key,iv,len,decrypted);

    //break the message encrypted with A's key to get B's ip address and port number
    char *r2[8];
    char * token2 = strtok(decrypted, "$");
    i = 0;
    while( token2 != NULL ) {
        r2[i++] = token2;
        token2 = strtok(NULL, "$");
    }

    // printf("b message : %s\n", r2[6]);

    char message_b[1024];
    strcpy(message_b,r2[6]);
    strcat(message_b,"|");
    strcat(message_b,r2[7]);

    char * ipaddr_b = r2[4];
    int port_b = atoi(r2[5]);

    char *sercet_key = r2[0];

    //after getting B's ip address and port number, send message to B
    send_message(inputfile, message_b, name, ipaddr_b, port_b, nonce1, othername, sercet_key, iv);
}

void client(char *name, char *othername, char *inputfile, char *kdcip, int kdcport, unsigned char *iv)
{
    int clientSocket;
    char buffer[1024];
    struct sockaddr_in serverAddr;
    socklen_t addr_size;

    clientSocket = socket(PF_INET, SOCK_STREAM, 0);

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(kdcport);
    serverAddr.sin_addr.s_addr = inet_addr(kdcip);

    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

    addr_size = sizeof serverAddr;

    //connect to KDC
    connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size);

    //client's ip address and port number
    char * clientip = "127.0.0.1";
    char *clientport = "7000";

    unsigned char *pwd = "verybadkeyqwerty";

    //register the client in KDC
    int value = registration(buffer, clientSocket, name, clientip, clientport, pwd);

    //sleep for sometime so that all the clients register in KDC
    sleep(1);

    //request for secret key key from KDC to communicate with otehr client
    requestKey(buffer, clientSocket, inputfile, name, othername, pwd, iv);

    close(clientSocket);
}

void recieve_message(char *port, char *name, char *outenc, char *outfile, unsigned char * key, unsigned char *iv)
{
    int welcomeSocket, newSocket;
    char buffer[1024];
    struct sockaddr_in serverAddr;
    struct sockaddr_storage serverStorage;
    socklen_t addr_size;

    welcomeSocket = socket(PF_INET, SOCK_STREAM, 0);

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(atoi(port));
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

    //bind to client A
    bind(welcomeSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));

    if(listen(welcomeSocket,5)==0){}
    else
    printf("Error\n");

    addr_size = sizeof serverStorage;
    newSocket = accept(welcomeSocket, (struct sockaddr *) &serverStorage, &addr_size);

    //receive message from client A with the secret key and nonce
    read(newSocket, buffer, 1024);

    printf("%s recieved a secret key from a user\n", name);

    //break to message to extract secrey key and nonce
    char *r[4];
    char * token = strtok(buffer, "|");
    int i = 0;
    while( token != NULL ) {
        r[i++] = token;
        token = strtok(NULL, "|");
    }

    int len = atoi(r[2]);

    unsigned char decrypted[1024];

    mydecrypt(r[1],key,iv,len,decrypted);

    char *r1[6];
    char * token1 = strtok(decrypted, "$");
    i = 0;
    while( token1 != NULL ) {
        r1[i++] = token1;
        token1 = strtok(NULL, "$");
    }

    unsigned char *secret_key = r1[0];

    // //send nonce+1 to client A as an authentication
    int x = atoi(r1[3]) + 1;
    char nonce2[10];
    sprintf(nonce2,"%d",x);

    // printf("%s\n", nonce2);

    strcpy(buffer,"|310|");
    strcat(buffer,nonce2);
    strcat(buffer,"|");
    strcat(buffer,name);
    strcat(buffer,"|");

    write(newSocket,buffer,1024);

    printf("%s sending an authentication message to the user\n", name);

    // //read the desired message sent by client A
    read(newSocket,buffer,1024);

    printf("%s received a message from user\n", name);

    char* t[2];
    i = 0;
    char * token11 = strtok(buffer, "|");
    while(token11 != NULL) {
        t[i++] = token11;
        token11 = strtok(NULL, "|");
    }

    FILE *fout1;

    fout1 = fopen(outenc,"w");
    fputs(t[0],fout1);

    fclose(fout1);

    mydecrypt(t[0],secret_key,iv,atoi(t[1]),decrypted);

    printf("Message : %s\n", decrypted);

    //write the desired message in a file
    FILE *fout;
    fout = fopen(outfile,"w");

    fputs(decrypted,fout);

    fclose(fout);

    close(welcomeSocket);
}

void server(char *name, char *outenc, char *outfile, char *kdcip, int kdcport, unsigned char *iv)
{
    int clientSocket;
    char buffer[1024];
    struct sockaddr_in serverAddr;
    socklen_t addr_size;

    clientSocket = socket(PF_INET, SOCK_STREAM, 0);

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(kdcport);
    serverAddr.sin_addr.s_addr = inet_addr(kdcip);

    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

    //connect to KDC for registration
    addr_size = sizeof serverAddr;
    connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size);  

    //client's ip address and port number
    char *clientip = "127.0.0.1";
    char *clientport = "6000";

    unsigned char *pwd = "qwertyuiopasdfgh";

    //register the client in KDC
    int value = registration(buffer, clientSocket, name, clientip, clientport, pwd);

    //sleep for sometime so that all the clients register themselves in KDC
    sleep(1);

    //recieve message from client A
    recieve_message(clientport, name, outenc, outfile, pwd, iv);

    close(clientSocket);
}

int main(int argc, char *argv[])
{
    char *name, *SR, *othername, *inputfile, *kdcip, *outenc;
    int opt, kdcport;

    while((opt = getopt(argc, argv, ":n:m:o:i:a:p:s:")) != -1){
        switch(opt) {
            case 'n':
                name = optarg;
                printf("name = %s\n", name);
                break;
            case 'm':
                SR = optarg;
                printf("SC = %s\n", SR);
                break;
            case 'o':
                othername = optarg;
                printf("othername = %s\n", othername);
                break;
            case 'i':
                inputfile = optarg;
                printf("inputfile = %s\n", inputfile);
                break;
            case 'a':
                kdcip = optarg;
                printf("kdcip = %s\n", kdcip);
                break;
            case 'p':
                kdcport = atoi(optarg);
                printf("kdcport = %d\n", kdcport);
                break;
            case 's':
                outenc = optarg;
                printf("outenc = %s\n", outenc);
                break;
            case ':':
                printf("option needs a value\n");
                break;
            case '?':
                printf("unknown option: %c\n", optopt);
                break;
        }
    }

    iv = (unsigned char *)malloc(AES_BLOCK_SIZE*sizeof(unsigned char));
    memset(iv, 0x00, AES_BLOCK_SIZE);

    if(strcmp(SR,"S") == 0)
        client(name,othername,inputfile,kdcip,kdcport,iv);
    else if(strcmp(SR,"R") == 0)
        server(name,outenc,othername,kdcip,kdcport,iv);
    else
        printf("invalid input\n");

    return 0;
}