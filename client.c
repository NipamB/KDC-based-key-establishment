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

int Nonce = 1000;


int registration(char buffer[], int clientSocket, char *name, char * clientip, char *clientport)
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
    strcpy(clientmasterkey,"password");
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

    printf("%s\n", buffer);

    //break the message by delimiter
    char *received[2];
    char * token = strtok(buffer, "|");
    int i = 0;
    while( token != NULL ) {
        received[i++] = token;
        token = strtok(NULL, "|");
    }

    // printf("%s %s\n",received[0],received[1]);
    // if(strcmp(received[0],"302") == 0 && strcmp(received[1],clientname) == 0)
    //     return 1;
    // return 0;
    return 1;
}

void send_message(char *message_b, char ida[], char *ipaddr_b, int port_b, char nonce1[])
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
    strcat(buffer,ida);
    strcat(buffer,"|");

    write(clientSocket,buffer,1024);

    //receive confimation from B with nonce+1
    read(clientSocket,buffer,1024);

    printf("%s\n",buffer);

    char *r[3];
    char * token = strtok(buffer, "|");
    int i = 0;
    while( token != NULL ) {
        r[i++] = token;
        token = strtok(NULL, "|");
    }

    //check if the nonce is correct
    if(atoi(nonce1)+1 == atoi(r[1])){
        //send desired message to client B
        char * message = "hello there! nice meeting you";
        strcpy(buffer,message);

        write(clientSocket,buffer,1024);
    }
    else
        printf("Wrong nonce\n");

    close(clientSocket);
}

void requestKey(char buffer[], int clientSocket, char *name, char *othername)
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

    strcat(buffer,message);
    strcat(buffer,"|");

    strcat(buffer,ida);
    strcat(buffer,"|");

    // printf("%s\n",buffer);

    //send key request message to KDC
    write(clientSocket,buffer,1024);

    //get the secret key appended with the message to be sent to the other client
    read(clientSocket,buffer,1024);

    printf("%s\n", buffer);

    //break the received message from KDC
    char *r1[2];
    char * token1 = strtok(buffer, "|");
    int i = 0;
    while( token1 != NULL ) {
        r1[i++] = token1;
        token1 = strtok(NULL, "|");
    }

    //break the message encrypted with A's key to get B's ip address and port number
    char *r2[2];
    char * token2 = strtok(r1[1], "#");
    i = 0;
    while( token2 != NULL ) {
        r2[i++] = token2;
        token2 = strtok(NULL, "#");
    }


    char *r3[2];
    char * token3 = strtok(r2[0], "$");
    i = 0;
    while( token3 != NULL ) {
        r3[i++] = token3;
        token3 = strtok(NULL, "$");
    }

    char * ipaddr_b = r3[4];
    int port_b = atoi(r3[5]);

    //after getting B's ip address and port number, send message to B
    send_message(r2[1], name, ipaddr_b, port_b, nonce1);
}

void client(char *name, char *othername, char *inputfile, char *kdcip, int kdcport)
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

    //register the client in KDC
    int value = registration(buffer, clientSocket, name, clientip, clientport);

    //sleep for sometime so that all the clients register in KDC
    sleep(1);

    //request for secret key key from KDC to communicate with otehr client
    requestKey(buffer, clientSocket, name, othername);

    close(clientSocket);
}

void recieve_message(char *port, char *name, char *outenc, char *outfile)
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

    if(listen(welcomeSocket,5)==0)
    printf("Listening\n");
    else
    printf("Error\n");

    addr_size = sizeof serverStorage;
    newSocket = accept(welcomeSocket, (struct sockaddr *) &serverStorage, &addr_size);

    //receive message from client A with the secret key and nonce
    read(newSocket, buffer, 1024);

    printf("%s\n", buffer);

    //break to message to extract secrey key and nonce
    char *r[3];
    char * token = strtok(buffer, "|");
    int i = 0;
    while( token != NULL ) {
        r[i++] = token;
        token = strtok(NULL, "|");
    }

    char *r1[2];
    char * token1 = strtok(r[1], "$");
    i = 0;
    while( token1 != NULL ) {
        r1[i++] = token1;
        token1 = strtok(NULL, "$");
    }

    //send nonce+1 to client A as an authentication
    int x = atoi(r1[3]) + 1;
    char nonce2[10];
    sprintf(nonce2,"%d",x);

    strcpy(buffer,"|310|");
    strcat(buffer,nonce2);
    strcat(buffer,"|");
    strcat(buffer,name);
    strcat(buffer,"|");

    write(newSocket,buffer,1024);

    //read the desired message sent by client A
    read(newSocket,buffer,1024);

    printf("Message : %s\n", buffer);

    //write the desired message in a file
    FILE *fout;
    fout = fopen(outfile,"w");

    fputs(buffer,fout);

    fclose(fout);

    close(welcomeSocket);
}

void server(char *name, char *outenc, char *outfile, char *kdcip, int kdcport)
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

    //register the client in KDC
    int value = registration(buffer, clientSocket, name, clientip, clientport);
    // printf("%d\n",value);
    // if(value)
    //     printf("Registration passed\n");
    // else
    //     printf("Registration failed\n");

    //sleep for sometime so that all the clients register themselves in KDC
    sleep(1);

    //recieve message from client A
    recieve_message(clientport, name, outenc, outfile);

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

    if(strcmp(SR,"S") == 0)
        client(name,othername,inputfile,kdcip,kdcport);
    else if(strcmp(SR,"R") == 0)
        server(name,outenc,othername,kdcip,kdcport);
    else
        printf("invalid input\n");

    return 0;
}