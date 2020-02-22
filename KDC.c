#include<stdio.h>
#include<unistd.h>
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h>

char *clientIpAddr[1024], *clientPortNum[1024], *clientMasterKey[1024], *clientName[1024];
int numOfReg;

int find(char **array, char* reqString, int n) {
    for(int i = 0; i < n; i++) {
        if(strcmp(array[i], reqString) == 0) {
            return i;
        }
    }
    return -1;
}

void receive_message(char* port, char* outfile, char* passwdfile) {
    int socket_id, newsocket;
    char buffer[1024];
    struct sockaddr_in serverAddr;
    struct sockaddr_storage serverStorage;
    socklen_t addr_size;

    socket_id = socket(AF_INET, SOCK_STREAM, 0);
    
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(atoi(port));
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

    bind(socket_id, (struct sockaddr *) &serverAddr, sizeof(serverAddr));

    listen(socket_id, 5);

    addr_size = sizeof serverStorage;

    newsocket = accept(socket_id, (struct sockaddr *) &serverStorage, &addr_size);

    read(newsocket, buffer, 1024);

    printf("%s\n", buffer);

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
            clientName[numOfReg] = r[4];
            clientMasterKey[numOfReg] = r[3];
            clientPortNum[numOfReg] = r[2];
            clientIpAddr[numOfReg] = r[1];
            numOfReg++;
        }
        else {
            clientMasterKey[index] = r[3];
        }

        FILE *pwd;
        pwd = fopen(passwdfile, "w");
        fprintf(pwd, ":%s:%s:%s:%s:\n", r[4], r[1], r[2], r[3]); 
        // instead of r[3], use encryption of r[3] using KDC's password
        
        fflush(pwd);

        fclose(pwd);

        strcpy(buffer, "|302|");
        strcat(buffer, r[4]);
        strcat(buffer, "|");

        write(newsocket, buffer, 1024);

        fclose(newsocket);

    }
    else if(atoi(token) == 305) {
        puts("key request message");

        char* r[3];
        int i = 0;
        while(token != NULL) {
            r[i++] = token;
            token = strtok(NULL, "|");
        }

        //decrypt r[1] and store it in "decrypted"
        char decrypted[1024];

        
        char idA[12], idB[12], nonce1[4];

        memset(idA, '\0', sizeof(idA));
        memset(idB, '\0', sizeof(idB));
        memset(nonce1, '\0', sizeof(nonce1));
        
        strncpy(idA, decrypted, 12);
        strncpy(idB, decrypted+12, 12);
        strncpy(nonce1, decrypted+24, 4);

        
        char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        char sharedKey[8];
        srand(time(0));
        for(int j = 0; j < 8; j++) {
            sharedKey[j] = charset[rand() % 62];
        }

        
        int indexB = find(clientName, idB, numOfReg);
        int indexA = find(clientName, idA, numOfReg);
        
        char str2[1024];
        strcpy(str2, sharedKey);
        strcat(str2, idA);
        strcat(str2, idB);
        strcat(str2, nonce1);
        strcat(str2, clientIpAddr[indexA]);
        strcat(str2, clientPortNum[indexA]);

        // encrypt str2 using B's key

        char str1[1024];
        strcpy(str1, sharedKey);
        strcat(str1, idA);
        strcat(str1, idB);
        strcat(str1, nonce1);
        strcat(str1, clientIpAddr[indexB]);
        strcat(str1, clientPortNum[indexB]);
        strcat(str1, str2); // replace str2 with encryption of str2 with B's key

        //encrypt str1 using A's key

        strcpy(buffer, "|306|");
        strcat(buffer, str1); // replace str1 with encryption of str1 using A's key
        strcat(buffer, "|");

        write(newsocket, buffer, 1024);

        fclose(newsocket);

        int clientSocket;
        struct sockaddr_in serverAddr;
        socklen_t addr_size;

        clientSocket = socket(PF_INET, SOCK_STREAM, 0);
        
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(atoi(clientPortNum[indexB]));
        serverAddr.sin_addr.s_addr = inet_addr(clientIpAddr[indexB]);

        memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);
        
        addr_size = sizeof serverAddr;

        connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size);

        strcpy(buffer, "|309|");
        strcat(buffer, str2); // instead of str2, use encryption of str2 using B's key
        strcat(buffer, idA);
        strcat(buffer, "|");
        
        write(clientSocket, buffer, 1024);

        fclose(clientSocket);
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

    receive_message(port, outfile, passwdfile);

    return 0;
}
