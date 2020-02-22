#include<stdio.h>
#include<unistd.h>
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h>
#include <arpa/inet.h>
#include <time.h>

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

void receive_message(char* port, char* outfile, char* passwdfile, int newsocket) {
    
    char buffer[1024];
    
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
        char *decrypted = r[1];

        char *s[3];

        char *token2 = strtok(decrypted, "$");
        int l = 0;
        while(token2 != NULL) {
            s[l++] = token2;
            token2 = strtok(NULL, "$");
        }

        char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        char sharedKey[8];
        srand(time(0));
        for(int j = 0; j < 8; j++) {
            sharedKey[j] = charset[rand() % 62];
        }

        
        int indexB = find(clientName, s[1], numOfReg);
        int indexA = find(clientName, s[0], numOfReg);
        
        char str2[1024];
        strcpy(str2, sharedKey);
        strcat(str2, s[0]);
        strcat(str2, s[1]);
        strcat(str2, s[2]);
        strcat(str2, clientIpAddr[indexA]);
        strcat(str2, clientPortNum[indexA]);

        // encrypt str2 using B's key

        char str1[1024];
        strcpy(str1, sharedKey);
        strcat(str1, s[0]);
        strcat(str1, s[1]);
        strcat(str1, s[2]);
        strcat(str1, clientIpAddr[indexB]);
        strcat(str1, clientPortNum[indexB]);
        strcat(str1, str2); // replace str2 with encryption of str2 with B's key

        //encrypt str1 using A's key

        strcpy(buffer, "|306|");
        strcat(buffer, str1); // replace str1 with encryption of str1 using A's key
        strcat(buffer, "|");

        write(newsocket, buffer, 1024);

        int clientSocket;
        struct sockaddr_in serverAddr2;
        socklen_t addr_size;

        clientSocket = socket(PF_INET, SOCK_STREAM, 0);
        
        serverAddr2.sin_family = AF_INET;
        serverAddr2.sin_port = htons(atoi(clientPortNum[indexB]));
        serverAddr2.sin_addr.s_addr = inet_addr(clientIpAddr[indexB]);

        memset(serverAddr2.sin_zero, '\0', sizeof serverAddr2.sin_zero);
        
        addr_size = sizeof serverAddr2;

        connect(clientSocket, (struct sockaddr *) &serverAddr2, addr_size);

        strcpy(buffer, "|309|");
        strcat(buffer, str2); // instead of str2, use encryption of str2 using B's key
        strcat(buffer, s[0]);
        strcat(buffer, "|");

        write(clientSocket, buffer, 1024);

        close(clientSocket);
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

    int socket_id, newsocket;
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

    fclose(out);
    
    int m = 0;
    while(m < 2) {
        receive_message(port, outfile, passwdfile, newsocket);
        m++;
    }
    
    close(newsocket);

    return 0;
}
