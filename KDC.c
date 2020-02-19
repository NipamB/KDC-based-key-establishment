#include<stdio.h>
#include<unistd.h>
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include "aes.h"
#define SA struct sockaddr
#define MAX 100

char *outfilename, *pwdfile;
unsigned char *key, *iv;


void func(int sockfd) {
    char buff[MAX];
    int n;

    while(1) {
        bzero(buff, MAX);

        read(sockfd, buff, sizeof(buff));

        printf("From client: %s", buff);

        char* token = strtok(buff, "|");
        if(strcmp(token, " 301") == 0) {
            puts("registration message");
            int regmsg, i = 0, j, k;
            char **array = (char**)malloc(5*sizeof(char*));  
            while(token != NULL) {
                array[i] = token;
                token = strtok(NULL, "|");
                i++;
            }
            
            unsigned char encryptedKey[128];
            int encryptedKey_len = encrypt(array[3], strlen(array[3]), key, iv, encryptedKey);


            FILE* fp;
            fp = fopen(pwdfile, "w");
            fprintf(fp,":%s:%s:%s:%s:\n", array[4], array[1], array[2], array[3]);
            
            fflush(fp);
            
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

        else {

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