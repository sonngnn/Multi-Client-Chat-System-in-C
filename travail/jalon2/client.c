#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <poll.h>
#include "common.h"
#include "msg_struct.h"


void send_message(int fd, char *message)
{
	struct message msgstruct;
	msgstruct.pld_len  = strlen(message) +1;

	if(send(fd, &msgstruct, sizeof(msgstruct), 0) <= 0) 
    {
		fprintf(stdout, "Failed to send the message structure to the client %d.\n", fd);
		return;
	}
	if(send(fd, message, msgstruct.pld_len, 0) <= 0) 
    {
		fprintf(stdout, "Failed to send the message to the client %d.\n", fd);
		return;
	}

	fprintf(stdout, "Message sent successfully!\n");

}
void echo_client(int socketFd) 
{
	
	int flag = 0;
    char buff[MSG_LEN];
    int ret;
	struct message msgstruct;

	struct pollfd fds[2];
    fds[0].fd = socketFd;
    fds[0].events = POLLIN;

    fds[1].fd = STDIN_FILENO;
    fds[1].events = POLLIN;

    while (1) 
    {
		if(flag == 1)
        {
			fprintf(stdout, "\n[Client]: ");
			fflush(stdout);
		}

        ret = poll(fds, 2, -1);
        if (ret == -1) 
        {
            perror("poll");
            break;
        }

        if (fds[0].revents & POLLIN) 
        {
            memset(&msgstruct, 0, sizeof(struct message));


			if (recv(socketFd, &msgstruct, sizeof(struct message), 0) <= 0) 
            {
				break;
			}


			if (recv(socketFd, buff, msgstruct.pld_len, 0) <= 0) 
            {
				break;
			}

			fprintf(stdout, "[Client]: pld_len: %i / nick_sender: %s / type: %s / infos: %s\n", msgstruct.pld_len, msgstruct.nick_sender, msg_type_str[msgstruct.type], msgstruct.infos);
			fprintf(stdout, "%s", buff);
			flag = 1;
			}
		

        if (fds[1].revents & POLLIN) 
        {
            memset(buff, 0, MSG_LEN);
            ssize_t n = read(STDIN_FILENO, buff, MSG_LEN);

			if (strncmp(buff, "/quit\n", 6) == 0) 
            {
				send_message(socketFd, buff);
				fprintf(stdout, "Disconnected...\n");
				close(socketFd);
				exit(0); 
			}

            if (n <= 0 || strncmp(buff, "exit\n", 5) == 0) 
            {
                fprintf(stdout, "Status update : Client is now closed.\n");
                break;
            }
			

			memset(&msgstruct, 0, sizeof(struct message));
			msgstruct.pld_len = n;
			msgstruct.type = ECHO_SEND;
			strncpy(msgstruct.infos, "\0", 1);

			if(strncmp(buff, "/nick", 5) == 0)
            {
				msgstruct.type = NICKNAME_NEW;
			}
			else if(strncmp(buff, "/whois", 6) == 0)
            {
				msgstruct.type = NICKNAME_INFOS;
			}
			else if(strncmp(buff, "/who", 4) == 0)
            {
				msgstruct.type = NICKNAME_LIST;
			}			
			else if(strncmp(buff, "/msgall", 7) == 0)
            {
				msgstruct.type = BROADCAST_SEND;	
			}
			else if(strncmp(buff, "/msg", 4) == 0)
            {
				msgstruct.type = UNICAST_SEND;	
			}
			else
            {
				msgstruct.type = ECHO_SEND;
			}
						
			if (send(socketFd, &msgstruct, sizeof(struct message), 0) == -1) 
            {
				perror("[Client] -- Error: Could not send the structure of the message");
			}
			if (send(socketFd, buff, n, 0) == -1) 
            {
				perror("[Client] -- Error: Could not send the content of the message");
			}

            fprintf(stdout, "msgstruct.type : %u\n", msgstruct.type);

			flag = 0;
        }
    }
}



int handle_connect(const char *address, const char *port) 
{
	int sfd;

	struct addrinfo hints, *result, *rp;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(address, port, &hints, &result) != 0) 
    {
        perror("getaddrinfo()");
        exit(EXIT_FAILURE);
    }

	for (rp = result; rp != NULL; rp = rp->ai_next) 
    {
		sfd = socket(rp->ai_family, rp->ai_socktype,rp->ai_protocol);
		if (sfd == -1) 
        {
			continue;
		}
		if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1) 
        {
			break;
		}
		close(sfd);
	}

	if (rp == NULL) 
    {
		fprintf(stderr, "[Client] -- Error : Could not connect\n");
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(result);
	return sfd;
}

int main(int argc, char *argv[]) 
{
	int sfd;

	char *name=argv[1];

	char *adresse_port = argv[2]; 
    int port =atoi(adresse_port); 

	if (port == 0) 
    {
        fprintf(stderr, "Invalid port number : %d / Please use './client <server_address> <port_number>'\n", port);
        return 1;
    }

	sfd = handle_connect(name, adresse_port);
	echo_client(sfd);
	close(sfd);
	return EXIT_SUCCESS;
}
