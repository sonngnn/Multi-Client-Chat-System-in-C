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
#include <sys/stat.h>

#include "common.h"
#include "msg_struct.h"


void extract_after_keyword(const char* source, const char* keyword, char* result) {
    const char* keyword_position = strstr(source, keyword);

    if (keyword_position != NULL) {
        keyword_position = keyword_position + strlen(keyword);
		strcpy(result, keyword_position);
		result[strlen(result) - 1] = '\0';
    } 
	else {
        result[0] = '\0';
    }
}


int handle_bind(char *port_listener)
{
	int sfd;
	struct sockaddr_in servaddr;

	char *port_number = port_listener;
	int port = atoi(port_number);



	sfd = socket(AF_INET, SOCK_STREAM, 0);

	int opt = 1;
	if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1)
	{
		perror("setsockopt");
		return EXIT_FAILURE;
	}

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(port);

	if (bind(sfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
	{
		perror("bind");
		return EXIT_FAILURE;
	}

	return sfd;
}

int handle_connect(char *address, char *port)
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
		sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
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
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(result);
	return sfd;
}

struct message deserialize_message_struct(char *serialized) {
    struct message msg;
    sscanf(serialized, "%d:%[^:]:%s", &msg.type, msg.nick_sender, msg.infos);
    return msg;
}

int connect_to_peer(const char *peer_ip, int peer_port) {

    int peer_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (peer_socket < 0) {
        perror("[Client 1]: Socket creation has failed\n");
        return -1;
    }

    struct sockaddr_in peer_addr;
    memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(peer_port);
    if (inet_pton(AF_INET, peer_ip, &peer_addr.sin_addr) <= 0) {
        perror("[Client 1] -- Error: Invalid or unsupported address\n");
        close(peer_socket);
        return -1;
    }

    if (connect(peer_socket, (struct sockaddr *)&peer_addr, sizeof(peer_addr)) < 0) {
        perror("[Client 1] -- Error: Connection to another peer has failed");
        close(peer_socket);
        return -1;
    }

    return peer_socket;
}


void send_message(int fd, char *message){
	struct message msgstruct;
	msgstruct.pld_len  = strlen(message);


	if(send(fd, &msgstruct, sizeof(msgstruct), 0) <= 0) {
		fprintf(stdout, "Failed to send message structure to client %d.\n", fd);
		return;
	}


	if(send(fd, message, msgstruct.pld_len, 0) <= 0) {
		fprintf(stdout, "Failed to send message to client %d.\n", fd);
		return;
	}

	fprintf(stdout, "Message sent!\n");
}

void terminateAtSpace(char *str) {
    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] == ' ') {
            str[i] = '\0';
            break;
        }
    }
}

void removeNewline(char *str) {
    int len = strlen(str);
    if (len > 0 && str[len - 1] == '\n') {
        str[len - 1] = '\0';
    }
}

char *createNewFilename(const char *originalFilename) {
    char *dot = strrchr(originalFilename, '.');
    int nameLength = dot ? (dot - originalFilename) : strlen(originalFilename);
    char *newFilename = malloc(nameLength + 6 + (dot ? strlen(dot) : 0) + 1);

    if (!newFilename) {
        perror("Error allocating memory\n");
        exit(EXIT_FAILURE);
    }

    strncpy(newFilename, originalFilename, nameLength);
    strcpy(newFilename + nameLength, "_copy");

    if (dot) {
        strcat(newFilename, dot);
    }

    return newFilename;
}


void echo_client(int socketFd, int *fd_conn, int *p2p_fd, int *fd_listen,int *flag,char *name_file)
{
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
        ret = poll(fds, 2, -1);
        if (ret == -1) {
            perror("poll");
            break;
        }

		char nicknameBuff[MSG_LEN];

        if (fds[0].revents & POLLIN)
		{
            memset(&msgstruct, 0, sizeof(struct message));

			ssize_t len = recv(socketFd, &msgstruct, sizeof(struct message), 0);
			if (len <= 0)
			{
				if (len == 0) {
					fprintf(stdout, "Server has closed the connection\n");
				} else {
					perror("Erreur recv\n");
				}
				break;
			}
			
			if (msgstruct.type==0 && msgstruct.pld_len==5)
			{
				msgstruct.type = SETUP_LISTENER;

				*flag = 1;
			}

			snprintf(nicknameBuff, MSG_LEN, "%s", msgstruct.nick_sender);

			if (msgstruct.type == SETUP_LISTENER) {

			}

			len = recv(socketFd, buff, msgstruct.pld_len, 0);
			if (len <= 0)
			{
				perror("Erreur recv\n");
				break;
			}


			if (*fd_listen != -1) {

				char filename[NICK_LEN];

				strncpy(filename, msgstruct.infos, NICK_LEN);
				filename[NICK_LEN - 1] = '\0';
				removeNewline(filename);

				char *newFilename = createNewFilename(filename);

				FILE *outfile = fopen(newFilename, "ab");
				if (outfile == NULL) {
					perror("Error opening file\n");
					exit(EXIT_FAILURE);
				}
				chmod(newFilename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
				ssize_t total_received = 0;
				ssize_t recv_len=0;

				free(newFilename);
				if (recv(*fd_conn, &msgstruct, sizeof(struct message), 0) <= 0) {
					perror("Error receiving file size\n");
					fclose(outfile);
					exit(EXIT_FAILURE);
				}

				long file_size = msgstruct.pld_len;

				while (total_received < file_size)
				{
					memset(&msgstruct, 0, sizeof(struct message));
					memset(buff, 0, MSG_LEN);
					recv_len = recv(*fd_conn, &msgstruct, sizeof(struct message), 0);
					if (recv_len <= 0) {
						if (recv_len == 0) {

						} else {
							perror("[Client 2] -- Error: Was unable to receive message structure\n");
						}
						break;
					}

					recv_len = recv(*fd_conn, buff, MSG_LEN, 0);
					if (recv_len <= 0) {
						if (recv_len == 0) {

						} else {
							perror("[Client 2] -- Error: Was unable to receive message content\n");
						}
						break;
					}

					if (fwrite(buff, 1, recv_len, outfile) != recv_len) {
						perror("Error writing to file\n");
						break;
					}
					total_received += recv_len;
					

				}
				fclose(outfile);

				if (total_received == file_size) {

					
				}
				close(*fd_conn);
				close(*fd_listen);
				*fd_conn = -1;
				*fd_listen=-1;
				msgstruct.type=FILE_ACK;
				char *msg="File received successfully\n";
				fprintf(stdout, "%s\n",msg);
				if (send(socketFd, &msgstruct, sizeof(struct message), 0) == -1)
				{
					perror("Error send (structure)\n");
				}
				if (send(socketFd, msg, msgstruct.pld_len, 0) == -1)
				{
					perror("Error send (message)\n");
				}
				fprintf(stdout, "Sent message: Type=%d, Data=%s\n", msgstruct.type, msg);
			}
			else if (msgstruct.type == SETUP_LISTENER)
			{
				
				*flag=0;
				fprintf(stdout, "[Client]: Awaiting for file transfer...\n");

				int receiver_port = 8101;
				char *receiver_ip = "127.0.0.1";
				*p2p_fd = connect_to_peer(receiver_ip, receiver_port);

				if (*p2p_fd < 0) {
					perror("Error: Connection to peer has failed\n");
					exit(EXIT_FAILURE);
				}

				char filename[NICK_LEN];

				strncpy(filename, msgstruct.infos, NICK_LEN);
				filename[NICK_LEN - 1] = '\0';
				removeNewline(filename);
				name_file=filename;


				chmod(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
				FILE *file = fopen(filename, "rb");
				if (file == NULL) {
					perror("Error opening file\n");
					exit(EXIT_FAILURE);
				}
				char file_buffer[1024];
				int bytes_read;
				msgstruct.type = FILE_SEND;
				int sent=0;

				fseek(file, 0, SEEK_END);
				long file_size = ftell(file);
				fseek(file, 0, SEEK_SET);
				msgstruct.pld_len = file_size;
				if (send(*p2p_fd, &msgstruct, sizeof(struct message), 0) == -1) {
					perror("Error sending file size\n");
					fclose(file);
					exit(EXIT_FAILURE);
				}

				while ((bytes_read = fread(file_buffer, 1, sizeof(file_buffer), file)) > 0)
				{

					sprintf(buff, "%d", bytes_read);
					sent=send(*p2p_fd, &msgstruct, sizeof(struct message), 0);
					if (sent == -1) {
						perror("Error: Was unable to send message structure");
					}
					else
					{
						fprintf(stdout, "Sent %d bytes\n", sent);
					}

					sent =send(*p2p_fd, file_buffer, bytes_read, 0);
					if (sent == -1) {
						perror("Error: Was unable to send message content\n");
					}
					else
					{
						fprintf(stdout, "Sent %d bytes\n", sent);
					}

				}
				if (feof(file)) {

				} else if (ferror(file)) {
					perror("Error reading file\n");
				}
				fclose(file);
				msgstruct.type =FILE_ACK;
				close(*p2p_fd);
				*p2p_fd = -1;

			}
			else if (msgstruct.type == FILE_ACK)
			{
				fprintf(stdout, "File received successfully\n");
				msgstruct.type = ECHO_SEND;
			}
			else {
				fprintf(stdout, "%s\n", buff);
			}
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
                fprintf(stdout, "Client closed.\n");
                break;
            }

			memset(&msgstruct, 0, sizeof(struct message));
			msgstruct.pld_len = n;

			strncpy(msgstruct.infos, "\0", 1);

			snprintf(msgstruct.nick_sender, MSG_LEN, "%s", nicknameBuff);

			if(strncmp(buff, "/nick", 5) == 0)
			{
				msgstruct.type = NICKNAME_NEW;
				char nickname[MSG_LEN];
				extract_after_keyword(buff, "/nick ", nickname);
				snprintf(msgstruct.nick_sender, MSG_LEN, "%s", nickname);
				snprintf(msgstruct.infos, MSG_LEN, "%s", nickname);
			}
			else if(strncmp(buff, "/who\n", 6) == 0){
				char buffer[MSG_LEN];
				msgstruct.type = NICKNAME_LIST;
				snprintf(msgstruct.infos, MSG_LEN, "%s", buffer);
			}
			else if(strncmp(buff, "/whois", 6) == 0){
				msgstruct.type = NICKNAME_INFOS;
				char nickname_aimed[MSG_LEN];
				sscanf(buff, "/whois %s", nickname_aimed);
				snprintf(msgstruct.infos, MSG_LEN, "%s", nickname_aimed);
			}
			else if(strncmp(buff, "/msgall", 7) == 0){
				msgstruct.type = BROADCAST_SEND;
				char buffer[MSG_LEN];
				buffer[0] = '\0';
				snprintf(msgstruct.infos, MSG_LEN, "%s", buffer);
			}
			else if(strncmp(buff, "/msg", 4) == 0){
				msgstruct.type = UNICAST_SEND;
				char nickname_aimed[MSG_LEN];
				sscanf(buff, "/msg %s", nickname_aimed);
				snprintf(msgstruct.infos, MSG_LEN, "%s", nickname_aimed);
			}
			else if(strncmp(buff, "/cmd", 4) == 0){
				msgstruct.type = ASK_CMD;
				char buffer[MSG_LEN];
				buffer[0] = '\0';
				snprintf(msgstruct.infos, MSG_LEN, "%s", buffer);
			}
			else if(strncmp(buff, "/man", 4) == 0){
				msgstruct.type = MAN_CMD;

				char command[MSG_LEN];
				extract_after_keyword(buff, "/man ", command);

				snprintf(msgstruct.infos, MSG_LEN, "%s", command);
			}
			else if(strncmp(buff, "/create", 4) == 0){
				msgstruct.type = MULTICAST_CREATE;

				char channelName[MSG_LEN];
				extract_after_keyword(buff, "/create ", channelName);

				snprintf(msgstruct.infos, MSG_LEN, "%s", channelName);
			}
			else if(strncmp(buff, "/join", 5) == 0){
				msgstruct.type = MULTICAST_JOIN;

				char channelName[MSG_LEN];
				extract_after_keyword(buff, "/join ", channelName);

				snprintf(msgstruct.infos, MSG_LEN, "%s", channelName);
			}
			else if(strncmp(buff, "/channel_list", 13) == 0){
				msgstruct.type = MULTICAST_LIST;

				char buffer[MSG_LEN];
				buffer[0] = '\0';
				snprintf(msgstruct.infos, MSG_LEN, "%s", buffer);
			}
			else if(strncmp(buff, "/leave", 6) == 0){
				msgstruct.type = MULTICAST_QUIT;

				char channelName[MSG_LEN];
				extract_after_keyword(buff, "/leave ", channelName);
				
				snprintf(msgstruct.infos, MSG_LEN, "%s", channelName);
			}
			else if(strncmp(buff, "/kick", 5) == 0){
				msgstruct.type = MULTICAST_KICK;
				
				char nameToKick[MSG_LEN];
				extract_after_keyword(buff, "/kick ", nameToKick);
				
				snprintf(msgstruct.infos, MSG_LEN, "%s", nameToKick);
			}
			else if(strncmp(buff, "/who_channel", 12) == 0){
				msgstruct.type = MULTICAST_WHO;
				
				char buffer[MSG_LEN];
				buffer[0] = '\0';
				snprintf(msgstruct.infos, MSG_LEN, "%s", buffer);
			}
			else if (strncmp(buff, "/send", 5) == 0)
			{
				char receiverNick[MAX_LEN_NICKNAME];
				char filename[MAX_LEN_NICKNAME];
				sscanf(buff, "/send %s %s", receiverNick, filename);
				msgstruct.type = FILE_REQUEST;
				
			}
			else if (strncmp(buff, "Y", 1) == 0)
			{
				*flag =1;
				msgstruct.type = FILE_ACCEPT;

				char *file_transfer_port = "8101";
				*fd_listen = handle_bind(file_transfer_port);

				if (*fd_listen < 0)
				{
					perror("Socket listener has failed setting up the communication");
					exit(EXIT_FAILURE);
				}
				if (listen(*fd_listen, 3) < 0) {
					perror("Usage of 'listen' has failed");
					close(*fd_listen);
				}
				if (send(socketFd, &msgstruct, sizeof(struct message), 0) == -1)
				{
					perror("Error: Was unable to send message structure");
				}
				if (send(socketFd, buff, n, 0) == -1)
				{
					perror("Error: Was unable to send message content");
				}
				*fd_conn = accept(*fd_listen, NULL, NULL);
				if (*fd_conn < 0) {
					perror("Accept failed");
					close(*fd_conn);
					exit(EXIT_FAILURE);
				}

			}
			else if (strncmp(buff, "N", 1) == 0)
			{
				msgstruct.type = FILE_REJECT;
			}
			else
			{
				msgstruct.type = ECHO_SEND;
			}
			if (send(socketFd, &msgstruct, sizeof(struct message), 0) == -1)
			{
				perror("Error send (structure)");
			}
			if (send(socketFd, buff, n, 0) == -1)
			{
				perror("Error send (message)");
			}

		}
    }
}

int main(int argc, char *argv[]) {
	int sfd;
	char *name = argv[1];
	char *adresse_port = argv[2];
	int port = atoi(adresse_port);
	int fd_conn=-1;
	int p2p_fd=-1;
	int fd_listen = -1;
	int flag=0;
	char name_file;
	if (port == 0)
	{
		fprintf(stderr, "Invalid port : %d\n", port);
		return 1;
	}
	sfd = handle_connect(name, adresse_port);
	echo_client(sfd,&fd_conn,&p2p_fd,&fd_listen,&flag, &name_file);

	close(p2p_fd);
	close(sfd);

	return EXIT_SUCCESS;
}
