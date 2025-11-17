#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <ctype.h>
#include "common.h"
#include "msg_struct.h"


void display_client_list(struct clientListe *listeClient)
{
	struct nodeClient *current = listeClient->premier;

	if (current != NULL)
	{
		fprintf(stdout, "Client register :\n");
	}
	else
	{
		fprintf(stdout, "The client register is empty\n");
	}
	while (current != NULL)
	{
		fprintf(stdout, "Client FD: %d, IP: %s\n", current->socketFD, inet_ntoa(current->address.sin_addr));
		current = current->next;
	}
	fprintf(stdout, "\n");
}


void add_client(struct clientListe *listeClient, int newSocketFD, struct sockaddr_in clientAddress)
{
	struct nodeClient *newClient = malloc(sizeof(*newClient));
	newClient->socketFD = newSocketFD;
	newClient->address = clientAddress;
	newClient->connection_time = time(NULL);
	newClient->next = listeClient->premier;
	listeClient->premier = newClient;
}

void trim(char *str)
{
	char *end;

	while (isspace((unsigned char)*str))
		str++;

	end = str + strlen(str) - 1;
	while (end > str && isspace((unsigned char)*end))
		end--;

	end[1] = '\0';
}

void delete_client(struct clientListe *listeClient, int socketFD)
{
	struct nodeClient *current = listeClient->premier;
	struct nodeClient *previous = NULL;

	while (current != NULL)
	{
		if (current->socketFD == socketFD)
		{
			if (previous == NULL)
			{
				listeClient->premier = current->next;
			}
			else
			{
				previous->next = current->next;
			}
			free(current);
		}
		previous = current;
		current = current->next;
	}
}

void free_client_list(struct clientListe *listeClient)
{
	struct nodeClient *current = listeClient->premier;
	struct nodeClient *nextNode = NULL;

	while (current != NULL)
	{
		nextNode = current->next;
		free(current);
		current = nextNode;
	}

	free(listeClient);
}

struct nodeClient *get_client(struct clientListe *listeClient, int fd)
{
	if (listeClient == NULL)
	{
		return NULL;
	}

	struct nodeClient *current = listeClient->premier;
	while (current != NULL)
	{
		if (current->socketFD == fd)
		{
			return current;
		}
		current = current->next;
	}

	return NULL;
}

struct nodeClient *find_client_by_nickname(struct clientListe *listeClient, char *nickname)
{

	if (listeClient == NULL || nickname == NULL)
	{
		fprintf(stdout, "Invalid input: listeClient or nickname is NULL\n");
		return NULL;
	}


	struct nodeClient *current = listeClient->premier;
	while (current != NULL)
	{
		trim(current->nickname);
		trim(nickname);
		if (current->nickname[0] != '\0' && strcmp(current->nickname, nickname) == 0)
		{
			return current;
		}

		current = current->next;
	}
	return NULL;
}

int handle_bind(char *argv[])
{
	int sfd;
	struct sockaddr_in servaddr;

	char *port_number = argv[1];
	int port = atoi(port_number);

	fprintf(stdout, "Please use the following address to connect to the server : 127.0.0.1.\n");
	fprintf(stdout, "The port number is : %d\n", port);

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

void send_message(int fd, char *message)
{
	struct message msgstruct;
	msgstruct.pld_len = strlen(message) + 1;
	
	if (send(fd, &msgstruct, sizeof(msgstruct), 0) <= 0)
	{
		fprintf(stdout, "Failed to send the message structure to the client %d.\n", fd);
	}

	
	if (send(fd, message, msgstruct.pld_len, 0) <= 0)
	{
		fprintf(stdout, "Failed to send the message to the client %d.\n", fd);
	}
	memset(message, 0, msgstruct.pld_len);


}


void new_client_conexion(int *clientCount, struct pollfd fds[], int sfd, struct clientListe *listeClient)
{
	if (fds[0].revents & POLLIN)
	{
		struct sockaddr_in clientAddress;
		socklen_t clientAddressLen = sizeof(clientAddress);

		memset(&clientAddress, 0, clientAddressLen);

		int newSocketFD = accept(sfd, (struct sockaddr *)&clientAddress, &clientAddressLen);
		if (newSocketFD == -1)
		{
			perror("accept");
			return;
		}

		fds[*clientCount].fd = newSocketFD;
		fds[*clientCount].events = POLLIN;

		(*clientCount)++;

		add_client(listeClient, newSocketFD, clientAddress);

		char welcome_msg[] = "[Server] : Please login using '/nick <nickname>'\n";
		send_message(newSocketFD, welcome_msg);

		display_client_list(listeClient);
	}
}


int verif_nickname(char *nickname, struct clientListe *listeClient, int currentFD)
{
	struct nodeClient *currentClient = listeClient->premier;
	int est_valide = 1;
	char reminder_msg[MSG_LEN];

	if (strlen(nickname) > MAX_LEN_NICKNAME)
	{
		snprintf(reminder_msg, MSG_LEN, "[Server] -- Invalid input: Your nickname is too long. Please choose another one using '/nick <other_nickname>'\n");
		send_message(currentFD, reminder_msg);
		est_valide = 0;
	}

	for (int i = 0; i < strlen(nickname); i++)
	{
		if (!((nickname[i] >= 'a' && nickname[i] <= 'z') || (nickname[i] >= 'A' && nickname[i] <= 'Z') ) && est_valide != 0)
		{
			snprintf(reminder_msg, MSG_LEN, "[Server] -- Invalid input: Please avoid using special caracters or spaces in your nickname. Please choose another one using '/nick <other_nickname>'\n");
			send_message(currentFD, reminder_msg);
			est_valide = 0;
		}
	}

	while (currentClient != NULL)
	{
		if (strcmp(currentClient->nickname, nickname) == 0)
		{
			snprintf(reminder_msg, MSG_LEN, "[Server]: Nickname already taken. Please chose another with /nick <your nickname>\n");
			send_message(currentFD, reminder_msg);
			est_valide = 0;
		}
		currentClient = currentClient->next;
	}

	if (est_valide == 1)
	{
		struct nodeClient *clientToAuthentified = get_client(listeClient, currentFD);
		snprintf(reminder_msg, MSG_LEN, "[Server]: Welcome on the chat %s\n", nickname);
		clientToAuthentified->authenticated = 1;
		strcpy(clientToAuthentified->nickname, nickname);
		send_message(currentFD, reminder_msg);
		return EXIT_SUCCESS;
	}
	else
	{
		return EXIT_FAILURE;
	}
}


char *generate_who(struct clientListe *listeClient, int *clientCount)
{
	char *nickname_list = (char *)malloc(MAX_CLIENT_NUMBER*MAX_LEN_NICKNAME);
	strcpy(nickname_list, "[Server]: The current online users are\n");

	struct nodeClient *current = listeClient->premier;
	while (current != NULL)
	{
		strcat(nickname_list, "  - ");
		strcat(nickname_list, current->nickname);
		strcat(nickname_list, "\n");
		current = current->next;
	}

	return nickname_list;
}

char *extract_after_keyword(const char *source, const char *keyword)
{
	const char *keyword_position = strstr(source, keyword);

	if (keyword_position != NULL)
	{
		keyword_position += strlen(keyword);
		char *result = (char *)malloc(strlen(keyword_position) + 1);

		if (result == NULL)
		{
			return NULL;
		}

		strcpy(result, keyword_position);
		return result;
	}
	else
	{
		return NULL;
	}
}



void extract_keyword(const char *source, const char *keyword, char *result)
{
	const char *keyword_position = strstr(source, keyword);

	if (keyword_position != NULL)
	{
		keyword_position = keyword_position + strlen(keyword);
		strcpy(result, keyword_position);
	}
	else
	{
		result[0] = '\0';
	}
}

void reception_and_emission(int *clientCount, struct pollfd fds[], struct clientListe *listeClient)
{
	struct message msgstruct;
	char buff[MSG_LEN];
	for (int i = 1; i < *clientCount; i++)
	{
		if (fds[i].revents & POLLIN)
		{
			memset(&msgstruct, 0, sizeof(struct message));
			memset(buff, 0, MSG_LEN);


			int len = recv(fds[i].fd, &msgstruct, sizeof(struct message), 0);
			if (len <= 0)
			{
				fprintf(stdout, "Client %d disconnected or error.\n", fds[i].fd);
				fprintf(stdout, "\n");
				delete_client(listeClient, fds[i].fd);
				close(fds[i].fd);
				if (i < *clientCount - 1)
				{
					fds[i] = fds[*clientCount - 1];
				}

				(*clientCount)--;
				i--;
				continue;
			}

			len = recv(fds[i].fd, buff, msgstruct.pld_len, 0);
			if (len <= 0)
			{
				fprintf(stdout, "Client %d lost the connection : Error\n", fds[i].fd);
				fprintf(stdout, "\n");
				delete_client(listeClient, fds[i].fd);
				close(fds[i].fd);
				fds[i] = fds[*clientCount - 1];
				(*clientCount)--;
				i--;
				continue;
			}
			else if (strcmp(buff, "/quit\n") == 0)
			{
				fprintf(stdout, "Client %d disconnected\n", fds[i].fd);
				fprintf(stdout, "\n");
				delete_client(listeClient, fds[i].fd);
				close(fds[i].fd);
				fds[i] = fds[*clientCount - 1];
				(*clientCount)--;
				i--;
				continue;
			}

			struct nodeClient *currentClient = get_client(listeClient, fds[i].fd);
			if ((msgstruct.type == NICKNAME_NEW) || (currentClient->authenticated == 0))
			{
				if (strncmp(buff, "/nick", 5) == 0)
				{
					char *nickname = extract_after_keyword(buff, "/nick ");
					trim(nickname);
					
					verif_nickname(nickname, listeClient, fds[i].fd);
					free(nickname);
				}
				else
				{
					char reminder_msg[MSG_LEN];
					snprintf(reminder_msg, MSG_LEN, "%s", "[Server]: Please login using '/nick <nickname>' (no special caracters or spaces)\n");
					send_message(fds[i].fd, reminder_msg);
				}
				fprintf(stdout, "[Server]: pld_len: %i / nick_sender: %s / type: %s / info: %s\n", msgstruct.pld_len, currentClient->nickname, msg_type_str[msgstruct.type], msgstruct.infos);
				fprintf(stdout, "\n");
			}
			else if (msgstruct.type == NICKNAME_LIST)
			{
				char *nickname_list = generate_who(listeClient, clientCount);
				printf("  ");
				trim(nickname_list);
				send_message(fds[i].fd, nickname_list);
				fprintf(stdout, "[Server]: pld_len: %i / nick_sender: %s / type: %s / infos: %s\n", msgstruct.pld_len, currentClient->nickname, msg_type_str[msgstruct.type], msgstruct.infos);
				free(nickname_list);
			}
			else if (msgstruct.type == NICKNAME_INFOS)
			{
				fflush(stdout);
			
				char *nickname_aimed = extract_after_keyword(buff, "/whois ");
				trim(nickname_aimed);

				printf("Pseudo recherché : %s\n", nickname_aimed);

				
				struct nodeClient *clientAimed = find_client_by_nickname(listeClient, nickname_aimed);

				if (clientAimed != NULL)
				{
					char info[MSG_LEN];
					char ip[INET_ADDRSTRLEN];
					inet_ntop(AF_INET, &clientAimed->address.sin_addr, ip, INET_ADDRSTRLEN);


					char time_buff[80];
					struct tm *time_info = localtime(&clientAimed->connection_time);
					strftime(time_buff, sizeof(time_buff), "%Y-%m-%d %H:%M:%S", time_info);

					
					snprintf(info, MSG_LEN, "[Server] User info:\n- Nickname: %s\n- IP: %s\n- Port: %d\n- Connected since: %s", clientAimed->nickname, ip, ntohs(clientAimed->address.sin_port), time_buff);
					strcat(info, "\n");

					printf("  ");
					send_message(fds[i].fd, info);
				}
				else
				{
					char *error_msg = "[Server] -- Error: User not found.\n";
					send_message(fds[i].fd, error_msg);
				}

				
				fprintf(stdout, "[Server]: pld_len: %i / nick_sender: %s / type: %s / infos: %s\n", msgstruct.pld_len, currentClient->nickname, msg_type_str[msgstruct.type], msgstruct.infos);
				free(nickname_aimed);
				fprintf(stdout, "\n");
			}
			else if (msgstruct.type == BROADCAST_SEND)
			{
				char *message = extract_after_keyword(buff, "/msgall");
				for (int j = 1; j < *clientCount; j++)
				{
					char message_to_broadcast[MSG_LEN];
					snprintf(message_to_broadcast, MSG_LEN, "[%s]: %s\n", currentClient->nickname, message);
					if (fds[j].fd != fds[i].fd)
					{
						fprintf(stdout, "Sending to the client %d\n", fds[j].fd);
						printf("  ");
						send_message(fds[j].fd, message_to_broadcast);
						fprintf(stdout, "Sent to the client %d\n", fds[j].fd);
					}
				}
				fprintf(stdout, "[Server]: pld_len: %i / nick_sender: %s / type: %s / infos: %s\n", msgstruct.pld_len, currentClient->nickname, msg_type_str[msgstruct.type], msgstruct.infos);

				char confirmation[MSG_LEN];
				snprintf(confirmation, MSG_LEN, "[Server]: Broadcast done\n");

				send_message(fds[i].fd, confirmation);
				free(message);
				fprintf(stdout, "\n");
			}
			else if (msgstruct.type == UNICAST_SEND)
			{
				char nickname[MAX_LEN_NICKNAME];
				sscanf(buff, "/msg %s", nickname);
				trim(nickname);
				struct nodeClient *clientAimed = find_client_by_nickname(listeClient, nickname);
				if (clientAimed == NULL)
				{
					char message[MSG_LEN];
					snprintf(message, MSG_LEN, "[Server] -- Error: User %s doesn't exist in the database\n", nickname);
					send_message(fds[i].fd, message);
					fprintf(stdout, "\n");
				}
				else
				{
					char message[MSG_LEN];
					extract_keyword(buff, nickname, message);

					char message_to_broadcast[MSG_LEN];
					snprintf(message_to_broadcast, MSG_LEN, "[%.128s]: %.128s\n", currentClient->nickname, message);

					struct nodeClient *clientAimed = find_client_by_nickname(listeClient, nickname);
					printf("  ");
					send_message(clientAimed->socketFD, message_to_broadcast);
					fprintf(stdout, "[Server]: pld_len: %i / nick_sender: %s / type: %s / infos: %s\n", msgstruct.pld_len, currentClient->nickname, msg_type_str[msgstruct.type], msgstruct.infos);
					fprintf(stdout, "\n");
				}
			}
			else
			{
				fprintf(stdout, "[Server]: pld_len: %i / nick_sender: %s / type: %s / infos: %s\n", msgstruct.pld_len, currentClient->nickname, msg_type_str[msgstruct.type], msgstruct.infos);
				fprintf(stdout, "[Server]: %s", buff);
				send_message(fds[i].fd, buff);
				fprintf(stdout, "\n");
			}
		}
	}
}


void free_memory(int *clientCount, struct pollfd fds[], struct clientListe *listeClient)
{
	for (int i = 0; i < *clientCount; i++)
	{
		close(fds[i].fd);
	}

	free_client_list(listeClient);
	listeClient = NULL;
}



int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		fprintf(stdout, "Invalid input : Please use './server <port_number>' \n");
		return EXIT_FAILURE;
	}

	int sfd = handle_bind(argv);

	if (listen(sfd, 5) != 0)
	{
		perror("listen() error");
		exit(EXIT_FAILURE);
	}

	struct pollfd fds[MAX_CLIENT_NUMBER];
	fds[0].fd = sfd;
	fds[0].events = POLLIN;

	int clientCount = 1;

	struct clientListe *listeClient = malloc(sizeof(struct clientListe));
	if (listeClient == NULL)
	{
		exit(EXIT_FAILURE);
	}
	listeClient->premier = NULL;

	while (1)
	{
		int ret = poll(fds, clientCount, -1); 
		if (ret == -1)
		{
			perror("poll");
			exit(EXIT_FAILURE);
		}

		new_client_conexion(&clientCount, fds, sfd, listeClient);
		reception_and_emission(&clientCount, fds, listeClient);

		if (clientCount == 1)
		{
			fprintf(stdout, "[Server]: No more connected clients : server shutdown\n");
			break;
		}
	}

	free_memory(&clientCount, fds, listeClient); 

	return EXIT_SUCCESS;
}
