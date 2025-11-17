#define SERV_PORT "8080"
#define SERV_ADDR "127.0.0.1"
#define MSG_LEN (1024)

#define MAX_CLIENT_NUMBER (10)
#define MAX_LEN_NICKNAME (15)
#define MAX_SALONS (2)
#define NOM_SALON_LEN (15)

struct info{
    short s;
    long l;
};

struct clientListe{
    struct nodeClient *premier;
};

struct nodeClient{
    int socketFD;
    int authenticated;
    time_t connection_time;
    char nickname[15];
    struct sockaddr_in address;
    struct nodeClient *next;
};

struct ListeSalon {
     struct Salon *premier;
};

struct Salon {
    char nom[NOM_SALON_LEN];
    struct nodeClient *clients;
    int nombre_clients; 
    struct Salon *next;  
    int nombre_salons;
};

