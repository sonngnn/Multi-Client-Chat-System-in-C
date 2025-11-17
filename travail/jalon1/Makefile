# Définition des variables
CC = gcc
CFLAGS = -Wall -Wextra -pedantic
TARGET_SERVER = server
TARGET_CLIENT = client

# Fichiers sources (sans common.c)
SRCS_SERVER = server.c
SRCS_CLIENT = client.c

# Règle par défaut
all: $(TARGET_SERVER) $(TARGET_CLIENT)

# Règle pour compiler le serveur
$(TARGET_SERVER): $(SRCS_SERVER)
	$(CC) $(CFLAGS) -o $@ $^

# Règle pour compiler le client
$(TARGET_CLIENT): $(SRCS_CLIENT)
	$(CC) $(CFLAGS) -o $@ $^

# Règle pour nettoyer les fichiers générés
clean:
	rm -f $(TARGET_SERVER) $(TARGET_CLIENT)

# Règle pour afficher les cibles
.PHONY: all clean
