/*****************************************************************************
 *
 *     This file is part of the University of Michigan (U-M) EECS 489.
 *
 *     U-M EECS 489 is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     U-M EECS 489 is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with U-M EECS 489. If not, see <https://www.gnu.org/licenses/>.
 *
 *****************************************************************************/

/*
 * client.c
 * Name:
 * PUID:
 */

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SEND_BUFFER_SIZE 2048

/* TODO: client()
 * Open socket and send message from stdin.
 * Return 0 on success, non-zero on failure
 */
int client(char *server_ip, char *server_port) { 
  int sockfd = socket(AF_INET,SOCK_STREAM,0);
  if(sockfd == -1) {
      perror("socket");
      return -1;
  }
  // Build server address
  struct sockaddr_in server;
  memset(&server, 0, sizeof(server));
  server.sin_family = AF_INET;
  int port = atoi(server_port);
  server.sin_port = htons(port);
  // Convert Server IP to binary format
  if (inet_pton(AF_INET, server_ip, &server.sin_addr) <= 0) {
    close(sockfd);
    fprintf(stderr, "Invalid IP Address\n");
    return -1;
  }
  // Located the server, time to do TCP handshake
  if (connect(sockfd, (struct sockaddr *)&server, sizeof(server)) < 0){
    perror("connect");
    close(sockfd);
    return -1;
  }
  // TCP connection established can send now
  char buffer[SEND_BUFFER_SIZE];
  while (1){
    size_t bytes = fread(buffer,1,SEND_BUFFER_SIZE,stdin);
    if (bytes > 0) {
    size_t bytes_sent = 0;
    while (bytes_sent < bytes) {
      ssize_t n = send(sockfd, buffer + bytes_sent, bytes - bytes_sent, 0);
      if (n < 0) {
        perror("send");
        close(sockfd);
        return -1;
      }
      if (n == 0) {
        fprintf(stderr, "send returned 0\n");
        close(sockfd);
        return -1;
      }
      bytes_sent += (size_t)n;
    }
  } else {
      if(feof(stdin)) {
        // Nothing left to send from stdin
        close(sockfd);
        break;
      } else {
        fprintf(stderr, "stdin error\n");
        close(sockfd);
        return -1;
      }
    }
  }
  return 0;
}

/*
 * main()
 * Parse command-line arguments and call client function
 */
int main(int argc, char **argv) {
  char *server_ip;
  char *server_port;

  if (argc != 3) {
    fprintf(stderr,
            "Usage: ./client-c (server IP) (server port) < (message)\n");
    exit(EXIT_FAILURE);
  }

  server_ip = argv[1];
  server_port = argv[2];
  return client(server_ip, server_port);
}
