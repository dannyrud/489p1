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
 * server.c
 * Name: Daniel Rudnick
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

#define QUEUE_LENGTH 10
#define RECV_BUFFER_SIZE 2048

/* TODO: server()
 * Open socket and wait for client to connect
 * Print received message to stdout
 * Return 0 on success, non-zero on failure
 */
int server(char *server_port) {
  // Create initial socket
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(sockfd == -1) {
      perror("socket");
      return -1;
  }

  // Build server socket address
  struct sockaddr_in sin;
  bzero((char *)&sin, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  // Convert to network byte format
  sin.sin_port = htons(atoi(server_port));

  // Bind to port
  if ((bind(sockfd, (struct sockaddr *)&sin, sizeof(sin))) < 0) {
    perror("bind");
    close(sockfd);
    return -1;
  }

  if((listen(sockfd,QUEUE_LENGTH)) < 0) {
    perror("listen");
    close(sockfd);
    return -1;
  }
  // Main server socket is setup and ready to go
  while(1) {
    // Create per connection socket
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int newfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
    if(newfd < 0) {
      perror("accept");
      continue;
    }
    char buffer[RECV_BUFFER_SIZE];
    int bytes = 0;
    while(1) {
      bytes = recv(newfd,buffer,RECV_BUFFER_SIZE,0);
      if(bytes > 0) {
        fwrite(buffer, 1, bytes, stdout);
        fflush(stdout);
      } else if(bytes == 0) {
        // EOF, client done sending
        close(newfd);
        break;
      } else {
        perror("recv");
        close(newfd);
        break;
      }
    }
    
  }
  return 0;
}

/*
 * main():
 * Parse command-line arguments and call server function
 */
int main(int argc, char **argv) {
  char *server_port;

  if (argc != 2) {
    fprintf(stderr, "Usage: ./server-c (server port)\n");
    exit(EXIT_FAILURE);
  }

  server_port = argv[1];
  return server(server_port);
}
