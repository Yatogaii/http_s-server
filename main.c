#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define HTTP_PORT 80
#define HTTPS_PORT 443
#define BUFFER_SIZE 1024

// 日志颜色
#define LOG_COLOR_RED "\x1b[31m"
#define LOG_COLOR_GREEN "\x1b[32m"
#define LOG_COLOR_YELLOW "\x1b[33m"
#define LOG_COLOR_BLUE "\x1b[34m"
#define LOG_COLOR_RESET "\x1b[0m"

#define ROOT_DIR "/root/network_lab1/"

// 日志级别
typedef enum { DEBUG, INFO, WARN, ERROR } LogLevel;

#define LOG_DEBUG 1

void log_message(LogLevel level, const char *format, ...) {
#ifdef LOG_DEBUG
  const char *color;
  const char *level_strings[4] = {"DEBUG", "INFO", "WARN", "ERROR"};
  switch (level) {
  case DEBUG:
    color = LOG_COLOR_BLUE;
    break;
  case INFO:
    color = LOG_COLOR_GREEN;
    break;
  case WARN:
    color = LOG_COLOR_YELLOW;
    break;
  case ERROR:
    color = LOG_COLOR_RED;
    break;
  default:
    color = LOG_COLOR_RESET;
  }

  printf("%s[%s] ", color, level_strings[level]);

  va_list args;
  va_start(args, format);
  vprintf(format, args);
  va_end(args);

  printf("%s\n", LOG_COLOR_RESET);
#endif
}

void init_openssl() {
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
  log_message(DEBUG, "OpenSSL initialized");
}

SSL *get_new_ssl() {
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  method = SSLv23_server_method();
  ctx = SSL_CTX_new(method);
  if (!ctx) {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    log_message(ERROR, "Failed to create SSL context");
    exit(EXIT_FAILURE);
  }

  log_message(DEBUG, "SSL context created");
  SSL_CTX_set_ecdh_auto(ctx, 1);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  // Set the key and cert

  if (SSL_CTX_use_certificate_file(ctx, "keys/cnlab.cert", SSL_FILETYPE_PEM) <=
      0) {
    ERR_print_errors_fp(stderr);
    log_message(ERROR, "Failed to load SSL certificate");
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, "keys/cnlab.prikey", SSL_FILETYPE_PEM) <=
      0) {
    ERR_print_errors_fp(stderr);
    log_message(ERROR, "Failed to load SSL private key");
    exit(EXIT_FAILURE);
  }
  if (SSL_CTX_check_private_key(ctx) <= 0) {
    // 检查私钥
    printf("check private key error");
    exit(1);
  }

  SSL *ssl = SSL_new(ctx);

  if (ssl == NULL) {
    printf("SSL_new error");
    exit(1);
  }

  log_message(DEBUG, "SSL context configured");
  return ssl;
}

void get_file_content(char *file_path, char *response_body) {
  FILE *file = fopen(file_path, "r");
  if (file != NULL) {
    size_t new_len = fread(response_body, sizeof(char), BUFFER_SIZE, file);
    if (new_len == 0) {
      fputs("Error reading file", stderr);
    } else {
      response_body[new_len++] = '\0';
    }
    fclose(file);
  }
}

void get_partial_content(char *file_path, char *response_body, char *request) {
  char *range_header = strstr(request, "Range: bytes=");
  if (range_header) {
    range_header += strlen("Range: bytes=");
    int start_range, end_range;
    sscanf(range_header, "%d-%d", &start_range, &end_range);

    FILE *file = fopen(file_path, "rb");
    if (file) {
      fseek(file, start_range, SEEK_SET);
      fread(response_body, sizeof(char), end_range - start_range + 1, file);
      fclose(file);
    }
  }
}

int has_range_field(char *request) {
  // This is a simple implementation and might not cover all cases.
  return strstr(request, "Range:") != NULL;
}

int file_exists(char *file_path) {
  struct stat buffer;
  return (stat(file_path, &buffer) == 0);
}

char *get_file_path(char *url) {
  char *file_path = malloc(strlen(url) + strlen(ROOT_DIR) + 1);
  strcpy(file_path, ROOT_DIR);
  strcat(file_path, url);
  return file_path;
}

void send_http_response(int client_socket, SSL *ssl, int status_code,
                        const char *file_path) {
  char header[1024];
  char response[1024];

  if (status_code == 200) {
    struct stat file_stat;
    stat(file_path, &file_stat);
    sprintf(header,
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
            "%ld\r\n\r\n",
            file_stat.st_size);

    if (ssl) {
      SSL_write(ssl, header, strlen(header));
    } else {
      send(client_socket, header, strlen(header), 0);
    }

    int file_fd = open(file_path, O_RDONLY);
    int bytes_read;
    while ((bytes_read = read(file_fd, response, sizeof(response))) > 0) {
      if (ssl) {
        SSL_write(ssl, response, bytes_read);
      } else {
        send(client_socket, response, bytes_read, 0);
      }
    }
    close(file_fd);
  } else if (status_code == 404) {
    sprintf(header, "HTTP/1.1 404 Not Found\r\nContent-Type: "
                    "text/plain\r\nContent-Length: 9\r\nConnection: "
                    "close\r\n\r\nNot Found");
    if (ssl) {
      SSL_write(ssl, header, strlen(header));
    } else {
      send(client_socket, header, strlen(header), 0);
    }
  }
}

void send_http_partial_response(int client_socket, SSL *ssl,
                                const char *file_path, const char *range_header,
                                struct stat *file_stat) {
  // 解析Range头以确定所请求的范围
  int start, end;
  sscanf(range_header, "bytes=%d-%d", &start, &end);

  if (end == 0 || end > file_stat->st_size) {
    end = file_stat->st_size - 1;
  }

  int content_length = end - start + 1;
  char response_header[1024];
  sprintf(response_header,
          "HTTP/1.1 206 Partial Content\r\nContent-Type: "
          "text/plain\r\nContent-Range: bytes %d-%d/%ld\r\nContent-Length: "
          "%d\r\n\r\n",
          start, end, file_stat->st_size, content_length);

  if (ssl) {
    SSL_write(ssl, response_header, strlen(response_header));
  } else {
    send(client_socket, response_header, strlen(response_header), 0);
  }

  int file_fd = open(file_path, O_RDONLY);
  lseek(file_fd, start, SEEK_SET);
  char buffer[1024];
  int bytes_to_send = content_length;

  while (bytes_to_send > 0) {
    int bytes_read = read(file_fd, buffer, sizeof(buffer));
    int bytes = (bytes_read < bytes_to_send) ? bytes_read : bytes_to_send;
    if (ssl) {
      SSL_write(ssl, buffer, bytes);
    } else {
      send(client_socket, buffer, bytes, 0);
    }
    bytes_to_send -= bytes;
  }

  close(file_fd);
}

void send_http_redirect(int client_socket, SSL *ssl, const char *location) {
  char response[1024];
  sprintf(response, "HTTP/1.1 301 Moved Permanently\r\nLocation: %s\r\n\r\n",
          location);

  if (ssl) {
    SSL_write(ssl, response, strlen(response));
  } else {
    send(client_socket, response, strlen(response), 0);
  }
}

void handle_request(int client_socket, SSL *ssl) {
  char buffer[1024];
  int bytes_read;

  // 从 client_socket 或 ssl 读取请求
  if (ssl) {
    bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
  } else {
    bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
  }

  if (bytes_read <= 0)
    return;
  buffer[bytes_read] = '\0';

  char method[10], url[255], protocol[10], file_path[512];
  sscanf(buffer, "%s %s %s", method, url, protocol);
  log_message(INFO, url);

  sprintf(file_path, "%s%s", ROOT_DIR, url);

  struct stat file_stat;
  int file_exists = (stat(file_path, &file_stat) == 0);

  // 重定向HTTP到HTTPS
  if (!ssl && strncmp(url, "/http", 5) != 0) {
        char host[256]; // 创建一个变量来存储 host 信息
    char *host_start = strstr(buffer, "Host: ");
    if (host_start) {
      host_start += 6; // 移过 "Host: "
      char *host_end = strstr(host_start, "\r\n");
      if (host_end) {
        *host_end = '\0'; // 临时终止字符串

        strncpy(host, host_start, sizeof(host));
        host[sizeof(host) - 1] = '\0'; // 确保字符串以 null 结尾

        // 在此处使用 host 变量，例如发送重定向响应
        // ...

        *host_end = '\r'; // 恢复原始 buffer
      }
    } else {
      log_message(ERROR, "Cant find Host in Http Header");
      return;
    }
    char location[512];
    sprintf(location, "https://%s%s", host, url);
    log_message(INFO, location);
    send_http_redirect(client_socket, ssl, location);
    return;
  }

  // 处理HTTPS请求
  if (file_exists) {
    char *range_header = strstr(buffer, "Range: bytes=");
    if (range_header) {
      send_http_partial_response(client_socket, ssl, file_path, range_header,
                                 &file_stat);
    } else {
      send_http_response(client_socket, ssl, 200, file_path);
    }
  } else {
    log_message(INFO, "Not found file");
    send_http_response(client_socket, ssl, 404, NULL);
  }
}

// void handle_request(int client_socket, SSL *ssl) {
//   char buffer[BUFFER_SIZE];
//   int bytes_read;
//
//   // Read the request
//   if (ssl) {
//     bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
//   } else {
//     bytes_read = read(client_socket, buffer, sizeof(buffer));
//   }
//   buffer[bytes_read] = '\0';
//
//   // Extract the Method and Url
//   char method[255];
//   char url[255];
//   sscanf(buffer, "%s %s", method, url);
//
//   char response_header[BUFFER_SIZE];
//   char response_body[BUFFER_SIZE];
//
//   if (strcmp(method, "GET") == 0) {
//     if (ssl == NULL) {
//       // For requests on port 80, return 301 Moved Permanently and express
//       the
//       // corresponding HTTPS URL in the Location field of the response.
//       sprintf(response_header,
//               "HTTP/1.1 301 Moved Permanently\r\nLocation: "
//               "https://your_domain.com%s\r\n\r\n",
//               url);
//       strcpy(response_body, "");
//     } else {
//       // For Https
//       char *file_path = get_file_path(url);
//       if (file_exists(file_path)) {
//         if (has_range_field(buffer)) {
//           // If the requested content is partial (there is a Range field in
//           the
//           // request), return 206 Partial Content and the corresponding
//           partial
//           // content.
//           strcpy(response_header, "HTTP/1.1 206 Partial "
//                                   "Content\r\nContent-Type:
//                                   text/html\r\n\r\n");
//           get_partial_content(file_path, response_body, buffer);
//         } else {
//           // If the file requested exists in the program's folder, return the
//           // 200 OK status code and the requested file.
//           strcpy(response_header,
//                  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n");
//           get_file_content(file_path, response_body);
//         }
//       } else {
//         // If the file requested does not exist in the program's folder,
//         return
//         // the 404 Not Found status code.
//         strcpy(response_header,
//                "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n");
//         strcpy(response_body,
//                "<html><body><h1>404 Not Found</h1></body></html>");
//       }
//     }
//   }
//
//   if (ssl) {
//     SSL_write(ssl, response_header, strlen(response_header));
//     SSL_write(ssl, response_body, strlen(response_body));
//   } else {
//     write(client_socket, response_header, strlen(response_header));
//     write(client_socket, response_body, strlen(response_body));
//   }
// }

void *connection_handler(void *data) {
  int client_socket = *((int *)data);
  handle_request(client_socket, NULL);
  close(client_socket);
  free(data);
  return NULL;
}

void start_server(int port, SSL_CTX *ctx) {
  int server_fd, *client_socket;
  struct sockaddr_in address;
  int addrlen = sizeof(address);
  pthread_t thread_id;

  // Create socket
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    perror("Socket failed");
    exit(EXIT_FAILURE);
  }

  // Define address and port
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(port);

  // Bind socket
  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("Bind failed");
    exit(EXIT_FAILURE);
  }

  // Listen on socket
  if (listen(server_fd, 10) < 0) {
    perror("Listen failed");
    exit(EXIT_FAILURE);
  }

  while (1) {
    client_socket = malloc(sizeof(int));
    *client_socket =
        accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);

    if (port == HTTPS_PORT) {
      SSL *ssl = get_new_ssl(ctx);
      if (!ssl) {
        log_message(ERROR, "Failed to create SSL structure");
        ERR_print_errors_fp(stderr);
        // 处理错误，例如关闭socket，清理资源等
        exit(EXIT_FAILURE);
      }
      if (SSL_set_fd(ssl, *client_socket) == 0) {
        log_message(ERROR, "Failed to set the file descriptor for SSL");
        // 处理错误
        exit(EXIT_FAILURE);
      }
      if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
      } else {
        handle_request(*client_socket, ssl);
      }
      SSL_free(ssl);
    } else {
      pthread_create(&thread_id, NULL, connection_handler, client_socket);
    }
  }

  close(server_fd);
}

int main() {
  SSL_CTX *ctx;

  log_message(INFO, "Server starting...");
  init_openssl();

  pthread_t thread_id_http, thread_id_https;

  // Start HTTP server
  pthread_create(&thread_id_http, NULL, (void *)start_server,
                 (void *)HTTP_PORT);

  // Start HTTPS server
  pthread_create(&thread_id_https, NULL, (void *)start_server,
                 (void *)HTTPS_PORT);

  pthread_join(thread_id_http, NULL);
  pthread_join(thread_id_https, NULL);

  // SSL_CTX_free(ctx);
  // cleanup_openssl();

  log_message(INFO, "Server stopping...");
  return 0;
}
