#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdarg.h>

#define HTTP_PORT 80
#define HTTPS_PORT 443
#define BUFFER_SIZE 1024

// 日志颜色
#define LOG_COLOR_RED     "\x1b[31m"
#define LOG_COLOR_GREEN   "\x1b[32m"
#define LOG_COLOR_YELLOW  "\x1b[33m"
#define LOG_COLOR_BLUE    "\x1b[34m"
#define LOG_COLOR_RESET   "\x1b[0m"

// 日志级别
typedef enum { DEBUG, INFO, WARN, ERROR } LogLevel;

#define LOG_DEBUG 1

void log_message(LogLevel level, const char *format, ...) {
    #ifdef LOG_DEBUG
    const char *color;
    const char *level_strings[4] = {"DEBUG", "INFO", "WARN", "ERROR"};
    switch(level) {
        case DEBUG: color = LOG_COLOR_BLUE; break;
        case INFO:  color = LOG_COLOR_GREEN; break;
        case WARN:  color = LOG_COLOR_YELLOW; break;
        case ERROR: color = LOG_COLOR_RED; break;
        default: color = LOG_COLOR_RESET;
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
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    log_message(DEBUG, "OpenSSL initialized");
}

SSL_CTX *create_context() {
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
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    // Set the key and cert
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        log_message(ERROR, "Failed to load SSL certificate");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        log_message(ERROR, "Failed to load SSL private key");
        exit(EXIT_FAILURE);
    }

    log_message(DEBUG, "SSL context configured");
}

void handle_request(int client_socket, SSL *ssl) {
    char buffer[BUFFER_SIZE];
    int bytes_read;

    // Read the request
    if (ssl) {
        bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
    } else {
        bytes_read = read(client_socket, buffer, sizeof(buffer));
    }
    buffer[bytes_read] = '\0';

    // Simple response for demonstration
    char response_header[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    char response_body[] = "<html><body><h1>Hello, World!</h1></body></html>";

    if (ssl) {
        SSL_write(ssl, response_header, strlen(response_header));
        SSL_write(ssl, response_body, strlen(response_body));
    } else {
        write(client_socket, response_header, strlen(response_header));
        write(client_socket, response_body, strlen(response_body));
    }
}

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
        *client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);

        if (port == HTTPS_PORT) {
            SSL *ssl = SSL_new(ctx);
	    if (!ssl) {
	        log_message(ERROR, "Failed to create SSL structure");
	        // 处理错误，例如关闭socket，清理资源等
	    }
	    if (SSL_set_fd(ssl, client_socket) == 0) {
	        log_message(ERROR, "Failed to set the file descriptor for SSL");
	        // 处理错误
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
    ctx = create_context();
    configure_context(ctx);

    pthread_t thread_id_http, thread_id_https;

    // Start HTTP server
    pthread_create(&thread_id_http, NULL, (void *)start_server, (void *)HTTP_PORT);

    // Start HTTPS server
    pthread_create(&thread_id_https, NULL, (void *)start_server, (void *)HTTPS_PORT);

    pthread_join(thread_id_http, NULL);
    pthread_join(thread_id_https, NULL);

    SSL_CTX_free(ctx);
    //cleanup_openssl();

    log_message(INFO, "Server stopping...");
    return 0;
}

