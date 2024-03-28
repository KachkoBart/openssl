#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

#define port 44444
#define FAIL    -1


int OpenListener() {
    int sd;
    sd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        perror("can't bind port");
        abort();
    }
    if (listen(sd, 10) != 0) {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}

int OpenConnection() {
    int sd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(sd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        close(sd);
        abort();
    }
    return sd;
}

SSL_CTX *InitCTX(const SSL_METHOD *method) {
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

int isRoot() {
    if (getuid() != 0) {
        return 0;
    } else {
        return 1;
    }
}

void LoadCertificates(SSL_CTX *ctx, char *CertFile, char *KeyFile) {
    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void ShowCerts(SSL *ssl) {
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if (cert != NULL) {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    } else {
        printf("No certificates configured.\n");
    }
}

void Servlet(SSL *ssl) {
    char buf[1024] = {0};
    int sd, bytes;
    const char *ServerResponse = "Hello, Client, its encrypted answer";

    if (SSL_accept(ssl) == FAIL) {
        ERR_print_errors_fp(stderr);
    } else {
        ShowCerts(ssl);        /* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        buf[bytes] = '\0';
        printf("Client msg:\n\"%s\"\n", buf);
        if (bytes > 0) {
            SSL_write(ssl, ServerResponse, strlen(ServerResponse)); /* send reply */
        } else {
            ERR_print_errors_fp(stderr);
        }
    }
    sd = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sd);
}

void SSL_CTX_keylog_cb_func_cb(const SSL *ssl, const char *line) {
    FILE *fp;
    fp = fopen("sslkeylogfile.log", "a");
    if (fp == NULL) {
        printf("Failed to create log file\n");
    }
    fprintf(fp, "%s\n", line);
    fclose(fp);
}

int main() {
    printf("Choose:\n0-Server (print '0')\n1-Client (print '1')\n");
    int flag;
    if (scanf("%d", &flag) != 1 || flag < 0 || flag > 1) {
        printf("Incorrect input\n");
        exit(0);
    }

    SSL_CTX *ctx;
    int server;
    SSL_library_init();
    if (flag) {
        SSL *ssl;
        char buf[1024];
        char acClientRequest[1024] = {0};
        int bytes;

        ctx = InitCTX(TLS_client_method());
        server = OpenConnection();
        ssl = SSL_new(ctx);      /* create new SSL connection state */
        SSL_set_fd(ssl, server);    /* attach the socket descriptor */
        SSL_CTX_set_keylog_callback(ctx, SSL_CTX_keylog_cb_func_cb);

        if (SSL_connect(ssl) == FAIL)   /* perform the connection */
            ERR_print_errors_fp(stderr);
        else {
            const char *cpRequestMessage = "Hello, Server, its encrypted message.\nConnected with %s encryption";
            sprintf(acClientRequest, cpRequestMessage, SSL_get_cipher(ssl));   /* construct reply */
            printf("Information: Connected with %s encryption", SSL_get_cipher(ssl));

            ShowCerts(ssl);

            SSL_write(ssl, acClientRequest, strlen(acClientRequest));   /* encrypt & send message */
            bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */

            buf[bytes] = 0;
            printf("Received: \"%s\"\n", buf);
            SSL_free(ssl);
        }
        close(server);
        SSL_CTX_free(ctx);
    } else {
        if (!isRoot()) {
            printf("This program must be run as root/sudo user!!");
            exit(0);
        }

        ctx = InitCTX(TLS_server_method());
        LoadCertificates(ctx, "mycert.pem", "mycert.pem");
        server = OpenListener();

        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

        int client = accept(server, (struct sockaddr *) &addr, &len);
        printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
        Servlet(ssl);

        close(server);
        SSL_CTX_free(ctx);
    }
}