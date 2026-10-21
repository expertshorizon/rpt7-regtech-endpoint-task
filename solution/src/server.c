#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "decode.h"
#include "refdata/refdata.h"
#include "serialize/json.h"

#define REQUEST_BUF_SIZE 8192
#define RESPONSE_BUF_SIZE 4096

static int read_request(int fd, char *buf, size_t buflen, size_t *body_start, long *content_length) {
    size_t total = 0;
    ssize_t n;
    *content_length = 0;
    *body_start = 0;
    char *header_end = NULL;

    while (total < buflen - 1) {
        n = recv(fd, buf + total, buflen - 1 - total, 0);
        if (n <= 0) break;
        total += (size_t)n;
        buf[total] = '\0';
        header_end = strstr(buf, "\r\n\r\n");
        if (header_end) break;
    }
    if (!header_end) return -1;

    *body_start = (size_t)(header_end - buf) + 4;

    const char *cl = strstr(buf, "Content-Length:");
    if (!cl) cl = strstr(buf, "content-length:");
    if (cl) {
        *content_length = strtol(cl + strlen("Content-Length:"), NULL, 10);
    }

    long needed = (long)(*body_start) + *content_length;
    while ((long)total < needed && total < buflen - 1) {
        n = recv(fd, buf + total, buflen - 1 - total, 0);
        if (n <= 0) break;
        total += (size_t)n;
        buf[total] = '\0';
    }
    return 0;
}

static void send_response(int fd, int status, const char *status_text, const char *body) {
    char header[512];
    int blen = (int)strlen(body);
    int hlen = snprintf(header, sizeof(header),
                         "HTTP/1.1 %d %s\r\n"
                         "Content-Type: application/json\r\n"
                         "Content-Length: %d\r\n"
                         "Connection: close\r\n"
                         "\r\n",
                         status, status_text, blen);
    send(fd, header, (size_t)hlen, 0);
    send(fd, body, (size_t)blen, 0);
}

static void handle_connection(int fd, const rpt7_refdata_t *ref) {
    char buf[REQUEST_BUF_SIZE];
    size_t body_start;
    long content_length;
    if (read_request(fd, buf, sizeof(buf), &body_start, &content_length) != 0) {
        send_response(fd, 400, "Bad Request", "{\"error\":\"malformed_request\"}");
        return;
    }

    char method[8] = {0};
    char path[256] = {0};
    sscanf(buf, "%7s %255s", method, path);

    if (strcmp(method, "GET") == 0 && strcmp(path, "/health") == 0) {
        send_response(fd, 200, "OK", "{\"status\":\"ok\"}");
        return;
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/decode") == 0) {
        char *body = buf + body_start;
        rpt7_decoded_t decoded;
        rpt7_decode(ref, body, &decoded);
        char response[RESPONSE_BUF_SIZE];
        rpt7_to_json(&decoded, response, sizeof(response));
        send_response(fd, decoded.ok ? 200 : 400, decoded.ok ? "OK" : "Bad Request", response);
        return;
    }

    send_response(fd, 404, "Not Found", "{\"error\":\"not_found\"}");
}

int main(int argc, char **argv) {
    const char *db_path = getenv("RPT7_DB_PATH");
    if (!db_path) db_path = "/app/data/rpt7.db";
    int port = 8080;
    if (getenv("RPT7_PORT")) port = atoi(getenv("RPT7_PORT"));
    if (argc > 1) port = atoi(argv[1]);

    rpt7_refdata_t ref;
    if (rpt7_load_refdata(db_path, &ref) != 0) {
        fprintf(stderr, "failed to load reference data from %s\n", db_path);
        return 1;
    }
    fprintf(stderr, "loaded %d issuers, %d rules from %s\n", ref.issuer_count, ref.rule_count,
            db_path);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(server_fd, 32) < 0) {
        perror("listen");
        return 1;
    }
    fprintf(stderr, "rpt7 service listening on port %d\n", port);

    for (;;) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) continue;
        handle_connection(client_fd, &ref);
        close(client_fd);
    }

    close(server_fd);
    return 0;
}
