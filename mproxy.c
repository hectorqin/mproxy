#include <arpa/inet.h>
#include <errno.h>
#include <libgen.h>
#include <netdb.h>
#include <resolv.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <string.h>

#define DEBUG 1
// #define ENCRYPTION_DEBUG 0

#define DEFAULT_LOCAL_PORT 8080

// size
#define BUF_SIZE 8192
#define MAX_HEADER_SIZE 65536
#define MAX_HEADER_LINE_SIZE 8192
#define MAX_HEADER_VALUE_SIZE 8192
#define MAX_AUTH_STRING_SIZE 128

// error
#define SERVER_SOCKET_ERROR -1
#define SERVER_SETSOCKOPT_ERROR -2
#define SERVER_BIND_ERROR -3
#define SERVER_LISTEN_ERROR -4
#define CLIENT_SOCKET_ERROR -5
#define CLIENT_RESOLVE_ERROR -6
#define CLIENT_CONNECT_ERROR -7
#define CREATE_PIPE_ERROR -8
#define BROKEN_PIPE_ERROR -9
#define HEADER_BUFFER_FULL -10
#define BAD_HTTP_PROTOCOL -11

#if defined(OS_ANDROID)
#include <android/log.h>
#define LOG(fmt...) __android_log_print(ANDROID_LOG_DEBUG,__FILE__,##fmt)
#else
#define LOG(fmt...)             \
    do                          \
    {                           \
        fprintf(stderr,"[%s %s] ",__DATE__,__TIME__); \
        fprintf(stderr, ##fmt); \
    } while (0)
#endif

// response
#define SSL_CONNECTION_RESPONSE "HTTP/1.0 200 Connection established\r\n\r\n"
#define PROXY_AUTHENTICATION_REQUIRED_RESPONSE "HTTP/1.0 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"\"\r\n\r\n"
#define PROXY_UNAUTHORIZED_RESPONSE "HTTP/1.0 401 Unauthorized\r\n\r\n"
#define WWW_UNAUTHORIZED_RESPONSE "HTTP/1.0 401 Unauthorized\r\nWww-Authenticate: Basic realm=\"Restricted\"\r\n\r\n"

/**
 *
 * Base64 encode start
 *
 */
#include <stddef.h>
/* calculates number of bytes base64-encoded stream of N bytes will take. */
#define BASE64ENC_BYTES(N) (((N + 2) / 3) * 4)
void base64enc(char *dst, const void *src, size_t count);

static const char base64_tbl[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
   rofl0r's base64 impl (taken from libulz)
   takes count bytes from src, writing base64 encoded string into dst.
   dst needs to be at least BASE64ENC_BYTES(count) + 1 bytes in size.
   the string in dst will be zero-terminated.
   */
void base64enc(char *dst, const void *src, size_t count)
{
    unsigned const char *s = src;
    char *d = dst;
    while (count)
    {
        int i = 0, n = *s << 16;
        s++;
        count--;
        if (count)
        {
            n |= *s << 8;
            s++;
            count--;
            i++;
        }
        if (count)
        {
            n |= *s;
            s++;
            count--;
            i++;
        }
        *d++ = base64_tbl[(n >> 18) & 0x3f];
        *d++ = base64_tbl[(n >> 12) & 0x3f];
        *d++ = i ? base64_tbl[(n >> 6) & 0x3f] : '=';
        *d++ = i == 2 ? base64_tbl[n & 0x3f] : '=';
    }
    *d = 0;
}
/**
 *
 * Base64 encode End
 *
 */

char remote_host[128];
int remote_port;
int local_port;

// sock
int server_sock;
int client_sock;
int remote_sock;

// 是否 CONNECT 请求
int is_http_tunnel = 0;

// 是否严格Host模式
int is_strict_host = 0;

// 是否反向代理模式
int is_reverse_server = 0;
// 是否转发上游代理
int is_forward_upstream_proxy = 0;

// 主进程pid
int master_pid;

// 请求头
char *header_buffer;
// 代理鉴权
char *base64_auth_string;
// 上游代理鉴权字符串(包含Basic 字符串)
char *upstream_base64_auth_string;

enum
{
    FLG_NONE = 0, /* 正常数据流不进行编解码 */
    R_C_DEC = 1,  /* 读取客户端数据仅进行解码 */
    W_S_ENC = 2   /* 发送到服务端进行编码 */
};

static int io_flag; /* 网络io的一些标志位 */

// Proxy回环等待客户端的连接请求
void server_loop();

// Proxy处理客户端发起的连接请求
void handle_client(int client_sock, struct sockaddr_in client_addr);

// Proxy通过destination_sock转发HTTP头部
void forward_header(int destination_sock);

// Proxy从source_sock接收数据，并把接收到的数据转发到destination_sock上
int forward_data(int source_sock, int destination_sock);

// 重写HTTP头部
void rewrite_header();

// 重写代理路径
void rewrite_proxy_path();

// 响应隧道连接请求
int send_tunnel_ok(int client_sock);

// 发送数据
int send_data(int socket, char *buffer, int len);

// 接收数据
int receive_data(int socket, char *buffer, int len);

// 创建proxy与服务器的连接
int create_connection();
int create_server_socket(int port);

// Read HTTP Header
int read_header(int fd, void *buffer);

// 读取套接字中的数据流
int readLine(int fd, void *buffer, int n);

// 读取header
int get_header(const char *header, char *name, char *value);

// 去掉header
int strip_header(char *name);

// 设置header
int set_header(char *name, char *value);

// 添加header
int add_header(char *name, char *value);

// 设置远程服务器
void set_remote_server(char *server);

// 读取一行
int readLine(int fd, void *buffer, int n)
{
    int numRead;
    int totRead;
    char *buf;
    char ch;

    if (n <= 0 || buffer == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    buf = buffer;

    totRead = 0;
    for (;;)
    {
        numRead = receive_data(fd, &ch, 1);

        if (numRead == -1)
        {
            if (errno == EINTR)
                continue;
            else
                return -1; /* 未知错误 */
        }
        else if (numRead == 0)
        {                     /* EOF */
            if (totRead == 0) /* No bytes read; return 0 */
                return 0;
            else /* Some bytes read; add '\0' */
                break;
        }
        else
        {

            if (totRead < n - 1)
            { /* Discard > (n - 1) bytes */
                totRead++;
                *buf++ = ch;
            }

            if (ch == '\n')
                break;
        }
    }

    *buf = '\0';
    return totRead;
}

// Read HTTP Header
int read_header(int fd, void *buffer)
{
    memset(header_buffer, 0, MAX_HEADER_SIZE);
    char line_buffer[MAX_HEADER_LINE_SIZE];
    char *base_ptr = header_buffer;

    for (;;)
    {
        memset(line_buffer, 0, MAX_HEADER_LINE_SIZE);

        int total_read = readLine(fd, line_buffer, MAX_HEADER_LINE_SIZE);
        if (total_read <= 0)
        {
            return CLIENT_SOCKET_ERROR;
        }

        //防止header缓冲区越界
        if (base_ptr + total_read - header_buffer <= MAX_HEADER_SIZE)
        {
            strncpy(base_ptr, line_buffer, total_read);
            base_ptr += total_read;
        }
        else
        {
            return HEADER_BUFFER_FULL;
        }

        //读到了空行，http头结束
        if (strcmp(line_buffer, "\r\n") == 0 || strcmp(line_buffer, "\n") == 0)
        {
            break;
        }
    }
    return 0;
}

// 读取host数据
int get_host(const char *header, char *value)
{
    // 读取第一行header
    char *first_line = (char *)malloc(MAX_HEADER_LINE_SIZE);
    char *p = strchr(header, '\n');
    if (!p)
    {
        return BAD_HTTP_PROTOCOL;
    }
    int v_len = (int)(p - header - 1);
    strncpy(first_line, header, v_len);

    char *is_connect = strstr(first_line, "CONNECT ");
    if (is_connect)
    {
        char *p1 = strchr(first_line, ' ');
        char *p2 = strchr(p1 + 1, ' ');
        if (!p2)
        {
            return BAD_HTTP_PROTOCOL;
        }
        int h_len = (int)(p2 - p1 - 1);
        strncpy(value, p1 + 1, h_len);
    }
    else
    {
        char *p3 = strstr(first_line, "http://");
        if (!p3)
        {
            // http请求没有host路径
            return BAD_HTTP_PROTOCOL;
        }
        char *p4 = strstr(first_line, " HTTP/");
        int h_len = (int)(p4 - p3 - 7); // 减去http://的7个字符
        LOG("hear %d\n", h_len);
        strncpy(value, p3 + 7, h_len); // 赋值 host:port/path 给value
        LOG("hear %s\n", value);
        char *p5 = strstr(value, "/");
        if (p5)
        {
            // 有path，去掉path
            char *temp = (char *)malloc(MAX_HEADER_LINE_SIZE);
            h_len = (int)(p5 - value);
            LOG("hear %d\n", h_len);
            memcpy(temp, value, h_len);
            LOG("hear %s\n", temp);
            strncpy(value, temp, h_len);
            value[h_len] = '\0'; // 字符串缩短了，补上结尾符号
        }
    }

    return 0;
}

// 读取header数据
int get_header(const char *header, char *name, char *value)
{
    char h_name[strlen(name) + 1];
    sprintf(h_name, "%s:", name);
    char *p = strstr(header, h_name);
    if (!p)
    {
        return -1;
    }
    char *p1 = strchr(p, '\n');
    if (!p1)
    {
        return -1;
    }
    int h_l = (int)strlen(h_name);
    int v_len = (int)(p1 - p - h_l - 1 - 1);
    strncpy(value, p + h_l + 1, v_len);
    return 0;
}

// 去掉header
int strip_header(char *name)
{
    char h_name[strlen(name) + 1];
    sprintf(h_name, "%s:", name);
    char *p = strstr(header_buffer, h_name);
    if (!p)
    {
        return -1;
    }
    char *p1 = strchr(p, '\n');
    if (!p1)
    {
        return -1;
    }
    p1 = p1 + 1;
    char *p0 = strchr(p, '\0');
    int len = strlen(header_buffer);
    memcpy(p, p1, (int)(p0 - p1));
    int l = len - (p1 - p);
    header_buffer[l] = '\0';
    return 0;
}

// 设置header
int set_header(char *name, char *value)
{
    char h_name[strlen(name) + 1];
    sprintf(h_name, "%s:", name);
    char *p = strstr(header_buffer, h_name);
    if (!p)
    {
        return -1;
    }
    char *p1 = strchr(p, '\n');
    if (!p1)
    {
        return -1;
    }
    p1 = p1 + 1;
    char *p0 = strchr(p, '\0');
    char *temp = (char *)malloc(MAX_HEADER_SIZE);
    // 保存当前header(name)末尾到 header_buffer 末尾
    memcpy(temp, p1, (int)(p0 - p1));
    // 插入新header
    char header[strlen(name) + strlen(value) + 5]; // 5个字符 : \r\n + 结尾符号\0
    sprintf(header, "%s: %s\r\n", name, value);
    memcpy(p, header, strlen(header));
    // 插入原剩余header
    memcpy(p + strlen(header), temp, strlen(temp));
    int len = strlen(header_buffer);
    int l = len - (p1 - p) + strlen(header);
    header_buffer[l] = '\0';
    return 0;
}

// 设置header
int add_header(char *name, char *value)
{
    if (set_header(name, value) < 0)
    {
        char header[strlen(name) + strlen(value) + 8]; // 8个字符 \r\n : \r\n\r\n\0
        sprintf(header, "\r\n%s: %s\r\n\r\n", name, value);
        int i = strlen(header_buffer) - 1;
        while (header_buffer[i] == '\r' || header_buffer[i] == '\n')
        {
            i--;
        }
        header_buffer[i + 1] = '\0';
        LOG("header_buffer:\n%s\n", header_buffer);
        strcat(header_buffer, header);
        LOG("header_buffer:\n%s\n", header_buffer);
    }
    return 0;
}

// 设置远程服务器
void set_remote_server(char *server)
{
    char *p_mid = strchr(server, ':');
    if (p_mid)
    {
        char *p_end = strchr(server, '\0');
        // 已传入端口号
        int p_len = (int)(p_end - p_mid - 1);
        char s_port[p_len];
        strncpy(s_port, p_mid + 1, p_len);
        s_port[p_len] = '\0';
        remote_port = atoi(s_port);

        int h_len = (int)(p_mid - server);
        strncpy(remote_host, server, h_len);
        remote_host[h_len] = '\0';
    }
    else
    {
        // 默认80端口
        strncpy(remote_host, server, strlen(server));
        remote_host[strlen(server) + 1] = '\0';
        remote_port = 80;
    }
}

// 处理客户端的连接
void handle_client(int client_sock, struct sockaddr_in client_addr)
{
    char *client_ip;
    int client_port;

    client_ip = inet_ntoa(client_addr.sin_addr);
    client_port = client_addr.sin_port;

    LOG("Request arrived from client: [%s:%d]\n", client_ip, client_port);

    if (read_header(client_sock, header_buffer) < 0)
    {
        LOG("Read Http header failed : Request from client: [%s:%d]\n", client_ip, client_port);
        return;
    }

#ifdef DEBUG
    LOG("Received headers: \n%s\n", header_buffer);
#endif

    if (strlen(remote_host) == 0) // 未指定远端主机名称从 http 请求 HOST 字段中获取
    {
        char *hoststring = (char *)malloc(MAX_HEADER_VALUE_SIZE);
        if (get_host(header_buffer, hoststring) < 0)
        {
            if (is_strict_host)
            {
                LOG("Cannot extract host field : Request from client: [%s:%d]\n", client_ip, client_port);
                return;
            }
            if (get_header(header_buffer, "Host", hoststring) < 0)
            {
                LOG("Cannot extract host field : Request from client: [%s:%d]\n", client_ip, client_port);
                return;
            }
        }
#ifdef DEBUG
        LOG("Parsed hoststring: \n%s\n", hoststring);
#endif
        set_remote_server(hoststring);
    }

    if (base64_auth_string)
    {
        if (!is_reverse_server || is_forward_upstream_proxy)
        {
            char *authstring = (char *)malloc(MAX_HEADER_VALUE_SIZE);
            if (get_header(header_buffer, "Proxy-Authorization", authstring) < 0)
            {
                LOG("Proxy auth required\n");
                // 发送407代理需要鉴权消息
                if (io_flag == R_C_DEC)
                {
                    io_flag = W_S_ENC; // 接收客户端请求进行解码，那么响应客户端请求需要编码
                }
                else
                {
                    io_flag = FLG_NONE; // 否则响应客户端请求不编码
                }
                send_data(client_sock, PROXY_AUTHENTICATION_REQUIRED_RESPONSE, strlen(PROXY_AUTHENTICATION_REQUIRED_RESPONSE));
                return;
            }
#ifdef DEBUG
            LOG("Detected Proxy-Authorization: %s\n", authstring);
#endif
            /* currently only "basic" auth supported */
            int auth_failure = 1;
            if ((strncmp(authstring, "Basic ", 6) == 0 || strncmp(authstring, "basic ", 6) == 0) &&
                strcmp(base64_auth_string, authstring + 6) == 0)
            {
                auth_failure = 0;
            }
            if (auth_failure)
            {
                LOG("Proxy auth error with header Proxy-Authorization: %s \n", authstring);
                // 发送401代理鉴权失败消息
                if (io_flag == R_C_DEC)
                {
                    io_flag = W_S_ENC; // 接收客户端请求进行解码，那么响应客户端请求需要编码
                }
                else
                {
                    io_flag = FLG_NONE; // 否则响应客户端请求不编码
                }
                send_data(client_sock, PROXY_UNAUTHORIZED_RESPONSE, strlen(PROXY_UNAUTHORIZED_RESPONSE));
                return;
            }
        }
        else
        {
            // 反向代理
            char *authstring = (char *)malloc(MAX_HEADER_VALUE_SIZE);
            if (get_header(header_buffer, "Authorization", authstring) < 0)
            {
                LOG("WWW-Authorization required\n");
                // 发送401未授权消息
                send_data(client_sock, WWW_UNAUTHORIZED_RESPONSE, strlen(WWW_UNAUTHORIZED_RESPONSE));
                return;
            }
            LOG("Detected Authorization: %s\n", authstring);
            /* currently only "basic" auth supported */
            int auth_failure = 1;
            if ((strncmp(authstring, "Basic ", 6) == 0 || strncmp(authstring, "basic ", 6) == 0) &&
                strcmp(base64_auth_string, authstring + 6) == 0)
            {
                auth_failure = 0;
            }
            if (auth_failure)
            {
                LOG("WWW-Authorization error\n");
                // 发送401未授权消息
                send_data(client_sock, WWW_UNAUTHORIZED_RESPONSE, strlen(WWW_UNAUTHORIZED_RESPONSE));
                return;
            }
        }
    }

    if ((remote_sock = create_connection()) < 0)
    {
        LOG("Proxy cannot connect to host [%s:%d]\n", remote_host, remote_port);
        return;
    }

    if (is_forward_upstream_proxy)
    {
        LOG("Connected to remote host(upstream proxy): [%s:%d]\n", remote_host, remote_port);
    }
    else if (is_reverse_server)
    {
        LOG("Connected to remote host(reverse proxy): [%s:%d]\n", remote_host, remote_port);
    }
    else
    {
        LOG("Connected to remote host: [%s:%d]\n", remote_host, remote_port);
    }

    char *mp = strstr(header_buffer, "CONNECT ");
    if (mp)
    {
        is_http_tunnel = 1;
    }

    if (fork() == 0)
    { // 创建子进程用于从客户端转发数据到远端socket接口
        if (strlen(header_buffer) > 0 && (!is_http_tunnel || is_forward_upstream_proxy))
        {
            forward_header(remote_sock); // 转发HTTP Header
        }

        LOG("Transfer data start [%s:%d]-->[%s:%d]\n", client_ip, client_port, remote_host, remote_port);
        int b = forward_data(client_sock, remote_sock);
        LOG("Transfer data end [%s:%d]-->[%s:%d] [total: %d bytes]\n", client_ip, client_port, remote_host, remote_port, b);
        exit(0);
    }

    if (fork() == 0)
    { // 创建子进程用于转发从远端socket接口过来的数据到客户端
        if (io_flag == W_S_ENC)
        {
            io_flag = R_C_DEC; //发送请求给服务端进行编码，读取服务端的响应则进行解码
        }
        else if (io_flag == R_C_DEC)
        {
            io_flag = W_S_ENC; //接收客户端请求进行解码，那么响应客户端请求需要编码
        }
        if (is_http_tunnel && !is_forward_upstream_proxy)
        {
            // 等待子进程开始监听转发
            usleep(10);
            send_tunnel_ok(client_sock);
        }
        LOG("Transfer data start [%s:%d]-->[%s:%d]\n", remote_host, remote_port, client_ip, client_port);
        int b = forward_data(remote_sock, client_sock);
        LOG("Transfer data end [%s:%d]-->[%s:%d] [total: %d bytes]\n", remote_host, remote_port, client_ip, client_port, b);
        exit(0);
    }
    close(client_sock);
    close(remote_sock);
}

// 响应隧道连接请求
int send_tunnel_ok(int client_sock)
{
    char *resp = SSL_CONNECTION_RESPONSE;
    int len = strlen(resp);
    char buffer[len + 1];
    strcpy(buffer, resp);
    if (send_data(client_sock, buffer, len) < 0)
    {
        perror("Send http tunnel response failed\n");
        return -1;
    }
    return 0;
}

// 发送数据
int send_data(int socket, char *buffer, int len)
{
#ifdef ENCRYPTION_DEBUG
    LOG("Before Encode:\n %s\n", buffer);
#endif
    if (io_flag == W_S_ENC)
    {
        int i;
        for (i = 0; i < len; i++)
        {
            buffer[i] ^= 1;
        }
    }
#ifdef ENCRYPTION_DEBUG
    LOG("After Encode:\n %s\n", buffer);
#endif
    return send(socket, buffer, len, 0);
}

int receive_data(int socket, char *buffer, int len)
{
    int n = recv(socket, buffer, len, 0);
#ifdef ENCRYPTION_DEBUG
    LOG("Before Decode:\n %s\n", buffer);
#endif
    if (io_flag == R_C_DEC && n > 0)
    {
        int i;
        for (i = 0; i < n; i++)
        {
            buffer[i] ^= 1;
            // printf("%d => %d\n",c,buffer[i]);
        }
    }
#ifdef ENCRYPTION_DEBUG
    LOG("After Decode:\n %s\n", buffer);
#endif
    return n;
}

// 转发HTTP Header
void forward_header(int destination_sock)
{
    rewrite_header();
#ifdef DEBUG
    LOG("Rewrited header: \n%s\n", header_buffer);
#endif
    send_data(destination_sock, header_buffer, strlen(header_buffer));
}

// 重写请求头
void rewrite_header()
{
    if (!is_http_tunnel && !is_forward_upstream_proxy)
    {
        // 普通http请求在非转发上游模式才重写代理路径
        rewrite_proxy_path();
    }
    if (is_forward_upstream_proxy && upstream_base64_auth_string)
    {
        add_header("Proxy-Authorization", upstream_base64_auth_string);
    }
    else
    {
        strip_header("Proxy-Authorization");
    }
    strip_header("Keep-Alive");
    strip_header("Proxy-Authenticate");
    strip_header("Proxy-Connection");

    if (is_reverse_server)
    {
        set_header("Host", remote_host);
    }
}

// 重写代理路径 代理中的完整URL转发前需改成path的形式
void rewrite_proxy_path()
{
    char *p = strstr(header_buffer, "http://");
    char *p5 = strstr(header_buffer, "HTTP/"); // "HTTP/" 是协议标识 如 "HTTP/1.1"
    int len = strlen(header_buffer);
    if (p)
    {
        char *p0 = strchr(p, '\0');
        char *p1 = strchr(p + 7, '/');
        if (p1 && (p5 > p1))
        {
            //转换url到 path
            memcpy(p, p1, (int)(p0 - p1));
            int l = len - (p1 - p);
            header_buffer[l] = '\0';
        }
        else
        {
            char *p2 = strchr(p, ' '); //GET http://3g.sina.com.cn HTTP/1.1

            memcpy(p + 1, p2, (int)(p0 - p2));
            *p = '/'; //url 没有路径使用根
            int l = len - (p2 - p) + 1;
            header_buffer[l] = '\0';
        }
    }
}

// 转发数据
int forward_data(int source_sock, int destination_sock)
{
    char buffer[BUF_SIZE];
    int n;
    int s = 0;

    while ((n = receive_data(source_sock, buffer, BUF_SIZE)) > 0)
    {
        send_data(destination_sock, buffer, n);
        s += n;
    }

    shutdown(destination_sock, SHUT_RDWR);
    shutdown(source_sock, SHUT_RDWR);
    return s;
}

// 连接远程服务器
int create_connection()
{
    struct sockaddr_in server_addr;
    struct hostent *server;
    int sock;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        return CLIENT_SOCKET_ERROR;
    }

    if ((server = gethostbyname(remote_host)) == NULL)
    {
        errno = EFAULT;
        return CLIENT_RESOLVE_ERROR;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    server_addr.sin_port = htons(remote_port);

    // LOG("Connect to remote host: [%s:%d]\n",remote_host,remote_port);
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        return CLIENT_CONNECT_ERROR;
    }

    return sock;
}

// 监听端口
int create_server_socket(int port)
{
    int server_sock, optval;
    struct sockaddr_in server_addr;

    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        return SERVER_SOCKET_ERROR;
    }

    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        return SERVER_SETSOCKOPT_ERROR;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0)
    {
        return SERVER_BIND_ERROR;
    }

    if (listen(server_sock, 20) < 0)
    {
        return SERVER_LISTEN_ERROR;
    }

    return server_sock;
}

// 接收请求
void server_loop()
{
    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);

    while (1)
    {
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addrlen);

        char *client_ip;
        int client_port;

        client_ip = inet_ntoa(client_addr.sin_addr);
        client_port = client_addr.sin_port;

        LOG("Accepted connect from client: [%s:%d]\n", client_ip, client_port);

        if (fork() == 0)
        { // 创建子进程处理客户端连接请求
            close(server_sock);
            handle_client(client_sock, client_addr);
            exit(0);
        }
        close(client_sock);
    }
}

/* 处理僵尸进程 */
void sigchld_handler(int signal)
{
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
}

// 启动监听服务
void start_server(int is_daemon)
{
    //初始化全局变量
    header_buffer = (char *)malloc(MAX_HEADER_SIZE);

    signal(SIGCHLD, sigchld_handler); // 防止子进程变成僵尸进程

    if ((server_sock = create_server_socket(local_port)) < 0)
    {
        LOG("Cannot run server on port %d\n", local_port);
        exit(-1);
    }

    if (is_daemon)
    {
        pid_t pid;
        if ((pid = fork()) == 0)
        {
            fclose(stderr);
            fclose(stdout);
            fclose(stdin);
            server_loop();
        }
        else if (pid > 0)
        {
            master_pid = pid;
            LOG("mporxy pid is: [%d]\n", pid);
            close(server_sock);
        }
        else
        {
            LOG("Cannot daemonize\n");
            exit(pid);
        }
    }
    else
    {
        server_loop();
    }
}

// Usage
void usage(void)
{
    printf("Usage:\n");
    printf("\t-p <port number> : Specifyed local listen port.\n");
    printf("\t-a <user:pass> : Specifyed basic authorization of proxy.\n");
    printf("\t-r <remote_host:remote_port> : Specifyed remote host and port of reverse proxy. Only support http service now.\n");
    printf("\t-f <remote_host:remote_port> : Specifyed remote host and port of upstream proxy.\n");
    printf("\t-A <user:pass> : Specifyed basic authorization of upstream proxy.\n");
    printf("\t-E : Encode data when forwarding data. Available in forwarding upstream proxy.\n");
    printf("\t-D : Decode data when receiving data. Available in forwarding upstream proxy.\n");
    printf("\t-s : Get remote host and port from first line strictly.\n");
    printf("\t-d : Run as daemon.\n");
    printf("\t-h : Print usage.\n");
    exit(0);
}

// main
int main(int argc, char *argv[])
{
    local_port = DEFAULT_LOCAL_PORT;
    io_flag = FLG_NONE;
    int daemon = 0;

    int opt;
    char optstrs[] = "p:a:r:f:A:EDsdh";

    while ((opt = getopt(argc, argv, optstrs)) != -1)
    {
        switch (opt)
        {
        case 'p':
            local_port = atoi(optarg);
            break;
        case 'a':
            if (MAX_AUTH_STRING_SIZE < (BASE64ENC_BYTES(strlen(optarg)) + 1))
            {
                printf("Authorization string is too long\n");
                usage();
            }
            base64_auth_string = (char *)malloc(MAX_AUTH_STRING_SIZE);
            base64enc(base64_auth_string, optarg, strlen(optarg));
#ifdef DEBUG
            LOG("\nBase64 of auth %s(size %lu) is: %s(size %lu)\n", optarg, strlen(optarg), base64_auth_string, strlen(base64_auth_string));
#endif
            break;
        case 'r':
        case 'f':
            set_remote_server(optarg);
            if (opt == 'r')
            {
                is_reverse_server = 1;
                LOG("Reverse proxy remote server %s:%d\n", remote_host, remote_port);
            }
            else
            {
                is_forward_upstream_proxy = 1;
                LOG("Upstream proxy remote server %s:%d\n", remote_host, remote_port);
            }
            break;
        case 'A':
            if (MAX_AUTH_STRING_SIZE < (BASE64ENC_BYTES(strlen(optarg)) + 1))
            {
                printf("Authorization string is too long\n");
                usage();
            }
            upstream_base64_auth_string = (char *)malloc(MAX_AUTH_STRING_SIZE);
            char *tmp = (char *)malloc(MAX_AUTH_STRING_SIZE);
            base64enc(tmp, optarg, strlen(optarg));
            sprintf(upstream_base64_auth_string, "Basic %s", tmp);
#ifdef DEBUG
            LOG("\nBase64 of auth %s(size %lu) is: %s(size %lu)\n", optarg, strlen(optarg), upstream_base64_auth_string, strlen(upstream_base64_auth_string));
#endif
            break;
        case 'E':
            io_flag = W_S_ENC;
            break;
        case 'D':
            io_flag = R_C_DEC;
            break;
        case 's':
            is_strict_host = 1;
            break;
        case 'd':
            daemon = 1;
            break;
        case '?':
			printf("\nInvalid argument: %c\n", optopt);
        case 'h':
        default:
            usage();
        }
    }

    if (is_reverse_server && io_flag != FLG_NONE)
    {
        printf("Reverse proxy server is not support encryption\n");
        usage();
    }

    LOG("Proxy server start on port : %d\n", local_port);
    start_server(daemon);
    return 0;
}
