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

#define BUF_SIZE 8192

#define DEFAULT_LOCAL_PORT    8080
#define DEFAULT_REMOTE_PORT   8081

#define READ  0
#define WRITE 1

#define MAX_HEADER_SIZE 8192

#define MAX_HEADER_VALUE_SIZE 2048

#define LOG(fmt...)  do {fprintf(stderr, ##fmt);} while(0)

#define SSL_CONNECTION_RESPONSE "HTTP/1.0 200 Connection established"

#define PROXY_AUTHENTICATION_REQUIRED_RESPONSE "HTTP/1.0 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"\""

#define PROXY_UNAUTHORIZED_RESPONSE "HTTP/1.0 401 Unauthorized"

#define WWW_UNAUTHORIZED_RESPONSE "HTTP/1.0 401 Unauthorized\r\nWww-Authenticate: Basic realm=\"Restricted\""

/**
 *
 * Base64 encode start
 *
 */
#include <stddef.h>
/* calculates number of bytes base64-encoded stream of N bytes will take. */
#define BASE64ENC_BYTES(N) (((N+2)/3)*4)
void base64enc(char *dst, const void* src, size_t count);

static const char base64_tbl[64] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
   rofl0r's base64 impl (taken from libulz)
   takes count bytes from src, writing base64 encoded string into dst.
   dst needs to be at least BASE64ENC_BYTES(count) + 1 bytes in size.
   the string in dst will be zero-terminated.
   */
void base64enc(char *dst, const void* src, size_t count)
{
	unsigned const char *s = src;
	char* d = dst;
	while(count) {
		int i = 0,  n = *s << 16;
		s++;
		count--;
		if(count) {
			n |= *s << 8;
			s++;
			count--;
			i++;
		}
		if(count) {
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

int reverse_server;
char remote_host[128];
int remote_port;
int local_port;

int server_sock;
int client_sock;
int remote_sock;

char * header_buffer;
char * base64_auth_string;


// Proxy回环等待客户端的连接请求
void server_loop();

// Proxy处理客户端发起的连接请求
void handle_client(int client_sock, struct sockaddr_in client_addr);

// Proxy通过destination_sock转发HTTP头部
void forward_header(int destination_sock);

// Proxy从source_sock接收数据，并把接收到的数据转发到destination_sock上
void forward_data(int source_sock, int destination_sock);

// 重写HTTP头部
void rewrite_header();

// 重写代理路径
void rewrite_proxy_path();

// 创建proxy与服务器的连接
int create_connection();
int create_server_socket(int port);

// Read HTTP Header
int read_header(int fd, void * buffer);

// 读取套接字中的数据流
int readLine(int fd, void *buffer, int n);

// 读取header
int get_header(const char *header, char *name, char *value);

// 去掉header
int strip_header(char *name);

// 设置远程服务器
void set_remote_server(char *server);

// 读取一行
int readLine(int fd, void *buffer, int n)
{
    int numRead;
    int totRead;
    char *buf;
    char ch;

    if (n <= 0 || buffer == NULL) {
        errno = EINVAL;
        return -1;
    }

    buf = buffer;

    totRead = 0;
    for (;;) {
        numRead = recv(fd, &ch, 1, 0);

        if (numRead == -1) {
            if (errno == EINTR)
                continue;
            else
                return -1;              /* 未知错误 */

        } else if (numRead == 0) {      /* EOF */
            if (totRead == 0)           /* No bytes read; return 0 */
                return 0;
            else                        /* Some bytes read; add '\0' */
                break;

        } else {

            if (totRead < n - 1) {      /* Discard > (n - 1) bytes */
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
    memset(header_buffer,0,MAX_HEADER_SIZE);
    char line_buffer[2048];
    char * base_ptr = header_buffer;

    for(;;)
    {
        memset(line_buffer,0,2048);

        int total_read = readLine(fd, line_buffer, 2048);
        if(total_read <= 0)
        {
            return -1;
        }

        //防止header缓冲区越界
        if(base_ptr + total_read - header_buffer <= MAX_HEADER_SIZE)
        {
           strncpy(base_ptr,line_buffer,total_read);
           base_ptr += total_read;
        } else
        {
            return -1;
        }

        //读到了空行，http头结束
        if(strcmp(line_buffer,"\r\n") == 0 || strcmp(line_buffer,"\n") == 0)
        {
            break;
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
    if (!p) {
        return -1;
    }
    char *p1 = strchr(p,'\n');
    if(!p1)
    {
        return -1;
    }
    int h_l = (int)strlen(h_name);
    int v_len = (int)(p1 - p - h_l -1 -1);
    strncpy(value, p + h_l + 1, v_len);
    return 0;
}

// 去掉header
int strip_header(char *name)
{
    char h_name[strlen(name) + 1];
    sprintf(h_name, "%s:", name);
    char *p = strstr(header_buffer, h_name);
    if (!p) {
        return -1;
    }
    char *p1 = strchr(p, '\n');
    if(!p1)
    {
        return -1;
    }
    p1 = p1+1;
    char * p0 = strchr(p, '\0');
    int len = strlen(header_buffer);
    memcpy(p, p1, (int)(p0 -p1));
    int l = len - (p1 - p) ;
    header_buffer[l] = '\0';
    return 0;
}

// 设置header
int set_header(char *name, char *value)
{
    char h_name[strlen(name) + 1];
    sprintf(h_name, "%s:", name);
    char *p = strstr(header_buffer, h_name);
    if (!p) {
        return -1;
    }
    char *p1 = strchr(p, '\n');
    if(!p1)
    {
        return -1;
    }
    p1 = p1+1;
    char * p0 = strchr(p, '\0');
    char *temp = (char *) malloc(MAX_HEADER_SIZE);
    // 保存当前header(name)末尾到 header_buffer 末尾
    memcpy(temp, p1, (int)(p0 -p1));
    // 插入新header
    char header[strlen(name) + strlen(value) + 1 + 1 + 1 + 1]; // 三个字符 : \n + 结尾符号\0
    sprintf(header, "%s: %s\n", name, value);
    memcpy(p, header, strlen(header));
    // 插入原剩余header
    memcpy(p + strlen(header), temp, strlen(temp));
    int len = strlen(header_buffer);
    int l = len - (p1 - p) + strlen(header);
    header_buffer[l] = '\0';
    return 0;
}

// 设置远程服务器
void set_remote_server(char *server)
{
    char *p_mid = strchr(server, ':');
    if (p_mid) {
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
    } else {
        // 默认80端口
        strncpy(remote_host, server, strlen(server));
        remote_host[strlen(server) + 1] = '\0';
        remote_port=80;
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

    if(read_header(client_sock, header_buffer) < 0)
    {
        LOG("Read Http header failed : Request from client: [%s:%d]\n", client_ip, client_port);
        return;
    }

    if(strlen(remote_host) == 0) // 未指定远端主机名称从 http 请求 HOST 字段中获取
    {
        char * hoststring = (char *) malloc(MAX_HEADER_VALUE_SIZE);
        if(get_header(header_buffer, "Host", hoststring) < 0)
        {
            LOG("Cannot extract host field : Request from client: [%s:%d]\n", client_ip, client_port);
            return;
        }
        set_remote_server(hoststring);
    }

    if (base64_auth_string)
    {
        if (!reverse_server) {
            char * authstring = (char *) malloc(MAX_HEADER_VALUE_SIZE);
            if (get_header(header_buffer, "Proxy-Authorization", authstring) < 0)
            {
                LOG("Proxy auth required\n");
                // 发送407代理需要鉴权消息
                char * auth_response = (char *) malloc(200);
                sprintf(auth_response, "%s\r\n\r\n", PROXY_AUTHENTICATION_REQUIRED_RESPONSE);
                send(client_sock, auth_response, strlen(auth_response), 0);
                return;
            }
            // LOG("Detected Proxy-Authorization: %s\n", authstring);
            /* currently only "basic" auth supported */
            int auth_failure = 1;
            if ((strncmp(authstring, "Basic ", 6) == 0 || strncmp(authstring, "basic ", 6) == 0) &&
                            strcmp(base64_auth_string, authstring + 6) == 0)
            {
                auth_failure = 0;
            }
            if(auth_failure) {
                LOG("Proxy auth error with header Proxy-Authorization: %s \n", authstring);
                // 发送401代理鉴权失败消息
                char * auth_response = (char *) malloc(200);
                sprintf(auth_response, "%s\r\n\r\n", PROXY_UNAUTHORIZED_RESPONSE);
                send(client_sock, auth_response, strlen(auth_response), 0);
                return;
            }
        } else {
            // 反向代理
            char * authstring = (char *) malloc(MAX_HEADER_VALUE_SIZE);
            if (get_header(header_buffer, "Authorization", authstring) < 0)
            {
                LOG("WWW-Authorization required\n");
                // 发送401未授权消息
                char * auth_response = (char *) malloc(200);
                sprintf(auth_response, "%s\r\n\r\n", WWW_UNAUTHORIZED_RESPONSE);
                send(client_sock, auth_response, strlen(auth_response), 0);
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
            if(auth_failure) {
                LOG("Proxy auth error\n");
                // 发送401未授权消息
                char * auth_response = (char *) malloc(200);
                sprintf(auth_response, "%s\r\n\r\n", WWW_UNAUTHORIZED_RESPONSE);
                send(client_sock, auth_response, strlen(auth_response), 0);
                return;
            }
        }
    }

    if ((remote_sock = create_connection()) < 0) {
        LOG("Proxy cannot connect to host [%s:%d]\n",remote_host,remote_port);
        return;
    }

    LOG("Connected to remote host: [%s:%d]\n", remote_host, remote_port);

    char * is_connect = strstr(header_buffer, "CONNECT ");

    if (fork() == 0) { // 创建子进程用于从客户端转发数据到远端socket接口
        if (strlen(header_buffer) > 0 && !is_connect)
        {
            forward_header(remote_sock); // 转发HTTP Header
        }

        LOG("Transfer data [%s:%d]-->[%s:%d]\n", client_ip, client_port, remote_host, remote_port);
        forward_data(client_sock, remote_sock);
        exit(0);
    }

    if (fork() == 0) { // 创建子进程用于转发从远端socket接口过来的数据到客户端

        LOG("Transfer data [%s:%d]-->[%s:%d]\n", remote_host, remote_port, client_ip, client_port);
        forward_data(remote_sock, client_sock);
        exit(0);
    }

    if (is_connect) {
        // 等待子进程开始监听转发
        usleep(10);
        // 发送 connect 成功消息
        char * connect_response = (char *) malloc(200);
        sprintf(connect_response, "%s\r\n\r\n", SSL_CONNECTION_RESPONSE);
        send(client_sock, connect_response, strlen(connect_response), 0);
    }

    LOG("Close sock:  Proxy <===> [%s:%d] \n", client_ip, client_port);
    close(client_sock);
    LOG("Close sock:  Proxy <===> [%s:%d] \n", remote_host, remote_port);
    close(remote_sock);
}

// 转发HTTP Header
void forward_header(int destination_sock)
{
    rewrite_header();
    strip_header("Proxy-Authorization");
    strip_header("Keep-Alive");
    strip_header("Proxy-Authenticate");
    strip_header("Proxy-Connection");
    // LOG("rewrite_header:\n %s\n", header_buffer);
    int len = strlen(header_buffer);
    send(destination_sock, header_buffer, len, 0) ;
}

// 重写请求头
void rewrite_header()
{
    rewrite_proxy_path();
    if (reverse_server) {
        set_header("Host", remote_host);
    }
}

// 重写代理路径 代理中的完整URL转发前需改成path的形式
void rewrite_proxy_path()
{
    char * p = strstr(header_buffer, "http://");
    char * p5 = strstr(header_buffer, "HTTP/"); // "HTTP/" 是协议标识 如 "HTTP/1.1"
    int len = strlen(header_buffer);
    if(p)
    {
        char * p0 = strchr(p, '\0');
        char * p1 = strchr(p + 7,'/');
        if(p1 && (p5 > p1))
        {
            //转换url到 path
            memcpy(p,p1,(int)(p0 -p1));
            int l = len - (p1 - p) ;
            header_buffer[l] = '\0';

        } else
        {
            char * p2 = strchr(p,' ');  //GET http://3g.sina.com.cn HTTP/1.1

            memcpy(p + 1, p2, (int)(p0-p2));
            *p = '/';  //url 没有路径使用根
            int l  = len - (p2  - p ) + 1;
            header_buffer[l] = '\0';

        }
    }
}

// 转发数据
void forward_data(int source_sock, int destination_sock) {
    char buffer[BUF_SIZE];
    int n;

    while ((n = recv(source_sock, buffer, BUF_SIZE, 0)) > 0)
    {
        send(destination_sock, buffer, n, 0);
    }
}

// 连接远程服务器
int create_connection() {
    struct sockaddr_in server_addr;
    struct hostent *server;
    int sock;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return -1;
    }

    if ((server = gethostbyname(remote_host)) == NULL) {
        errno = EFAULT;
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    server_addr.sin_port = htons(remote_port);

    LOG("Connect to remote host: [%s:%d]\n",remote_host,remote_port);
    if (connect(sock, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        return -1;
    }

    return sock;
}

// 监听端口
int create_server_socket(int port) {
    int server_sock;
    struct sockaddr_in server_addr;

    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return -1;
    }

    int reuseaddr = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(int));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
        return -1;
    }

    if (listen(server_sock, 20) < 0) {
        return -1;
    }

    return server_sock;
}

// 接收请求
void server_loop() {
    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);

    while (1) {
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addrlen);

        char *client_ip;
        int client_port;

        client_ip = inet_ntoa(client_addr.sin_addr);
        client_port = client_addr.sin_port;

        LOG("Accepted connect from client: [%s:%d]\n", client_ip, client_port);

        if (fork() == 0) { // 创建子进程处理客户端连接请求
            close(server_sock);
            handle_client(client_sock, client_addr);
            exit(0);
        }
        close(client_sock);
    }

}

// 启动监听服务
void start_server()
{
    //初始化全局变量
    header_buffer = (char *) malloc(MAX_HEADER_SIZE);

    if ((server_sock = create_server_socket(local_port)) < 0)
    {
        LOG("Cannot run server on port %d\n",local_port);
        exit(-1);
    }

    server_loop();
}

// Usage
void usage(void)
{
    printf("Usage:\n");
    printf("\t-h : Print usage \n");
    printf("\t-p <port number> : Specifyed local listen port \n");
    printf("\t-u <user:pass> : Specifyed basic authorization of proxy \n");
    printf("\t-r <remote_host:remote_port> : Specifyed remote host and port of reverse proxy. Only support http service now. \n");
    exit(0);
}

// main
int main(int argc, char *argv[])
{
    local_port = DEFAULT_LOCAL_PORT;

	int opt;
	char optstrs[] = "p:u:r:h";

	while((opt = getopt(argc, argv, optstrs)) != -1)
	{
		switch(opt)
		{
			case 'p':
				local_port = atoi(optarg);
				break;
            case 'u':
                base64_auth_string = (char *) malloc(1024);
                base64enc(base64_auth_string, optarg, strlen(optarg));
                // printf("\nBase64 of auth %s(size %lu) is: %s(size %lu)\n", optarg, strlen(optarg), base64_auth_string, strlen(base64_auth_string));
				break;
            case 'h':
                usage();
                break;
            case 'r':
                set_remote_server(optarg);
                reverse_server=1;
                LOG("Reverse proxy remote server %s:%d\n", remote_host, remote_port);
                break;
			case '?':
				printf("\nInvalid argument: %c\n", optopt);
			default:
				usage();
		}
    }

    LOG("Proxy server start on port : %d\n", local_port);
    start_server();
    return 0;
}
