#include <stdio.h>
#include <string.h>


void *memcpy_fixed(void *dst, const void *src, size_t size)
{
    char *psrc;
    char *pdst;

    if(NULL == dst || NULL == src)
    {
        return NULL;
    }

    if((src < dst) && (char *)src + size > (char *)dst) // 自后向前拷贝
    {
        psrc = (char *)src + size - 1;
        pdst = (char *)dst + size - 1;
        while(size--)
        {
            *pdst-- = *psrc--;
        }
    }
    else
    {
        psrc = (char *)src;
        pdst = (char *)dst;
        while(size--)
        {
            *pdst++ = *psrc++;
        }
    }

    return dst;
}

void rewrite_proxy_path(char *buffer)
{
    char *p = strstr(buffer, "http://");
    fprintf(stderr, "p:  %ld\n%s\n", (long)p, p);
    char *p5 = strstr(buffer, "HTTP/"); // "HTTP/" 是协议标识 如 "HTTP/1.1"
    fprintf(stderr, "p5:  %ld\n%s\n", (long)p5, p5);
    int len = strlen(buffer);
    fprintf(stderr, "len:  %d\n", len);
    if (p)
    {
        char *p0 = strchr(p, '\0');
        fprintf(stderr, "p0:  %ld\n%s\n", (long)p0, p0);
        char *p1 = strchr(p + 7, '/');
        fprintf(stderr, "p1:  %ld\n%s\n", (long)p1, p1);
        if (p1 && (p5 > p1))
        {
            //转换url到 path
            // int i = 0;
            // for (i = 0; i <= (int)(p0 - p1); i++) {
            //     p[i] = p1[i];
            // }

            memcpy_fixed(p, p1, (int)(p0 - p1));
            // p[(int)(p0 - p1)] = '\0';
            fprintf(stderr, "p:  %ld\n%s\n", (long)p, p);
            int l = len - (p1 - p);
            fprintf(stderr, "l:  %d\n", l);
            buffer[l] = '\0';
            fprintf(stderr, "buffer:  %ld\n%s\n", (long)buffer, buffer);
        }
        else
        {
            char *p2 = strchr(p, ' '); //GET http://3g.sina.com.cn HTTP/1.1
            fprintf(stderr, "p2:  %ld\n%s\n", (long)p2, p2);

            memcpy_fixed(p + 1, p2, (int)(p0 - p2));
            *p = '/'; //url 没有路径使用根
            int l = len - (p2 - p) + 1;
            buffer[l] = '\0';
        }
    }
}

int main(int argc, char *argv[])
{
    char buffer[] = "GET http://edu.10155.com/ HTTP/1.1\nHost: edu.10155.com\nUser-Agent: curl/7.64.1\nAccept: */*\n\n";
    char *p = buffer;
    rewrite_proxy_path(p);
    fprintf(stderr, "buffer:\n%s\n", p);

    // char a[] = "hello world";
    // char *a1 = a;
    // char *a2 = a1 + 6;
    // char *a3 = "hector";
    // fprintf(stderr, "a1: %s\na2: %s\na3: %s\n", a1, a2, a3);

    // memcpy_fixed(a2, a3, 6);
    // a2[12]='\0';
    // a1[12]='\0';
    // fprintf(stderr, "a1: %s\na2: %s\na3: %s\n", a1, a2, a3);
    return 0;
}