# mproxy

A simple HTTP proxy. Support proxy basic authentication, custom proxy port and HTTP reverse proxy.

## Install

```bash
git clone https://github.com/hectorqin/mproxy
cd mproxy
make clean && make
# move this binary to your path
# mv mproxy /usr/local/bin/
```

## Usage

```bash
$ ./mproxy -h
Usage:
        -p <port number> : Specifyed local listen port.
        -a <user:pass> : Specifyed basic authorization of proxy.
        -r <remote_host:remote_port> : Specifyed remote host and port of reverse proxy. Only support http service now.
        -f <remote_host:remote_port> : Specifyed remote host and port of upstream proxy.
        -A <user:pass> : Specifyed basic authorization of upstream proxy.
        -E : Encode data when forwarding data. Available in forwarding upstream proxy.
        -D : Decode data when receiving data. Available in forwarding upstream proxy.
        -h : Print usage.
```

## Start a http forward proxy server

### Default port is 8080

```bash
./mproxy
```

### Custom port

```bash
./mproxy -p 8999
```

### Proxy basic authentication

```bash
./mproxy -a "www:123456"
```

### Upstream proxy

```bash
./mproxy -f "127.0.0.1:8999"
```

### Upstream proxy with upstream proxy basic authentication

```bash
./mproxy -f "127.0.0.1:8999" -A "www:123456"
```

### Upstream proxy with upstream proxy basic authentication and Proxy basic authentication

```bash
./mproxy -f "127.0.0.1:8999" -A "www:123456" -a "www:12345678"
```

### Upstream proxy with simple data encryption

```bash
# upstream proxy
./mproxy -D -p 8999

# proxy
./mproxy -f "127.0.0.1:8999" -A "www:123456" -a "www:12345678" -E
```

## Start a http reverse proxy server

### With custom port

```bash
./mproxy -p 8999 -r "www.baidu.com:80"
```

### With www basic authentication

```bash
./mproxy -a "www:123456" -r "www.baidu.com:80"
```
