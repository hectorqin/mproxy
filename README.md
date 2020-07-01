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
        -h : Print usage
        -p <port number> : Specifyed local listen port
        -u <user:pass> : Specifyed basic authorization of proxy
        -r <remote_host:remote_port> : Specifyed remote host and port of reverse proxy. Only support http service now.
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
./mproxy -u "www:123456"
```

## Start a http reverse proxy server

### With custom port

```bash
./mproxy -p 8999 -r "www.baidu.com:80"
```

### With proxy basic authentication

```bash
./mproxy -u "www:123456" -r "www.baidu.com:80"
```
