
---
title: "Ssh"
date: 2024-09-21T15:54:25+08:00
summary: "Secure Shell 加密的网络传输协议及在teleport中应用 "
categories:
  - ssh
tags:
  - ssh
  - teleport
---


对于 SSH 协议的标准实现是 OpenSSH。该实现不仅实现了标准 rfc 中的 ssh，还对 ssh 进行了扩展.

由于 OpenSSH 协议是事实上的标准，因此 Go 的 SSH 库也对 OpenSSH 的扩展进行了支持.


## SSH 协议架构

SSH 协议由 3 个子协议构成。从底层到顶层分别是：

{{<figure src="./ssh_structure.png#center" width=800px >}}

- 传输层协议 SSH Transport Layer Protocol（rfc4253），定义了 SSH 协议数据包的格式以及 Key 交换算法。
- 用户认证协议SSH User Authentication Protocol（rfc4252），定义了 SSH 协议支持的用户身份认证算法。
- 连接协议SSH Connection Protocol:（rfc4254），定义了 SSH 支持功能特性：交互式登录会话、TCP/IP 端口转发、X11 Forwarding。



## 传输层协议

简单流程
- 建立底层连接（4.1 Use over TCP/IP）
  - Client 请求建立 TCP 连接
  - Server Accept 完成 TCP 连接建立
- 协议版本交换（4.2 Protocol Version Exchange）
  - Client 发送字符串，格式 SSH-protoversion-softwareversion SP comments CR LF，如 SSH-2.0-Go\r\n
  - Server 发送字符串，格式要求和 Client 一致。如 SSH-2.0-dropbear_2022.83\r\n
- Key 交换算法协商（7.1. Algorithm Negotiation）
  - 原因：非对称加密算法性能太差，SSH 在这里交互对称加密算法和密钥，之后采用对称加密通信，类似于 https 交互过程
- Key 交换算法执行（8. Diffie-Hellman Key Exchange）
- Key Re-Exchange 即 Key 会多次交换

## 用户认证协议

RFC 4252: The Secure Shell (SSH) Authentication Protocol  支持如下几种身份认证协议：

- none，服务端关闭身份认证，也就是说，任意用户都可以连接到该服务端（rfc4252#section-5.2）。
- publickey基于公钥的身份认证:设备上可以利用RSA和 DSA两种公共密钥算法实现数字签名.客户端发送包含用户名,公共密钥和公共密钥算法的 publickey 认证请求给服务器端.服务器对公钥进行合法性检查,如果不合法,则直接发送失败消息;否则,服务器利用数字签名对客户端进行认证,并返回认证成功或失败的消息（rfc4252#section-7）。
- password认证: 客户端向服务器发出 password认证请求,将用户名和密码加密后发送给服务器;服务器将该信息解密后得到用户名和密码的明文,与设备上保存的用户名和密码进行比较,并返回认证成功或失败的消息。（rfc4252#section-8）
- hostbased，比较少见，略（rfc4252#section-9）。
- GSS-API，校验 （rfc4462）

```go
// /Users/python/go/pkg/mod/golang.org/x/crypto@v0.22.0/ssh/client_auth.go

// "none" authentication, RFC 4252 section 5.2.
type noneAuth int

type passwordCallback func() (password string, err error)

type publicKeyCallback func() ([]Signer, error)

// 定义多种keyboard-challenge来提示用户输入认证的input.
type KeyboardInteractiveChallenge func(name, instruction string, questions []string, echos []bool) (answers []string, err error)

type gssAPIWithMICCallback struct {
	gssAPIClient GSSAPIClient
	target       string
}
```



## 连接协议
RFC 4254: The Secure Shell (SSH) Connection Protocol 连接协议，包括：交互式登录会话、TCP/IP 端口转发、X11 Forwarding

SSH 连接协议定义的交互式登录终端会话、TCP/IP 端口转发、X11 Forwarding 的这些功能，都工作在自己的通道 (Channel) 之上的。

在 SSH 协议中，Channel 实现对底层连接的多路复用（虚拟连接）
- 通过一个数字来进行标识和区分这些 Channel
- 实现流控（窗口


### 交互式会话
在 SSH 语境下，会话（Session）代表远程执行一个程序。这个程序可能是 Shell、应用。同时，它可能有也可能没有一个 tty、可能涉及也可能不涉及 x11 forward。




## 应用
```html
// https://www.rfc-editor.org/rfc/rfc4250#section-4.9.1
Channel type                  Reference
------------                  ---------
session                       [SSH-CONNECT, Section 6.1]
x11                           [SSH-CONNECT, Section 6.3.2]
forwarded-tcpip               [SSH-CONNECT, Section 7.2]
direct-tcpip                  [SSH-CONNECT, Section 7.2]


```

常见使用场景包括：

- 远程登录：从任何地点通过互联网安全地访问和控制远程计算机或服务器。
- 安全文件传输：使用SCP (Secure Copy) 或 SFTP (SSH File Transfer Protocol) 安全地复制或传输文件。
- 远程命令执行：在远程服务器上执行命令，就像在本地终端一样。
- 端口转发/隧道：通过SSH创建安全的隧道传输数据，可以将本地端口映射到远程服务器上的端口，或反向操作。
- 代理服务：使用SSH作为SOCKS代理来进行网络活动，增加通信的安全性。


### 端口转发（port forwarding）
又称 SSH 隧道（tunnel）。

端口转发有两个主要作用：

（1）将不加密的数据放在 SSH 安全连接里面传输，使得原本不安全的网络服务增加了安全性，比如通过端口转发访问 Telnet、FTP 等明文服务，数据传输就都会加密。

（2）作为数据通信的加密跳板，绕过网络防火墙。


#### X11 Forwarding
X11 Forwarding，通过SSH连接并运行Linux上有GUI的程序，就像是在Windows下运行GUI程序一样方便。

X11 中的 X 指的就是 X 协议，11 指的是采用 X 协议的第 11 个版本。


#### 本地端口转发（local forwarding）（direct-tcpip）



使用场景

- 远程机器监听在 127.0.0.1:3306 的MySQL想在本地访问


```shell
     -L [bind_address:]port:host:hostport
     -L [bind_address:]port:remote_socket
     -L local_socket:host:hostport
     -L local_socket:remote_socket
             Specifies that connections to the given TCP port or Unix socket on the local (client) host are to be forwarded to the given host and port, or Unix socket, on the remote side.  This works by allocating
             a socket to listen to either a TCP port on the local side, optionally bound to the specified bind_address, or to a Unix socket.  Whenever a connection is made to the local port or socket, the
             connection is forwarded over the secure channel, and a connection is made to either host port hostport, or the Unix socket remote_socket, from the remote machine.

             Port forwardings can also be specified in the configuration file.  Only the superuser can forward privileged ports.  IPv6 addresses can be specified by enclosing the address in square brackets.

             By default, the local port is bound in accordance with the GatewayPorts setting.  However, an explicit bind_address may be used to bind the connection to a specific address.  The bind_address of
             “localhost” indicates that the listening port be bound for local use only, while an empty address or ‘*’ indicates that the port should be available from all interfaces.
```

{{<figure src="./local-port-forward.png#center" width=800px >}}
```shell
# 创建一个本地端口，将发往该端口的所有通信都通过 SSH 服务器，转发到指定的远程服务器的端口。
ssh -L  -N -f localPort : remoteHost : remotePort  sshServer

ssh -L 9000:host2:80 host3
```

* -L：转发本地端口。
* -N：不发送任何命令，只用来建立连接。没有这个参数，会在 SSH 服务器打开一个 Shell。
* -f：将 SSH 连接放到后台。没有这个参数，暂时不用 SSH 连接时，终端会失去响应。


#### 远程端口转发 （forwarded-tcpip）
远程转发指的是在远程 SSH 服务器建立的转发规则。

它跟本地转发正好反过来。建立本地计算机到远程 SSH 服务器的隧道以后，本地转发是通过本地计算机访问远程 SSH 服务器，而远程转发则是通过远程 SSH 服务器访问本地计算机。

远程转发主要针对内网的情况。

```shell

     -R [bind_address:]port:host:hostport
     -R [bind_address:]port:local_socket
     -R remote_socket:host:hostport
     -R remote_socket:local_socket
     -R [bind_address:]port
             Specifies that connections to the given TCP port or Unix socket on the remote (server) host are to be forwarded to the local side.

             This works by allocating a socket to listen to either a TCP port or to a Unix socket on the remote side.  Whenever a connection is made to this port or Unix socket, the connection is forwarded over
             the secure channel, and a connection is made from the local machine to either an explicit destination specified by host port hostport, or local_socket, or, if no explicit destination was specified,
             ssh will act as a SOCKS 4/5 proxy and forward connections to the destinations requested by the remote SOCKS client.

             Port forwardings can also be specified in the configuration file.  Privileged ports can be forwarded only when logging in as root on the remote machine.  IPv6 addresses can be specified by enclosing
             the address in square brackets.

             By default, TCP listening sockets on the server will be bound to the loopback interface only.  This may be overridden by specifying a bind_address.  An empty bind_address, or the address ‘*’,
             indicates that the remote socket should listen on all interfaces.  Specifying a remote bind_address will only succeed if the server's GatewayPorts option is enabled (see sshd_config(5)).

             If the port argument is ‘0’, the listen port will be dynamically allocated on the server and reported to the client at run time.  When used together with -O forward, the allocated port will be printed
             to the standard output.

```

1. 第一个例子是内网某台服务器localhost在 80 端口开了一个服务，可以通过远程转发将这个 80 端口，映射到具有公网 IP 地址的my.public.server服务器的 8080 端口，使得访问my.public.server:8080这个地址，就可以访问到那台内网服务器的 80 端口

```shell
# ssh -R  sshServerPort : remoteHost : remotePort  sshServer
# 命令是在内网localhost服务器上执行，建立从localhost到my.public.server的 SSH 隧道。
ssh -R 8080:localhost:80 -N my.public.server
```


2. 第二个例子是本地计算机local在外网，SSH 跳板机和目标服务器my.private.server都在内网，必须通过 SSH 跳板机才能访问目标服务器。但是，本地计算机local无法访问内网之中的 SSH 跳板机，而 SSH 跳板机可以

```shell
# 命令是在 SSH 跳板机上执行的，建立跳板机到local的隧道
ssh -R 2121:my.private.server:80 -N local
```


#### 动态转发
目标：将本地主机（或局域网）服务监听的端口转发到远程服务器

相对于本地转发和远程转发的单一端口转发模式而言，动态转发有点更加强劲的端口转发功能，即是无需固定指定被访问目标主机的端口号。这个端口号需要在本地通过协议指定，该协议就是简单、安全、实用的 SOCKS 协议。

动态转发需要把本地端口绑定到 SSH 服务器。至于 SSH 服务器要去访问哪一个网站，完全是动态的，取决于原始通信，所以叫做动态转发。

```shell
     -D [bind_address:]port
             Specifies a local “dynamic” application-level port forwarding.  This works by allocating a socket to listen to port on the local side, optionally
             bound to the specified bind_address.  Whenever a connection is made to this port, the connection is forwarded over the secure channel, and the
             application protocol is then used to determine where to connect to from the remote machine.  Currently the SOCKS4 and SOCKS5 protocols are
             supported, and ssh will act as a SOCKS server.  Only root can forward privileged ports.  Dynamic port forwardings can also be specified in the
             configuration file.

             IPv6 addresses can be specified by enclosing the address in square brackets.  Only the superuser can forward privileged ports.  By default, the
             local port is bound in accordance with the GatewayPorts setting.  However, an explicit bind_address may be used to bind the connection to a
             specific address.  The bind_address of “localhost” indicates that the listening port be bound for local use only, while an empty address or ‘*’
             indicates that the port should be available from all interfaces.
```
* -D表示动态转发
* port 本地端口

```shell
# 创建了一个SOCKS代理，去监听本地的50000端口,所以通过该SOCKS代理发出的数据包将经过host1转发出去。
ssh -D 50000 user@host1

# 使用，curl 的-x参数指定代理服务器
curl -x socks5://localhost:50000 http://www.example.com
```

如果经常使用动态转发，可以将设置写入 SSH 客户端的用户个人配置文件 ~/.ssh/config


### 交互式会话 session

```go
// https://github.com/gravitational/teleport/blob/bfbc0276d4a0341f7170399a0062a2dcc5f90148/api/observability/tracing/ssh/client.go
func (c *clientWrapper) NewSession() (*Session, error) {
	// create a client that will defer to us when
	// opening the "session" channel so that we
	// can add an Envelope to the request
	client := &ssh.Client{
		Conn: c,
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// wrap the session so all session requests on the channel
	// can be traced
	return &Session{
		Session: session,
		wrapper: c,
	}, nil
}
```

伪终端 
```go
// allocateTerminal creates (allocates) a server-side terminal for this session.
func (ns *NodeSession) allocateTerminal(ctx context.Context, termType string, s *tracessh.Session) (io.ReadWriteCloser, error) {
	var err error

	// read the size of the terminal window:
	width := teleport.DefaultTerminalWidth
	height := teleport.DefaultTerminalHeight
	if ns.terminal.IsAttached() {
		realWidth, realHeight, err := ns.terminal.Size()
		if err != nil {
			log.Error(err)
		} else {
			width = int(realWidth)
			height = int(realHeight)
		}
	}

	// ... and request a server-side terminal of the same size:
	err = s.RequestPty(
		ctx,
		termType,
		height,
		width,
		ssh.TerminalModes{},
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// 获取到标准输入、标准输出、标准出错和远端进行交互
	writer, err := s.StdinPipe()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	reader, err := s.StdoutPipe()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	stderr, err := s.StderrPipe()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if ns.terminal.IsAttached() {
		go ns.updateTerminalSize(ctx, s)
	}
	go func() {
		if _, err := io.Copy(ns.nodeClient.TC.Stderr, stderr); err != nil {
			log.Debugf("Error reading remote STDERR: %v", err)
		}
	}()
	return utils.NewPipeNetConn(
		reader,
		writer,
		utils.MultiCloser(writer, s, ns.closer),
		&net.IPAddr{},
		&net.IPAddr{},
	), nil
}
```


```go
func (s *Session) RequestPty(ctx context.Context, term string, h, w int, termmodes ssh.TerminalModes) error {
	const request = "pty-req"
	config := tracing.NewConfig(s.wrapper.opts)
	tracer := config.TracerProvider.Tracer(instrumentationName)
	ctx, span := tracer.Start(
		ctx,
		fmt.Sprintf("ssh.RequestPty/%s", term),
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(
			semconv.RPCServiceKey.String("ssh.Session"),
			semconv.RPCMethodKey.String("SendRequest"),
			semconv.RPCSystemKey.String("ssh"),
			attribute.Int("width", w),
			attribute.Int("height", h),
		),
	)
	defer span.End()

	s.wrapper.addContext(ctx, request)
	return trace.Wrap(s.Session.RequestPty(term, h, w, termmodes))
}
```


运行命令

```go
// https://github.com/gravitational/teleport/blob/f814b2d510ed38266d340ea138bc38f0b8a132f0/api/observability/tracing/ssh/session.go
func (s *Session) Run(ctx context.Context, cmd string) error {
	const request = "exec"
	config := tracing.NewConfig(s.wrapper.opts)
	ctx, span := config.TracerProvider.Tracer(instrumentationName).Start(
		ctx,
		fmt.Sprintf("ssh.Run/%s", cmd),
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(
			semconv.RPCServiceKey.String("ssh.Session"),
			semconv.RPCMethodKey.String("SendRequest"),
			semconv.RPCSystemKey.String("ssh"),
		),
	)
	defer span.End()

	s.wrapper.addContext(ctx, request)
	return trace.Wrap(s.Session.Run(cmd)) // 等价于先 Start 再 Wait

```

```go
// golang.org/x/crypto@v0.22.0/ssh/session.go
func (s *Session) Run(cmd string) error {
	err := s.Start(cmd) // 在远端启动一个命令
	if err != nil {
		return err
	}
	return s.Wait() // 等待远端执行完成
}

```


## golang 实现

- golang.org/x/crypto/ssh 实现了 SSH 客户端和服务器
- github.com/gliderlabs/ssh 将 crypto/ssh 包包装在更高级别的 API 中，用于构建 SSH 服务器


### x/crypto/ssh 实现参考代码

```go
// https://github.com/gravitational/teleport/blob/9ef216584cc0829334cff1f7fd15ed0a3fb7aa52/lib/srv/forward/sshserver.go
func (s *Server) newRemoteClient(ctx context.Context, systemLogin string) (*tracessh.Client, error) {
	// the proxy will use the agentless signer as the auth method when
	// connecting to the remote host if it is available, otherwise the
	// forwarded agent is used
	var signers []ssh.Signer
	if s.agentlessSigner != nil {
		signers = []ssh.Signer{s.agentlessSigner}
	} else {
		var err error
		signers, err = s.userAgent.Signers()
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}
	authMethod := ssh.PublicKeysCallback(signersWithSHA1Fallback(signers))

	clientConfig := &ssh.ClientConfig{
		User: systemLogin, // 用户名，对应 ssh 命令的 ssh 用户名@xxx 用户名部分
		Auth: []ssh.AuthMethod{
			authMethod,
		},
		// SSH Server Host Key 的校验，预防 SSH 中间人攻击
		HostKeyCallback: s.authHandlers.HostKeyAuth,
		Timeout:         apidefaults.DefaultIOTimeout,
	}

	// Ciphers, KEX, and MACs preferences are honored by both the in-memory
	// server as well as the client in the connection to the target node.
	clientConfig.Ciphers = s.ciphers
	clientConfig.KeyExchanges = s.kexAlgorithms
	clientConfig.MACs = s.macAlgorithms

	// Destination address is used to validate a connection was established to
	// the correct host. It must occur in the list of principals presented by
	// the remote server.
	dstAddr := net.JoinHostPort(s.address, "0")
	client, err := tracessh.NewClientConnWithDeadline(ctx, s.targetConn, dstAddr, clientConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return client, nil
}
```




## 常见命令

ssh-keygen:产生公钥和私钥对.
```shell
ssh-keygen -t ed25519 -b 4096 -C "xxxx@gmail.com" # 推荐，比 rsa 短，安全性高

```

ssh-add：把专用密钥添加到ssh-agent的高速缓存中,从而提高ssh的认证速度
```shell
# 查看ssh-agent中的密钥
ssh-add -l
```


ssh-copy-id ：将本机的秘钥复制到远程机器的authorized_keys文件中

```shell
ssh-copy-id -i /root/.ssh/id_dsa.pub root@180.8.5.6
```


## 参考

- [SSH 协议 和 Go SSH 库源码浅析](https://www.rectcircle.cn/posts/ssh-protocol-and-go-lib/)
- [SSH 端口转发](https://wangdoc.com/ssh/port-forwarding)
- [Go语言自定义自己的SSH-Server](https://zh.mojotv.cn/go/create-your-own-ssh-server)
- [开发扩展SSH的使用领域和功能](https://zh.mojotv.cn/golang/ssh-pty-im)