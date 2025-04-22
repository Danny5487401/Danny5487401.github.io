---
title: "Certificate 证书"
summary: 证书分为根证书、服务器证书、客户端证书。根证书文件（ca.crt）和根证书对应的私钥文件（ca.key）由 CA（证书授权中心，国际认可）生成和保管。那么服务器如何获得证书呢？向 CA 申请！
date: 2023-12-20T09:36:06+08:00
draft: false
tags:
  - Security
---


## 基本概念

- CRL(Certificate Revocation List 证书吊销列表) : PKI 系统中的一个结构化数据文件，该文件包含了证书颁发机构 (CA) 已经吊销的证书的序列号及其吊销日期
- CA(Certificate Authority): 证书的签发机构，它是公钥基础设施（Public Key Infrastructure，PKI）的核心。
  任何个体/组织都可以扮演 CA 的角色，只不过难以得到客户端的信任，能够受浏览器默认信任的 CA 大厂商有很多，其中 TOP5 是 Symantec、Comodo、Godaddy、GolbalSign 和 Digicert
- PKCS（The Public-Key Cryptography Standards 公钥密码学标准）: 是一组由RSA Security Inc.设计和发布的公钥密码标准。
- X.509标准是Public Key Certificates公钥证书的格式标准
- Certificate Trust Chain（证书信任链): 用于身份验证的一系列证书，它们形成一条从一个可信任的根证书颁发机构开始，逐级向下连接，直到用于验证某个特定证书的中间证书或终端证书的一种方式
- Digital Certificate 数字证书又称为公开密钥证书(Public key certificate)：用来证明公开密钥拥有者的身份。
- ASN.1（Abstract Syntax Notation One 抽象语法标记）：一种 ISO/ITU-T 标准，描述了一种对数据进行表示、编码、传输和解码的数据格式。第一代PKI标准主要是基于抽象语法符号（Abstract Syntax Notation One，ASN.1）编码的，实现比较困难，这也在一定程度上影响了标准的推广。


### 服务器证书分类
![screen reader text](server_cer.png "服务器证书分类")

- DV（Domain Validation）：面向个体用户，安全体系相对较弱，验证方式就是向 whois 信息中的邮箱发送邮件，按照邮件内容进行验证即可通过；
- OV（Organization Validation）：面向企业用户，证书在 DV 证书验证的基础上，还需要公司的授权，CA 通过拨打信息库中公司的电话来确认；
- EV（Extended Validation）：打开 Github 的网页，你会看到 URL 地址栏展示了注册公司的信息，这会让用户产生更大的信任，这类证书的申请除了以上两个确认外，还需要公司提供金融机构的开户许可证，要求十分严格



### 数字证书编码格式
X.509 证书目前有以下两种编码格式:

- PEM - Privacy Enhanced Mail 保密增强邮件协议，以”—–BEGIN…”开头，”—–END…” 结尾，内容以 BASE64 编码。Apache 和 *NIX 服务器偏向于使用这种编码格式。
```text
-----BEGIN Type-----
Headers
base64-encoded Bytes
-----END Type-----
```

- DER - Distinguished Encoding Rules，二进制格式，不可读。Java 和 Windows 服务器偏向于使用这种编码格式

### 扩展名

除了 .pem 及 .der 之外，不同的系统或程序对数字证书文件载体定义了自己的扩展名，它们除了格式不同之外，内容也有差别，但大多数都能相互转换:

- .crt: 多见于 *NIX 系统 PEM 编码
- .cer: 多见于 Windows 系统 DER 编码
- .csr: (Certificate Signing Request 证书签名请求),是向 CA 发出的证书申领请求，其核心内容包含一个「公钥」及其他主体信息，在生成该请求时，也会生成相应的「私钥」



## go 语言  x509 包
crypto/x509 包主要用于解析 X.509 编码的密钥和证书.

crypto/x509/pkix 包含用于 X.509 证书，CRL 和 OCSP 的 ASN.1 解析和序列化的共享低级结构。

```go
// X509 证书
type Certificate struct {
    // 证书的 subject 信息,包含 CN,O,L,S,C等字段
    Subject pkix.Name
    // contains filtered or unexported fields
}


// 证书签署请求
type CertificateRequest struct {
    // 签名
    Signature          []byte
    // 签名算法
    SignatureAlgorithm SignatureAlgorithm
    // 私钥算法
    PublicKeyAlgorithm PublicKeyAlgorithm
    // 私钥
    PublicKey          interface{}
    // 证书签署请求的 subject
    Subject pkix.Name
    // contains filtered or unexported fields
}
```

```go
type Name struct {
	Country, Organization, OrganizationalUnit []string
	Locality, Province                        []string
	StreetAddress, PostalCode                 []string
	SerialNumber, CommonName                  string

	// Names contains all parsed attributes. When parsing distinguished names,
	// this can be used to extract non-standard attributes that are not parsed
	// by this package. When marshaling to RDNSequences, the Names field is
	// ignored, see ExtraNames.
	Names []AttributeTypeAndValue

	// ExtraNames contains attributes to be copied, raw, into any marshaled
	// distinguished names. Values override any attributes with the same OID.
	// The ExtraNames field is not populated when parsing, see Names.
	ExtraNames []AttributeTypeAndValue
}
```

## CloudFlare 开源证书管理工具 cfssl

```shell
[root@master-01 bin]# ./cfssl version
Version: dev
Runtime: go1.22.8
```


```shell
[root@master-01 bin]# ./cfssl --help
version # 查看 cfssl 版本
selfsign # 生成一个新的自签名密钥和签名证书
certinfo # 输出给定证书的证书信息， 跟 cfssl-certinfo 工具作用一样
print-defaults # 打印json格式的模板-ca签名配置文件和客户端证书请求文件
  # config：生成ca配置模板文件
  # csr：生成证书请求模板文件
gencert # 生成新的key(密钥)和签名证书
  # -initca：初始化一个新ca （默认false，需要指定ca证书用以前面其他证书）
  # -ca：ca的证书
  # -ca-key：ca的私钥文件
  # -config：请求证书的json文件
  # -profile：与-config中的profile对应，是指根据config中的profile段来生成证书的相关信息
sign # 签名一个客户端证书，通过给定的CA和CA密钥，和主机名
revoke # 吊销证书
info # 获取签名者信息
bundle # 创建包含客户端证书的证书包
serve # 启动一个HTTP API服务
genkey  # 生成一个key(私钥)和csr(证书签名请求)
gencsr # 生成新的证书请求文件
gencrl # 生成新的证书吊销列表
```