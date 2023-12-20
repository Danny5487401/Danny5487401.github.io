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
- PKCS（The Public-Key Cryptography Standards 公钥密码学标准）: 是一组由RSA Security Inc.设计和发布的公钥密码标准
- Certificate Trust Chain（证书信任链): 用于身份验证的一系列证书，它们形成一条从一个可信任的根证书颁发机构开始，逐级向下连接，直到用于验证某个特定证书的中间证书或终端证书的一种方式


### 服务器证书分类
![screen reader text](server_cer.png "服务器证书分类")

- DV（Domain Validation）：面向个体用户，安全体系相对较弱，验证方式就是向 whois 信息中的邮箱发送邮件，按照邮件内容进行验证即可通过；
- OV（Organization Validation）：面向企业用户，证书在 DV 证书验证的基础上，还需要公司的授权，CA 通过拨打信息库中公司的电话来确认；
- EV（Extended Validation）：打开 Github 的网页，你会看到 URL 地址栏展示了注册公司的信息，这会让用户产生更大的信任，这类证书的申请除了以上两个确认外，还需要公司提供金融机构的开户许可证，要求十分严格
