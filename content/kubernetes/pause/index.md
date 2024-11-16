---
title: "Pause 容器"
date: 2024-11-02T21:52:00+08:00
summary: Pause 容器作用
categories:
  - kubernetes
tags:
  - k8s
  - pause
  - 源码
---

Pause容器 全称 infrastructure container（又叫infra）基础容器.它本身不包含任何业务逻辑，只是为其他容器提供一个稳定、可靠的运行环境。


kubelet的配置文件中心都指定了如下参数,这是指定拉取的pause镜像地址.

```shell
--pod-infra-container-image=registry.cn-hangzhou.aliyuncs.com/google_containers/pause-amd64:3.5
```

## 背景

熟悉 Pod 生命周期的同学应该知道，创建 Pod 时 Kubelet 先调用 CRI 接口 RuntimeService.RunPodSandbox 来创建一个沙箱环境，为 Pod 设置网络（例如：分配 IP）等基础运行环境。
当 Pod 沙箱（Pod Sandbox）建立起来后，Kubelet 就可以在里面创建用户容器。当到删除 Pod 时，Kubelet 会先移除 Pod Sandbox 然后再停止里面的所有容器

没有 pause 容器，那么 A 和 B 要共享网络，要不就是 A 加入 B 的 network namespace，要嘛就是 B 加入 A 的 network namespace， 而无论是谁加入谁，只要 network 的 owner 退出了，该 Pod 里的所有其他容器网络都会立马异常，这显然是不合理的。


## 基本概念

### Linux namespace 


| 名称 | 宏定义 |                                                                                      隔离的内容                                                                                       |
| :--: | :--: |:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| IPC | CLONE_NEWIPC |                                                             System V IPC, POSIX message queues (since Linux 2.6.19)                                                              |
| Network | CLONE_NEWNET | network device interfaces, IPv4 and IPv6 protocol stacks, IP routing tables, firewall rules, the /proc/net and /sys/class/net directory trees, sockets, etc (since Linux 2.6.24) |
| Mount | CLONE_NEWNS |                                                                        Mount points (since Linux 2.4.19)                                                                         |
| PID | CLONE_NEWPID |                                                                         Process IDs (since Linux 2.6.24)                                                                         |
| User | CLONE_NEWUSER |                                                     User and group IDs (started in Linux 2.6.23 and completed in Linux 3.8)                                                      |
| UTS | CLONE_NEWUTS |                                       Hostname and NIS domain name (since Linux 2.6.19)                                                                                                                                           |
| Cgroup | CLONE_NEWCGROUP |                                       Cgroup root directory (since Linux 4.6)                                                                                                                                      |







## 功能
kubernetes中的pause容器主要为每个业务容器提供以下功能：

- PID命名空间：Pod中的不同应用程序可以看到其他应用程序的进程ID。

- NETWORK 网络命名空间：Pod中的多个容器能够访问同一个IP和端口范围。

- IPC命名空间：Pod中的多个容器能够使用SystemV IPC或POSIX消息队列进行通信。

- UTS命名空间：Pod中的多个容器共享一个主机名；Volumes（共享存储卷）

pod 默认开启共享了 NETWORK, IPC 和 UTS 命名空间. 其他命名空间 namespace 需要在 pod 配置才可开启. 比如可以通过 shareProcessNamespace = true 开启 PID 命名空间的共享, 共享 pid 命名空间后, 容器内可以互相查看彼此的进程.

## 源码分析
```cgo
...

/* SIGINT, SIGTERM 信号会调用该函数. */
static void sigdown(int signo) {
  psignal(signo, "Shutting down, got signal");
  /* sigint 和 sigterm 都是正常干掉进程, exit code 为 0. */
  exit(0);
}

/* SIGCHLD 信号会调用该函数. */
static void sigreap(int signo) {
  /* waitpid 监听进程组的子进程退出, WNOHANG 是非阻塞标记, 当没有找到子进程退出时, 不会阻塞. */
  /* -1 是什么？ 1 为 pod 主进程, 通常也是pgid, -1 则是指进程组 1 */
  while (waitpid(-1, NULL, WNOHANG) > 0)
    ;
}

int main(int argc, char **argv) {
  int i;
  for (i = 1; i < argc; ++i) {
    if (!strcasecmp(argv[i], "-v")) {
      /* 打印 paruse.c 版本 */
      printf("pause.c %s\n", VERSION_STRING(VERSION));
      return 0;
    }
  }

  if (getpid() != 1)
    /* 如果不是 1 号进程, 则打印错误. */
    fprintf(stderr, "Warning: pause should be the first process\n");

  /* 注册 signal 信号对应的回调方法 */
  if (sigaction(SIGINT, &(struct sigaction){.sa_handler = sigdown}, NULL) < 0)
    return 1;
  if (sigaction(SIGTERM, &(struct sigaction){.sa_handler = sigdown}, NULL) < 0)
    return 2;
  if (sigaction(SIGCHLD, &(struct sigaction){.sa_handler = sigreap,
                                             .sa_flags = SA_NOCLDSTOP},
                NULL) < 0)
    return 3;

  for (;;)
    pause(); // 等待 signal 信号
  fprintf(stderr, "Error: infinite loop terminated\n");
  return 42;
}
```
pause 容器主要做两件事情.

1. 注册各种信号处理函数，主要处理两类信息：退出信号和 child 信号. 当收到 SIGINT 或是 SIGTERM 后, pause 进程可直接退出. 收到 SIGCHLD 信号, 则调用 waitpid 进行回收进程.
2. 主进程 for 循环调用 pause() 函数，使进程陷入休眠状态, 不占用 cpu 资源, 直到被终止或是收到信号.

## 参考
- [docker 容器基础技术：linux namespace 简介](https://cizixs.com/2017/08/29/linux-namespace/)
- [源码分析 kubernetes pause 容器的设计实现原理](https://github.com/rfyiamcool/notes/blob/main/kubernetes_pause_code.md)
- [Kubernetes Pod 网络精髓：pause 容器详解](https://segmentfault.com/a/1190000021710436)