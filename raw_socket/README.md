这是一个使用原始套接字（RAW_SOCKET）实现的网络抓包工具。与 AF-XDP 不同，RAW_SOCKET 是传统的 Linux 网络抓包方法，它通过在内核协议栈中捕获数据包来实现抓包功能。

## 原理

原始套接字（SOCK_RAW）允许应用程序直接访问网络层数据包，而不需要通过标准的 TCP/IP 协议栈。通过创建 AF_PACKET 类型的原始套接字，程序可以捕获通过指定网络接口的所有数据包。

## 特性

- 捕获以太网帧并解析各种协议头部
- 支持解析 Ethernet、IP、TCP、UDP、ICMP 和 ARP 协议
- 显示详细的协议头部信息
- 显示所有协议的负载数据
- 简单易用的命令行界面

## 编译

```bash
make
```


## 使用方法

```bash
sudo ./raw_socket_capture <网络接口名>
```

例如：
```bash
sudo ./raw_socket_capture eth0
```

或者使用 make 命令：
```bash
sudo make run INTERFACE=eth0
```

## 工作原理

1. 创建 AF_PACKET 类型的原始套接字
2. 绑定到指定的网络接口
3. 循环接收通过该接口的所有数据包
4. 解析并显示数据包的协议头部信息
5. 显示每个数据包的负载数据

## 协议支持

当前版本支持解析以下协议：

1. **Ethernet (以太网)**
   - 源和目的 MAC 地址
   - 帧类型

2. **IP (Internet Protocol)**
   - 版本和头部长度
   - 服务类型
   - 总长度
   - 标识符和生存时间
   - 协议类型
   - 源和目的 IP 地址

3. **TCP (Transmission Control Protocol)**
   - 源和目的端口
   - 序列号和确认号
   - 标志位 (SYN, ACK, FIN 等)
   - 窗口大小和校验和

4. **UDP (User Datagram Protocol)**
   - 源和目的端口
   - 数据报长度和校验和

5. **ICMP (Internet Control Message Protocol)**
   - 类型和代码
   - 校验和
   - 基本类型识别 (Echo Request/Reply)

6. **ARP (Address Resolution Protocol)**
   - 硬件类型和协议类型
   - 硬件地址长度和协议地址长度
   - 操作码 (请求/响应)
   - 负载数据

## 负载数据显示

程序会显示所有协议的负载数据：

- 对于TCP数据包，如果检测到HTTP流量（端口80、443、8080），会特殊处理HTTP头部和内容
- 对于其他所有协议，以十六进制和ASCII格式显示负载数据
- 对于非IP数据包（如ARP），也会显示其负载数据

## 与 AF-XDP 的区别

| 特性 | RAW_SOCKET | AF-XDP |
|------|------------|--------|
| 性能 | 较低，数据包需要经过内核协议栈 | 极高，绕过内核协议栈直接从驱动获取 |
| 实现复杂度 | 简单，使用标准套接字API | 复杂，需要编写eBPF程序 |
| 兼容性 | 广泛支持 | 需要较新的内核版本和特定硬件支持 |
| 数据包处理 | 经过内核协议栈 | 直接从驱动获取 |
| 权限要求 | root权限 | root权限 |

## 注意事项

1. 需要 root 权限运行程序
2. 程序不会影响网络连接，因为它只是被动地捕获数据包
3. 按 Ctrl+C 停止程序