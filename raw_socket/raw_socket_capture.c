#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <net/if_arp.h>
#include <ctype.h>

#define BUFFER_SIZE 65536

void print_packet_info(unsigned char *buffer, int size);
void print_ethernet_header(unsigned char *buffer, int size);
void print_ip_header(unsigned char *buffer, int size);
void print_tcp_packet(unsigned char *buffer, int size);
void print_udp_packet(unsigned char *buffer, int size);
void print_icmp_packet(unsigned char *buffer, int size);
void print_arp_packet(unsigned char *buffer, int size);
void print_payload(unsigned char *data, int size);
void print_http_payload(unsigned char *data, int size);

int main(int argc, char *argv[])
{
    int sock_raw;
    struct sockaddr_ll sll;
    unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE);
    int packet_count = 0;

    if (argc != 2) {
        printf("用法: %s <网络接口名>\n", argv[0]);
        printf("例如: %s eth0\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // 创建原始套接字
    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        perror("创建原始套接字失败");
        exit(EXIT_FAILURE);
    }

    // 获取接口索引
    int ifindex = if_nametoindex(argv[1]);
    if (ifindex == 0) {
        perror("获取接口索引失败");
        close(sock_raw);
        free(buffer);
        exit(EXIT_FAILURE);
    }

    // 绑定到指定接口
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock_raw, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("绑定套接字失败");
        close(sock_raw);
        free(buffer);
        exit(EXIT_FAILURE);
    }

    printf("RAW_SOCKET 抓包程序运行在接口 %s 上\n", argv[1]);
    printf("按 Ctrl+C 停止程序\n\n");

    // 开始捕获数据包
    while (1) {
        int data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, NULL, NULL);
        
        if (data_size < 0) {
            perror("接收数据包失败");
            break;
        }

        packet_count++;
        printf("========== 数据包 %d ==========\n", packet_count);
        print_packet_info(buffer, data_size);
        printf("\n");
    }

    close(sock_raw);
    free(buffer);
    return 0;
}

void print_packet_info(unsigned char *buffer, int size)
{
    struct ethhdr *eth = (struct ethhdr*)buffer;

    // 打印以太网头部信息
    print_ethernet_header(buffer, size);

    // 检查是否为IP数据包
    if (ntohs(eth->h_proto) == ETH_P_IP) {
        print_ip_header(buffer, size);

        struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        switch (iph->protocol) {
            case IPPROTO_TCP:
                print_tcp_packet(buffer, size);
                break;
            case IPPROTO_UDP:
                print_udp_packet(buffer, size);
                break;
            case IPPROTO_ICMP:
                print_icmp_packet(buffer, size);
                break;
            default:
                printf("其他 IP 协议: %d\n", iph->protocol);
                break;
        }
    } else if (ntohs(eth->h_proto) == ETH_P_ARP) {
        // 处理ARP数据包
        print_arp_packet(buffer, size);
    } else {
        printf("非IP数据包，协议类型: 0x%04x\n", ntohs(eth->h_proto));
        // 显示非IP数据包的负载数据
        unsigned char *payload = buffer + sizeof(struct ethhdr);
        int payload_size = size - sizeof(struct ethhdr);
        if (payload_size > 0) {
            printf("负载数据 (%d 字节):\n", payload_size);
            print_payload(payload, payload_size);
        }
    }
}

void print_ethernet_header(unsigned char *buffer, int size)
{
    struct ethhdr *eth = (struct ethhdr*)buffer;

    printf("以太网头部:\n");
    printf("   源MAC地址: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("   目的MAC地址: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("   协议类型: 0x%04x\n", ntohs(eth->h_proto));
}

void print_ip_header(unsigned char *buffer, int size)
{
    unsigned char *ip_header = buffer + sizeof(struct ethhdr);
    struct iphdr *iph = (struct iphdr*)ip_header;

    printf("IP头部:\n");
    printf("   版本: %d\n", (unsigned int)iph->version);
    printf("   首部长度: %d DWORDS / %d 字节\n", (unsigned int)iph->ihl, ((unsigned int)(iph->ihl)) * 4);
    printf("   服务类型: %d\n", (unsigned int)iph->tos);
    printf("   总长度: %d 字节\n", ntohs(iph->tot_len));
    printf("   标识符: %d\n", ntohs(iph->id));
    printf("   生存时间: %d\n", (unsigned int)iph->ttl);
    printf("   协议: %d\n", (unsigned int)iph->protocol);
    printf("   首部校验和: %d\n", ntohs(iph->check));
    printf("   源IP地址: %s\n", inet_ntoa(*(struct in_addr*)&iph->saddr));
    printf("   目的IP地址: %s\n", inet_ntoa(*(struct in_addr*)&iph->daddr));
}

void print_tcp_packet(unsigned char *buffer, int size)
{
    unsigned char *ip_header = buffer + sizeof(struct ethhdr);
    struct iphdr *iph = (struct iphdr*)ip_header;
    unsigned short iphdrlen = iph->ihl * 4;
    struct tcphdr *tcph = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + iphdrlen);
    unsigned short tcphdrlen = tcph->doff * 4;

    printf("TCP头部:\n");
    printf("   源端口: %d\n", ntohs(tcph->source));
    printf("   目的端口: %d\n", ntohs(tcph->dest));
    printf("   序列号: %u\n", ntohl(tcph->seq));
    printf("   确认号: %u\n", ntohl(tcph->ack_seq));
    printf("   头部长度: %d DWORDS / %d 字节\n", (unsigned int)tcph->doff, (unsigned int)tcph->doff * 4);
    printf("   标志位: ");
    if (tcph->urg) printf("URG ");
    if (tcph->ack) printf("ACK ");
    if (tcph->psh) printf("PSH ");
    if (tcph->rst) printf("RST ");
    if (tcph->syn) printf("SYN ");
    if (tcph->fin) printf("FIN ");
    printf("\n");
    printf("   窗口大小: %d\n", ntohs(tcph->window));
    printf("   校验和: %d\n", ntohs(tcph->check));
    printf("   紧急指针: %d\n", ntohs(tcph->urg_ptr));

    // 计算TCP数据负载位置和大小
    unsigned char *payload = buffer + sizeof(struct ethhdr) + iphdrlen + tcphdrlen;
    int payload_size = size - sizeof(struct ethhdr) - iphdrlen - tcphdrlen;

    if (payload_size > 0) {
        printf("TCP 负载 (%d 字节):\n", payload_size);

        // 如果是常见的应用层协议端口，则尝试解析
        if (ntohs(tcph->source) == 80 || ntohs(tcph->dest) == 80 ||
            ntohs(tcph->source) == 443 || ntohs(tcph->dest) == 443 ||
            ntohs(tcph->source) == 8080 || ntohs(tcph->dest) == 8080) {
            print_http_payload(payload, payload_size);
        } else {
            print_payload(payload, payload_size);
        }
    }
}

void print_udp_packet(unsigned char *buffer, int size)
{
    unsigned char *ip_header = buffer + sizeof(struct ethhdr);
    struct iphdr *iph = (struct iphdr*)ip_header;
    unsigned short iphdrlen = iph->ihl * 4;
    struct udphdr *udph = (struct udphdr*)(buffer + sizeof(struct ethhdr) + iphdrlen);
    
    printf("UDP头部:\n");
    printf("   源端口: %d\n", ntohs(udph->source));
    printf("   目的端口: %d\n", ntohs(udph->dest));
    printf("   UDP长度: %d\n", ntohs(udph->len));
    printf("   校验和: %d\n", ntohs(udph->check));
    
    // 计算UDP数据负载位置和大小
    unsigned char *payload = buffer + sizeof(struct ethhdr) + iphdrlen + sizeof(struct udphdr);
    int payload_size = size - sizeof(struct ethhdr) - iphdrlen - sizeof(struct udphdr);
    
    if (payload_size > 0) {
        printf("UDP 负载 (%d 字节):\n", payload_size);
        print_payload(payload, payload_size);
    }
}

void print_icmp_packet(unsigned char *buffer, int size)
{
    unsigned char *ip_header = buffer + sizeof(struct ethhdr);
    struct iphdr *iph = (struct iphdr*)ip_header;
    unsigned short iphdrlen = iph->ihl * 4;
    struct icmphdr *icmph = (struct icmphdr*)(buffer + sizeof(struct ethhdr) + iphdrlen);
    
    printf("ICMP头部:\n");
    printf("   ICMP类型: %d\n", (unsigned int)icmph->type);
    printf("   ICMP代码: %d\n", (unsigned int)icmph->code);
    printf("   校验和: %d\n", ntohs(icmph->checksum));
    
    switch (icmph->type) {
        case 0:
            printf("   ICMP类型描述: Echo Reply\n");
            break;
        case 8:
            printf("   ICMP类型描述: Echo Request\n");
            break;
        default:
            printf("   ICMP类型描述: 其他\n");
            break;
    }
    
    // 计算ICMP数据负载位置和大小
    unsigned char *payload = buffer + sizeof(struct ethhdr) + iphdrlen + sizeof(struct icmphdr);
    int payload_size = size - sizeof(struct ethhdr) - iphdrlen - sizeof(struct icmphdr);
    
    if (payload_size > 0) {
        printf("ICMP 负载 (%d 字节):\n", payload_size);
        print_payload(payload, payload_size);
    }
}

void print_arp_packet(unsigned char *buffer, int size)
{
    struct arphdr *arp = (struct arphdr*)(buffer + sizeof(struct ethhdr));
    
    printf("ARP协议头部:\n");
    printf("   硬件类型: %d\n", ntohs(arp->ar_hrd));
    printf("   协议类型: 0x%04x\n", ntohs(arp->ar_pro));
    printf("   硬件地址长度: %d\n", arp->ar_hln);
    printf("   协议地址长度: %d\n", arp->ar_pln);
    printf("   操作码: %d ", ntohs(arp->ar_op));
    
    switch(ntohs(arp->ar_op)) {
        case ARPOP_REQUEST:
            printf("(ARP请求)\n");
            break;
        case ARPOP_REPLY:
            printf("(ARP响应)\n");
            break;
        case ARPOP_RREQUEST:
            printf("(RARP请求)\n");
            break;
        case ARPOP_RREPLY:
            printf("(RARP响应)\n");
            break;
        default:
            printf("(未知操作)\n");
            break;
    }
    
    // 显示ARP负载数据
    unsigned char *payload = buffer + sizeof(struct ethhdr) + sizeof(struct arphdr);
    int payload_size = size - sizeof(struct ethhdr) - sizeof(struct arphdr);
    if (payload_size > 0) {
        printf("ARP负载数据 (%d 字节):\n", payload_size);
        print_payload(payload, payload_size);
    }
}

void print_payload(unsigned char *data, int size)
{
    int i, j;
    
    // 限制显示的数据量，避免输出过多
    int display_size = (size > 256) ? 256 : size;
    
    // 以十六进制和ASCII格式显示数据
    for (i = 0; i < display_size; i += 16) {
        // 打印偏移量
        printf("   %04x: ", i);
        
        // 打印十六进制
        for (j = 0; j < 16; j++) {
            if (i + j < display_size) {
                printf("%02x ", data[i + j]);
            } else {
                printf("   ");
            }
            
            // 在第8个字节后添加空格以提高可读性
            if (j == 7) {
                printf(" ");
            }
        }
        
        // 打印ASCII
        printf("  ");
        for (j = 0; j < 16; j++) {
            if (i + j < display_size) {
                if (isprint(data[i + j])) {
                    printf("%c", data[i + j]);
                } else {
                    printf(".");
                }
            }
        }
        
        printf("\n");
    }
    
    if (size > 256) {
        printf("   ... (%d 字节剩余未显示)\n", size - 256);
    }
}

void print_http_payload(unsigned char *data, int size)
{
    int i;
    
    // 限制显示的数据量，避免输出过多
    int display_size = (size > 1024) ? 1024 : size;
    
    printf("HTTP 数据:\n");
    
    // 尝试检测HTTP头部结束位置（两个换行符）
    int header_end = -1;
    for (i = 0; i < display_size - 3; i++) {
        if (data[i] == '\r' && data[i+1] == '\n' && 
            data[i+2] == '\r' && data[i+3] == '\n') {
            header_end = i + 4;
            break;
        }
    }
    
    if (header_end > 0) {
        // 打印HTTP头部
        printf("HTTP 头部:\n");
        for (i = 0; i < header_end && i < display_size; i++) {
            if (isprint(data[i]) || data[i] == '\r' || data[i] == '\n') {
                printf("%c", data[i]);
            } else {
                printf(".");
            }
        }
        
        // 打印HTTP内容（如果有）
        if (display_size > header_end) {
            int content_size = display_size - header_end;
            printf("\nHTTP 内容 (%d 字节):\n", content_size);
            print_payload(data + header_end, content_size);
        }
    } else {
        // 如果未找到HTTP头部结束标记，按普通数据处理
        print_payload(data, display_size);
    }
    
    if (size > 1024) {
        printf("   ... (%d 字节剩余未显示)\n", size - 1024);
    }
}