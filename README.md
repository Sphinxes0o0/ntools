# ntools

## 网络接口检查 

check network interface status

```bash
$ gcc netif_check_linux.c -o netifstate
$ ./netifstate eno1
dev: eno1, iff_up: UP, carrier_on: ON, running: RUNNING
 => usable: YES 

# for unix-like system, such as macos
$ clang netif_state.c -o netifs
./netifs 
dev: en0, iff_up: DOWN, carrier_on: OFF, running: NOT RUNNING
 => usable: NO
```

## RAW_SOCKET 抓包
使用RAW_SOCKET抓包, 并简单解析
> tcpdump mini 版

详情查看 raw_socket/README.md

## snort/suricata rules 转binary
将snort/suricata规则转换成二进制文件
详情查看 rule2bin/README.md
