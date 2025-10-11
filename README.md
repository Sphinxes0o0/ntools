# ntools

## netif_check 

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

