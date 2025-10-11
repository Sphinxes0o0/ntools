#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>

typedef struct {
    bool iff_up;
    bool carrier_on;
    bool running;
} nic_state_t;

static int get_netif_state(const char *name, nic_state_t *st) {
    struct ifaddrs *ifa, *ifa_cur;
    int ret = -1;

    if (getifaddrs(&ifa) != 0) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa_cur = ifa; ifa_cur != NULL; ifa_cur = ifa_cur->ifa_next) {
        if (strcmp(ifa_cur->ifa_name, name) != 0) continue;

        unsigned flags = ifa->ifa_flags;
        st->iff_up = flags & IFF_UP;
        st->carrier_on = flags & IFF_RUNNING;
        st->running = flags & IFF_RUNNING;
        ret = 0;
        break;
    }

    freeifaddrs(ifa);
}

int main(int argc, char **argv) {
    const char *dev = argc > 1 ? argv[1] : "en0";
    nic_state_t s;

    if (get_netif_state(dev, &s) < 0) {
        fprintf(stderr, "device '%s' not found\n", dev);
        return 1;
    }

    printf("dev: %s, iff_up: %s, carrier_on: %s, running: %s\n => usable: %s\n",
           dev,
           s.iff_up ? "UP" : "DOWN",
           s.carrier_on ? "ON" : "OFF",
           s.running ? "RUNNING" : "NOT RUNNING",
           (s.iff_up && s.carrier_on) ? "YES" : "NO");

    return 0;
}