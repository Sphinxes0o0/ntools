#include <linux/if.h>        /*  IFF_LOWER_UP / IFF_RUNNING */
#include <linux/rtnetlink.h> /* RTM_* / IFLA_* / RTA_* */
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <stdio.h>

#undef  __USE_MISC
#include <net/if.h>
#define __USE_MISC 

typedef struct {
    bool iff_up;
    bool carrier_on;
    bool running;
} nic_state_t;


static int get_netif_state(const char *netif_name, nic_state_t *state) {
    unsigned idx = if_nametoindex(netif_name);
    if (!idx) {
        fprintf(stderr, "interface '%s' not exist\n", netif_name);
        return -1;
    }

    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifi;
    } req = {
        .nlh = {
            .nlmsg_len = sizeof(req),
            .nlmsg_type = RTM_GETLINK,
            .nlmsg_flags = NLM_F_REQUEST,
        },
        .ifi = {
            .ifi_family = AF_UNSPEC,
            .ifi_index = idx,
        },
    };

    struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
    if (sendto(fd, &req, sizeof(req), 0, (struct sockaddr *)&nladdr, sizeof(nladdr)) < 0) {
        perror("sendto");
        goto out;
    }

    char buf[16 * 1024];
    ssize_t len = recv(fd, buf, sizeof(buf), 0);
    if (len < 0) {
        perror("recv");
        goto out;
    }

    struct nlmsghdr *h;
    for (h = (void *)buf; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len)) {
        if (h->nlmsg_type == NLMSG_DONE) break;
        if (h->nlmsg_type != RTM_NEWLINK) continue;

        struct ifinfomsg *ifi = NLMSG_DATA(h);
        struct rtattr *rta = IFLA_RTA(ifi);
        int rta_len = IFLA_PAYLOAD(h);

        for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
            if (rta->rta_type == IFLA_IFNAME && strcmp(RTA_DATA(rta), netif_name) == 0) {
                unsigned f = ifi->ifi_flags;
                state->iff_up = !!(f & IFF_UP);
                state->carrier_on = !!(f & IFF_LOWER_UP);
                state->running = !!(f & IFF_RUNNING);
                close(fd);
                return 0;
            }
        }
    }

out:
    close(fd);
    return -1;
}



int main(int argc, char *argv[]) {
    const char *dev = argv[1] ? argv[1] : "eno1";
    nic_state_t state;
    if (get_netif_state(dev, &state) < 0) {
        fprintf(stderr, "get_netif_state: device '%s' not found or netlink error\n", dev);
        return -1;
    }

    printf("dev: %s, iff_up: %s, carrier_on: %s, running: %s\n => usable: %s \n", 
        dev, 
        state.iff_up ? "UP" : "DOWN",
        state.carrier_on ? "ON" : "OFF",
        state.running ? "RUNNING" : "NOT RUNNING",
        (state.iff_up && state.carrier_on && state.running) ? "YES" : "NO"
    );

    return 0;
}