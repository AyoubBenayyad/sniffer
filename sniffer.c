#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define SIZE_ETHERNET 14

/**
 * Global variable for Exercise 8 & 18 (Integration)
 */
int error404_count = 0;

/**
 * Exercise 5 Logic: Detect HTTP 404
 */
int detectHttp404(const char *buffer) {
    if (strstr(buffer, "HTTP") != NULL) {
        if (strstr(buffer, "404") != NULL) {
            return 1;
        }
    }
    return 0;
}

/**
 * Callback function (Exercises 14, 15, 18)
 */
void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *buff) {
    // Basic pointers to headers
    struct ip *ipHeader;
    struct tcphdr *tcpHeader;
    char *payload;
    int size_ip;
    int size_tcp;
    int size_payload;

    // Check header size to avoid invalid access
    ipHeader = (struct ip*)(buff + SIZE_ETHERNET);
    size_ip = ipHeader->ip_hl * 4;
    
    tcpHeader = (struct tcphdr*)(buff + SIZE_ETHERNET + size_ip);
    size_tcp = tcpHeader->th_off * 4;

    payload = (char *)(buff + SIZE_ETHERNET + size_ip + size_tcp);
    
    // Total header size
    int total_headers_size = SIZE_ETHERNET + size_ip + size_tcp;
    size_payload = h->len - total_headers_size;

    // Exercise 14: Print IP Dest and Size
    printf("[Packet] Dest IP: %s | Size: %d bytes\n", inet_ntoa(ipHeader->ip_dst), h->len);

    // Exercise 15: Print ASCII content if size >= 200
    if (size_payload >= 200) {
        printf("--- Content (First 200+ bytes) ---\n");
        // Print payload safely
        for (int i = 0; i < size_payload; i++) {
            if (isprint(payload[i]) || payload[i] == '\n' || payload[i] == '\r') {
                printf("%c", payload[i]);
            } else {
                printf(".");
            }
        }
        printf("\n--------------------------------\n");
    }

    // Exercise 18: Integrate detectHttp404 logic
    if (size_payload > 0) {
        // Create a temporary buffer to ensure null-termination for strstr
        // or just use payload if we are careful (strstr might overrun if not null-terminated)
        // For safety, let's assume text based HTTP protocols are roughly safe or just scan carefully.
        // We'll trust strstr won't go too far if we had a huge buffer or just copy a chunk.
        
        // Let's copy payload to a safe buffer for string analysis
        char safe_buffer[4096];
        int copy_len = size_payload < 4095 ? size_payload : 4095;
        memcpy(safe_buffer, payload, copy_len);
        safe_buffer[copy_len] = '\0';

        int retour = detectHttp404(safe_buffer);
        if (retour == 1) {
            printf("[!] 404 Error Detected in Packet!\n");
            error404_count++;
        }
    }

    // Alarm logic
    if (error404_count >= 2) {
        printf("ALARM: Suspicious behavior detected (Two 404 errors)!\n");
        error404_count = 0; // Reset
    }
}

int main(int argc, char *argv[]) {
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "tcp src port 80"; // Exercise 13
    bpf_u_int32 mask;
    bpf_u_int32 net;

    // Exercise 10: Lookup Device
    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        printf("Error finding device: %s\n", error_buffer);
        // Fallback for user or manual entry logic could go here
        // return 1;
        // For TP purposes, let's hardcode or ask user if NULL, but let's try "any" or "eth0" via argv
        if (argc > 1) {
            device = argv[1];
        } else {
            device = "any"; // Fallback to 'any' for linux often works
        }
        printf("Falling back to device: %s\n", device);
    }
    printf("Device found: %s\n", device);

    // Exercise 12: Network and Mask
    if (pcap_lookupnet(device, &net, &mask, error_buffer) == -1) {
        printf("Can't get netmask for device %s\n", device);
        net = 0;
        mask = 0;
    }
    struct in_addr net_addr, mask_addr;
    net_addr.s_addr = net;
    mask_addr.s_addr = mask;
    printf("Net: %s\n", inet_ntoa(net_addr));
    printf("Mask: %s\n", inet_ntoa(mask_addr));

    // Exercise 11: Open Live
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL) {
        printf("Could not open device %s: %s\n", device, error_buffer);
        return 2;
    }
    printf("Device %s opened.\n", device);

    // Exercise 13: Compile and Apply Filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        printf("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        printf("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    printf("Filter '%s' applied.\n", filter_exp);

    // Exercise 14: Loop
    printf("Starting capture loop...\n");
    pcap_loop(handle, -1, callback, NULL);

    // Cleanup
    pcap_close(handle);
    printf("Capture closed.\n");

    return 0;
}
