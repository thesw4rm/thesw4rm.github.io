---
title: About 
date: 2020-09-08 00:01:58
---

# Info

Hi, I am a soon to graduate (or perhaps by the time you read this, already graduated) computer science student. I've experimented with a lot of tech stuff, but am focusing on kernel level networking. Specifically in side projects, I work on exploiting protocols to find weaknesses and crazy workarounds, and am learning malware development on Linux. 

# Projects

Click the tab for my Gitlab repo. My Github has more stuff and can be found by clicking the icon above. 

1. [Command and Control via TCP Handshake](/2019/09/15/Command-and-Control-via-TCP-Handshake/)
    
    Red team post-exploitation method to exfiltrate and infiltrate data. Payloads are attached to the options field of a TCP SYN packet, basically allowing it to hide in the massive amounts of SYN packets sent within a company all the time while being flexible enough to be used with numerous services. Requires rooting the target system or having a user with CAP_NET_ADMIN capabilities. Also only works on Linux for now.



