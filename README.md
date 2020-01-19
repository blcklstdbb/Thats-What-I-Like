# That's What I Like
* [Windows Security](#windows-security)
  * [Malware Analysis](#malware-analysis)
  * [Exploit Development](#exploit-development)
* [macOS Security](#macos-security)
* [Linux Security](#linux-security)
* [Mobile Security](#mobile-security)
  * [Android Security](#android-security)
  * [iOS Security](#ios-security)
  * [Guides for Mobile Security Tools](#guides-for-mobile-security-tools)
* [Web App Security](#web-app-security)
* [Incident Response](#incident-response)
  * [macOS IR](#macos-ir)
* [Misc Resources](#misc-resources)
  * [Books](#books)


## Windows Security
* [PentesterAcademy's Reverse Engineering Win32 Application course (PAID)](https://www.pentesteracademy.com/course?id=41)
* [OALabs Malware Analysis Virtual Machine](https://oalabs.openanalysis.net/2018/07/16/oalabs_malware_analysis_virtual_machine/)
* [Uncovering The Unknowns: Mapping Windows API’s to Sysmon Events](https://posts.specterops.io/uncovering-the-unknowns-a47c93bb6971)
* [MalwareTech's User After Free (1.0) challenge](https://www.malwaretech.com/windows-exploit-challenges/user-after-free-1-0)
### Malware Analysis
* [OALabs's malware analysis videos](https://www.youtube.com/channel/UC--DwaiMV-jtO-6EvmKOnqg/videos)
* [Sam Bowne's Practical Malware Analysis class (FREE)](https://samsclass.info/126/126_F19.shtml)
### Exploit Development
* [Open Security Training's Buffer Overflow mystery box](https://web.archive.org/web/20170222100242/https://thesprawl.org/research/ost-introductory-x86-buffer-overflow-mystery-box/)
* [Open Security Training's Introduction To Software Exploits](http://opensecuritytraining.info/Exploits1.html)
* [Understanding Windows Shellcode](http://www.hick.org/code/skape/papers/win32-shellcode.pdf)
* [Sam Bowne's Exploit Development class (FREE)](https://samsclass.info/127/127_S20.shtml)
* [List of Corelan.be's exploit development tutorials](https://github.com/FabioBaroni/awesome-exploit-development#corelanbe)

## macOS Security
* [Writing a Process Monitor with Apple's Endpoint Security Framework](https://objective-see.com/blog/blog_0x47.html)
* [Skiptracing Part 1: Reversing Spotify.app](https://medium.com/@lerner98/skiptracing-reversing-spotify-app-3a6df367287d)
* [Skiptracing Part 3: Automated Hook Resolution](https://medium.com/swlh/skiptracing-automated-hook-resolution-74eda756533d)

## Linux Security
[Basic Linux Malware Process Forensics for Incident Responders](https://www.linkedin.com/pulse/basic-linux-malware-process-forensics-incident-craig-rowland)

## Mobile Security
* [Sam Bowne's Hacking Mobile Devices class (FREE)](https://samsclass.info/128/128_S20.shtml)
* [Mobile Application Penetration Testing Cheat Sheet](https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet)
* [ARM Lab VM](https://azeria-labs.com/arm-lab-vm/)
* [Debugging With Gdb](https://azeria-labs.com/debugging-with-gdb-introduction/)
* [Introduction To Arm Assembly Basics](https://azeria-labs.com/writing-arm-assembly-part-1/)
* [Introduction To Writing Arm Shellcode](https://azeria-labs.com/writing-arm-shellcode/)
### Android Security
* [Android Pentesting CheatSheet](https://blog.dixitaditya.com/android-pentesting-cheatsheet/)
* [Project Zero's Bad Binder](https://googleprojectzero.blogspot.com/2019/11/bad-binder-android-in-wild-exploit.html?m=1)
* [Android App Reverse Engineering 101](https://maddiestone.github.io/AndroidAppRE/)
* [Maddie Stone's REcon 2019 presention: Path To The Payload](https://recon.cx/media-archive/2019/Session.005.Maddie_Stone.The_path_to_the_payload_Android_Edition-J3ZnNl2GYjEfa.mp4)
  * [Slides - REcon 2019: Path To The Payload](https://github.com/maddiestone/ConPresentations/blob/master/REcon2019.PathToThePayload.pdf)
### iOS Security
* [Skiptracing Part 2: iOS](https://medium.com/@lerner98/skiptracing-part-2-ios-3c610205858b)
* [Part 1: Heap Exploit Development](https://azeria-labs.com/heap-exploit-development-part-1/)
* [Part 2: Heap Overflows And The Ios Kernel Heap](https://azeria-labs.com/heap-overflows-and-the-ios-kernel-heap/)
* [A very deep dive into iOS Exploit chains found in the wild](https://googleprojectzero.blogspot.com/2019/08/a-very-deep-dive-into-ios-exploit.html)
### Guides for Mobile Security Tools
* [Getting Started With Objection + Frida](https://www.secjuice.com/objection-frida-guide/)

## Web App Security
* [Security Best Practices for Managing API Access Tokens](https://dzone.com/articles/security-best-practices-for-managing-api-access-to)
* [Common Threats and How to Prevent Them](https://auth0.com/docs/security/common-threats)
* [Attacking the OAuth Protocol](https://dhavalkapil.com/blogs/Attacking-the-OAuth-Protocol/)
* [Top X OAuth 2 Hacks](https://www.owasp.org/images/6/61/20151215-Top_X_OAuth_2_Hacks-asanso.pdf)
* [[FUN] Bypass XSS Detection WAF](https://0x00sec.org/t/fun-bypass-xss-detection-waf/12228)
* [Bypassing Cloudflare WAF with the origin server IP address](https://blog.detectify.com/2019/07/31/bypassing-cloudflare-waf-with-the-origin-server-ip-address/)
* [Cross-site scripting (XSS) cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
* [XS-Leak: Leaking IDs using focus](https://portswigger.net/research/xs-leak-leaking-ids-using-focus)
* [Testing for XSS (Like a KNOXSS)](https://brutelogic.com.br/blog/testing-for-xss-like-a-knoxss/)
* [RCEScanner: Simple python script to extract unsafe functions from php projects](https://github.com/mhaskar/RCEScanner)
* [LiveOverflow Web Hacking](https://www.youtube.com/playlist?list=PLhixgUqwRTjx2BmNF5-GddyqZcizwLLGP)
* [Stealing JWTs in localStorage via XSS](https://medium.com/redteam/stealing-jwts-in-localstorage-via-xss-6048d91378a0)
* [The Ultimate Guide to handling JWTs on frontend clients (GraphQL)](https://dev.to/hasurahq/the-ultimate-guide-to-handling-jwts-on-frontend-clients-graphql-252a)
* [Practical Approaches for Testing and Breaking JWT Authentication](https://mazinahmed.net/blog/breaking-jwt/)


## Incident Response
* [Sam Bown's Incident Response class (FREE)](https://samsclass.info/152/152_F19.shtml)
### macOS IR
* [Investigating Mac OS X Systems](https://www.youtube.com/watch?v=7vVbHCgS0xQ&feature=emb_logo)

## Misc Resources
* [3 Hours of Studying & Creativity Music](https://www.youtube.com/watch?v=ggeQKhwymas&t=10804s)
### Books
* [Lean In: Women, Work, and the Will to Lead ](https://www.amazon.com/Lean-Women-Work-Will-Lead/dp/0385349947/)
* [Expert video series from Lean In](https://leanin.org/education#series)
* [Ask For It: How Women Can Use the Power of Negotiation to Get What They Really Want](https://www.amazon.com/Ask-Women-Power-Negotiation-Really/dp/0553384554/)
* [Quiet Leadership: Six Steps to Transforming Performance at Work](https://www.amazon.com/Quiet-Leadership-Steps-Transforming-Performance/dp/0060835915/)
