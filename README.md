[![Build](https://img.shields.io/badge/Supported_OS-OSX-orange.svg)]()
![](https://img.shields.io/badge/platform-OSX%20%7C%20Linux%20%7C%20KaliLinux%20%7C%20ParrotOs-blue)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-blue.svg?style=flat)]()
![](https://img.shields.io/badge/Python-3-blue)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/JesseRubio/PacketSniffer/)
[![Open Source Love svg1](https://badges.frapsoft.com/os/v1/open-source.svg?v=103)](https://github.com/ellerbrock/open-source-badges/)

# Packet Sniffer Tool

PacketSniffer is a python tool that can sniff packets on any interface and extract sensitive information like Usernames and Passwords along with the server IP, TCP Seq, cookies, referers etc. It has been written for Python3 and uses Scapy.

## Prerequisites

Install _scapy_ using

```
sudo pip install scapy
```

### Installation
1. **git clone this repo**
2. ***cd PacketSniffer*** 
3. **python3 PacketSniffer.py**

![image](https://user-images.githubusercontent.com/70275323/116866005-4b7bb580-ac28-11eb-8a5a-00832d650baf.png)

Entering ```1``` will show the results of ```ifconfig``` that can be used to select the interface.

Entering ```2``` will prompt you into entering the info and verbosity and will start the actual sniffing

![image](https://user-images.githubusercontent.com/70275323/116866105-76fea000-ac28-11eb-8028-0e4c7fd151db.png)

Recommended Verbosity levels are ```3``` and ```4``` they display most of the import information. 

However, if you need even more information, feel free to examine the entire packet using verbosity ```5```

As an example, I've used [Vulnhub Login Page](testphp.vulnweb.com/login.php) to demonstrate the use of this script.
Type the following address to your address bar "test.php.vulnweb.com/login.php" to view the test page.

![image](https://user-images.githubusercontent.com/70275323/116866516-263b7700-ac29-11eb-9b19-f80b7c82ae44.png)

To change interfaces, or exit out of the script, press ```Ctrl + C``` or ```cmd + c``` for macOS

This will bring you back to the initial prompt where you can choose to open ifconfig, sniff, or exit.

![image](https://user-images.githubusercontent.com/70275323/116867471-e7a6bc00-ac2a-11eb-9e7a-6d99f55dd53e.png)

#### Final Words

I've learnt a lot while I was writing this and one of the things i've learnt to do is reading the docs. The scapy docs are huge and the module itself has a large amount of things that can be done. Selecting the correct class and using the correct keywords in case of Scapy wasnt like other modules i've used so far where it was as simple as typing a letter and letting autocomplete do the rest of the job. 

Reading the docs, understanding how modules work, and understanding how packets are crafted is something i wouldn't have learnt out of a textbook, and getting hands on experience using this knowledge was invaluable.

Thanks again

***do not use for illegal activities***
