# Keylogger
Keyloggers are a particularly insidious type of spyware that can record and steal the user's keystrokes on a device. They are Software that logs what you type on your keyboard.

# Sample overview

md5 : A7F21E412022554D187D6A876A3C08AC

sha1 : 70E39BDFCAA4BCF0021311E8298266E527CF7C97

sha256 : 9B683D2FDA7CA7ADCC043E4412271009A0E115CA55F9A718C385A3F46B57AE6B
### Virustotal
<img src="https://user-images.githubusercontent.com/84356407/178140235-94f78b7c-d6af-4a86-8975-8d7c35f68f69.png" width="600">

### Unpacked
This sample is unpacked. It was checked by DIE & EXEINFO & PEID

<img src="https://user-images.githubusercontent.com/84356407/178139617-b804e8bc-074d-428c-b6c2-3a4c09c9e44e.png" width="600">
### Strings
<img src="https://user-images.githubusercontent.com/84356407/178142954-278e5f6b-ff1f-4ab0-80c9-dd0d1a3b0c67.png" width="100">

# How it works?



# Conclusion 

Malware declares all settings **AES256** then trying to connect victim machine to C2 server. From this point, all commands come from the other end of the world through the C2 server which were not embedded in the code.

Finally, I hope you had fun and learned something new. See you in another analysis report.

[![](/assets\images\malware-analysis\asyncRAT\CU.jpg)](/assets\images\malware-analysis\asyncRAT\CU.jpg)



# IOCs

#### Hashes

Packed: 8021f8aa674ce3a2ccb2e8f917ebaf5b638607447f0df0e405e837dd2e7a7ccd

Unpacked: bc61724d50bff04833ef13ae13445cd43a660acf9d085a9418b6f48201524329

#### C2s

jeazerlog.duckdns.org:6606

jeazerlog.duckdns.org:7707

jeazerlog.duckdns.org:8808

#### MUTEXs

AsyncMutex_6SI8OkPnk

#### REGs

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run


