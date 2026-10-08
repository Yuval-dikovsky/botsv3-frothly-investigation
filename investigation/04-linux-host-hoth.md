# Linux web server `hoth`: Struts RCE to root

The attackers compromised an on-premises Linux web server and escalated to root. This was reconstructed almost entirely from **osquery** process and file-integrity data.

## 1. Initial foothold: remote code execution

The `tomcat8` service account suddenly started running reconnaissance commands (`whoami`, `cat /etc/passwd`). To see how, I excluded root activity and listed everything else on the host:

```
index=botsv3 sourcetype=osquery:results hostIdentifier=hoth columns.uid!=0
| table _time,name,columns.cmdline, columns.command, columns.uid, columns.username, columns.target_path, hostIdentifier
| sort + _time
```

Then I searched for the first `whoami` in a tight window before the activity began:

```
index=botsv3 host=hoth whoami earliest=1534762800 latest=1534763160
```

A single event shows the command arriving over HTTP, in a request for **`saveGangster.action`**. That path points to an Apache Struts REST plugin exploit: **CVE-2017-9791**.

## 2. Privilege escalation to root

The osquery process data shows someone compiling and running exploit code. The `columns.uid` value changes from 111 (`tomcat8`) to 0 (root):

```
index=botsv3 earliest=0 tomcat8 sourcetype!=ps sourcetype!=top sourcetype!=lsof name!=largest_process
| table _time,name,columns.cmdline, columns.command, columns.uid, columns.username, columns.target_path
| sort + _time
```

The chain, rebuilt from file and process events:

`/tmp/colonel` (base64) -> decoded to `/tmp/colonel.c` -> compiled to `/tmp/colonelnew` -> run as root

The earliest reference to `colonel.c` appears in `WinEventLog:Security`, where the base64 content echoed into the file can be decoded. The decoded source is an exploit whose second comment line reads `Ubuntu 16.04.4 kernel priv esc`. Matching pieces of the code against Exploit-DB identified **CVE-2017-16995**, a Linux kernel flaw.

## 3. Files staged on the host

Filtering out the noisy sourcetypes, osquery's file-integrity events show what the attackers dropped in `/tmp`:

```
index=botsv3 earliest=0 /tmp/*.* sourcetype!=ps sourcetype!=lsof NOT phpsessionclean
```

Two files were streamed in as large base64 blobs:

- `colonel`
- `definitelydontinvestigatethisfile.sh`

A logged command, `tar czvf blargh.tgz suitecrm.sql loot.txt`, bundles `suitecrm.sql` and `loot.txt` into one archive, which looks like staging for exfiltration. The attacker also deleted `/usr/share/tomcat8/.bash_history`; the timing suggests the privilege escalation happened before that point.

## 4. Listening backdoor

osquery's `listening_ports` data shows one process listening on a "leet" port (1337 or 31337):

```
index=botsv3 earliest=0 sourcetype=osquery:results name=*port* (31337 OR 1337)
```

**PID 14356.**

## 5. Credentials in the command line

A user created by `root` shows its password in the logged `useradd`/`adduser` command line:

```
index=botsv3 earliest=0 (useradd OR adduser) (root OR uid=0)
```

Command-line auditing recorded the password in clear text. That helps the investigation, but also means any reader of those logs sees secrets.

## 6. SSH brute force against the web servers

Failed SSH logins against the `gacrux` hosts show a small brute-force attempt from two source IPs:

```
index=botsv3 earliest=0 sourcetype=linux_secure "invalid user" from host=gacrux*
| top src
| iplocation src
```

The source IPs geolocate to **Russia**. Web-application logs showed nothing, because the attempts targeted the SSH service on the hosts and not the site itself.

## Detection ideas (not tested in the lab)

- Alert on a web-server service account (`tomcat8`) spawning shells or running `whoami`
- Alert on `gcc` compilation or execution from `/tmp`
- Alert on a UID change from a service account to 0
- Alert on deletion of `.bash_history`
- Alert on new listening ports on 1337 or 31337
