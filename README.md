# Splunk BOTSv3: Frothly Breach Investigation

A hands-on investigation of the **Boss of the SOC v3 (BOTSv3)** dataset in a self-built Splunk Enterprise lab. The scenario is a fictional brewery, **Frothly**, attacked by a threat actor called **Taedonggang**. The case spans AWS, Office 365 / Azure AD, Windows endpoints and a Linux web server, so the work covers both cloud and on-prem investigation.

This is a write-up of my own analysis of a public training dataset. It is not official Splunk material, and no real systems were involved.

## What this repo shows

- Reconstructing an attack chain across **cloud, email, endpoint and network** telemetry
- Writing SPL for investigation and hunting: `rex` extraction, `stats`/`eventstats`, `rare`, CIDR matching, timestamp maths, statistical outliers
- Reading **CloudTrail, Sysmon, Windows Security/PowerShell logs, osquery, Symantec EP, Cisco ASA/NVM, Splunk Stream and O365/Azure AD** logs
- Decoding base64 payloads found inside log data (email attachments, PowerShell stagers)
- Mapping findings to **MITRE ATT&CK** and proposing detections

## Environment

| | |
| --- | --- |
| SIEM | Splunk Enterprise, self-hosted lab (Linux VM on KVM/QEMU) |
| Dataset | BOTSv3, `index=botsv3` (1M+ events, 107+ sourcetypes) |
| Key sourcetypes | `aws:cloudtrail`, `XmlWinEventLog` Sysmon, `WinEventLog:Security`, PowerShell Operational, `osquery:results`, `symantec:ep:*`, `cisco:asa`, `stream:*`, `ms:o365:management`, `ms:aad:signin` |

## Attack chain at a glance

| Stage | What happened | Main evidence | ATT&CK |
| --- | --- | --- | --- |
| Initial access | A malicious `.lnk` was shared through OneDrive and opened via an anonymous link from 7 IPs. A macro-enabled `.xlsm` lure was emailed and removed by Symantec (W97M.Empstage). | O365 management logs, Symantec EP, Sysmon | T1566, T1204.002 |
| Execution and C2 | PowerShell Empire stagers beaconed over HTTPS to `45.77.53.176:443` from two hosts. | PowerShell script-block logs, Sysmon network events | T1059.001, T1071.001 |
| Tooling | Attack tools were pulled over a non-standard port (3333) disguised as `logos.png`. | Splunk Stream | T1105 |
| Persistence | A local admin account `svcvnc` was created and added to Administrators. | Security 4732, Sysmon | T1136.001 |
| Discovery | `hdoor.exe` ran from `C:\Windows\Temp` and scanned the network. | Sysmon (distinct destination ports) | T1046 |
| Email and data access | A BCC transport rule (`SOX`) was created, SharePoint searches ran, and customer data was posted publicly. | O365 management logs | T1114.003, T1213.002 |
| Linux compromise | Apache Struts RCE on `hoth`, then kernel privilege escalation to root, history deleted, data archived. | osquery, Splunk Stream | T1190, T1068, T1070.003, T1560.001 |
| Cloud exposure | An S3 bucket was made public by an IAM user. Files were uploaded while it was open. | CloudTrail, S3 access logs | misconfiguration |
| Leaked AWS key | A key committed to a public repo was used for IAM and EC2 attempts in 15 regions. | CloudTrail, AWS notification email | T1552.001, T1078.004, T1098.001 |
| Coin mining | A browser-based miner (CoinHive) ran on one endpoint. Symantec blocked it on others. | Symantec EP, Perfmon, Cisco NVM flows | T1496 |
| Brute force | Failed SSH logins against the web servers from IPs geolocating to Russia. | `linux_secure` | T1110 |

## Investigation write-ups

1. [Cloud: public S3 bucket and leaked AWS key](investigation/01-cloud-s3-exposure-and-leaked-key.md)
2. [Coin mining: from CPU outlier to flow duration](investigation/02-coin-mining.md)
3. [Endpoint intrusion: phishing to C2 and lateral activity](investigation/03-endpoint-intrusion.md)
4. [Linux web server `hoth`: Struts RCE to root](investigation/04-linux-host-hoth.md)
5. [Hunting techniques: the reusable queries](investigation/05-hunting-techniques.md)
6. [Indicators of compromise](iocs.md)

## Open items

Where my results did not fully match the reference answers, or I could not finish:

- **First process to hit 100% CPU:** by timestamp it was an Edge process; the miner itself ran in Chrome. CPU alone does not tell which process was mining.
- **Mining destinations:** 5 distinct Symantec intrusion URLs after stripping parameters; the reference count differs, and I could not work out why.
- **Mining duration:** 1,634 seconds summed from flows to `*.coinhive.com`; the reference value is slightly higher.
- **First coin-miner signature:** two signatures fall within a second of each other, so the "first seen" one depends on which timestamp is used.
- **Memcached exposure:** I found the exposure and external UDP traffic on port 11211, but did not recover the defacement payload.

## Credits

BOTSv3 is published by Splunk. The beacon-hunting approach for the C2 analysis follows Jack Crook's [Hunting for Beacons, Part 2](http://findingbad.blogspot.com/2020/05/hunting-for-beacons-part-2.html).
