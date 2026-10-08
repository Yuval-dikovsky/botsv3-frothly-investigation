# Indicators of compromise

All indicators come from the public BOTSv3 training dataset. The AWS access key ID is masked, and no passwords or secret keys are reproduced.

## Network

| Indicator | Context |
| --- | --- |
| `45.77.53.176:443` | PowerShell Empire C2 server (HTTPS) |
| `/admin/get.php` | C2 URI built by the PowerShell stager |
| Port `3333`, `/images/logos.png` | Attack tool download disguised as an image |
| `199.66.91.253` | Azure AD sign-in event for an expired account |
| `13.125.33.130` | External UDP traffic to memcached (port 11211) |
| `coinhive.com` subdomains | Browser-based Monero miner |

## Files and hashes

| Indicator | Context |
| --- | --- |
| `Bruce Birthday Happy Hour Pics.lnk` | Malicious shortcut on OneDrive, detected as `Backdoor.PsEmpire` |
| `Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm` | Macro lure, detected as `W97M.Empstage` |
| `hdoor.exe`, MD5 `586ef56f4d8963dd546163ac31c865d7` | Network scanner dropped in `C:\Windows\Temp` |
| `/tmp/colonel`, `colonel.c`, `colonelnew` | Linux kernel exploit (CVE-2017-16995) |
| `/tmp/definitelydontinvestigatethisfile.sh` | Staged script on `hoth` |
| `/tmp/blargh.tgz`, `loot.txt`, `suitecrm.sql` | Collected data archive on `hoth` |
| `OPEN_BUCKET_PLEASE_FIX.txt` | Note uploaded to the public bucket |
| `frothly_html_memcached.tar.gz` | 2.93 MB archive uploaded to the public bucket |

## Accounts and rules

| Indicator | Context |
| --- | --- |
| `svcvnc` | Backdoor local administrator created on `FYODOR-L` |
| `bgist@froth.ly` | Account disabled during the attack (by `fyodor@froth.ly`) |
| `web_admin` | IAM user targeted with the leaked key |
| `AKIAJOGC****XUPA` | Leaked AWS access key ID |
| `SOX` | Malicious BCC transport rule |

## Cloud and application

| Indicator | Context |
| --- | --- |
| `frothlywebcode` | S3 bucket made public |
| `ElasticWolf/5.1.6` | User agent on the attacker's `GetUser` call |
| `NaenaraBrowser/3.5b4` string | User agent on the malicious file upload (likely spoofed) |
| `saveGangster.action` | Struts exploit path against `hoth` (CVE-2017-9791) |
| `cromdale OR beer OR financial OR secret` | Attacker SharePoint search terms |

## Affected hosts

`ABUNGST-L`, `FYODOR-L`, `BSTOLL-L` (miner), `hoth` (Linux, root compromise), `gacrux` hosts (SSH brute force)
