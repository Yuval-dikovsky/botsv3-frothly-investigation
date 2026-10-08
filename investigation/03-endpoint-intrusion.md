# Endpoint intrusion: phishing to C2 and lateral activity

The Windows side of the case: how the attackers got in, what they ran, and what they did with access to email and files.

## 1. Initial access

### Malicious shortcut on OneDrive

Searching for malware on OneDrive found a detection by Symantec for `Backdoor.PsEmpire` on a `.lnk` file named *Bruce Birthday Happy Hour Pics.lnk* in Bruce Gist's OneDrive:

```
index=botsv3 earliest=0 onedrive (malicious OR virus)
```

The upload audit trail comes from the O365 management logs. Sorting oldest-first with `reverse` shows the `FileUploaded` event:

```
index=botsv3 earliest=0 "Bruce Birthday Happy Hour Pics.lnk" | reverse
```

The uploader's user agent claims to be **NaenaraBrowser** on Linux with a Korean locale. A user agent is client-supplied, so it is weak attribution evidence and easy to fake.

Counting how widely the link was used:

```
index=botsv3 earliest=0 Operation=AnonymousLinkUsed sourcetype="ms:o365:management"
| stats dc(ClientIP)
```

The link was used from **7 unique IP addresses**.

### Macro-enabled spreadsheet

A phishing email asked recipients to enable macros in a financial planning worksheet. The mail gateway's alert attachment (*Malware Alert Text.txt*) is base64 encoded, and decoding it names the file and the threat:

```
Malware was detected in one or more attachments included with this email message.
Action: All attachments have been removed.
Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm	 W97M.Empstage
```

Symantec removed the document, so the macro's payload was never observed. Sysmon file-creation events for the `.xlsm` show it written by `HxTsr.exe`, the Outlook attachment-cache component, which marks the delivery chain:

```
index=botsv3 earliest=0 sysmon *.xlsm
```

### Expired account

An Azure AD sign-in event for an expired account came from `199.66.91.253`. The event itself shows a failed sign-in, so this is an indicator to watch, not proof of access.

## 2. Execution and command and control

The PowerShell Operational log holds script-block text. Filtering out console noise cut the data from 90 events to 11, and a regex pulled the URI the script builds:

```
index=botsv3 earliest=0 source="WinEventLog:Microsoft-Windows-PowerShell/Operational" Message!="PowerShell console*" Message="*/*"
| rex field=Message "\$t\=[\'\"](?<c2_uri>[^\'\"]+)"
| table c2_uri
| dedup c2_uri
```

The C2 path was **`/admin/get.php`**. The script assembles the full URL from a base64 string, which decodes to the server:

```
$ echo 'aAB0AHQAcABzADoALwAvADQANQAuADcANwAuADUAMwAuADEANwA2ADoANAA0ADMA' | base64 -d
https://45.77.53.176:443
```

Because the channel is HTTPS, the URI never appears in network logs. To find which hosts beaconed, I pivoted on the server IP in Sysmon network events:

```
index=botsv3 earliest=0 DestinationIp=45.77.53.176 source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count by host
```

**Beaconing hosts:** `ABUNGST-L` and `FYODOR-L`.

### Tool download

To find how the attackers fetched their tools, I looked for rare destination ports in the Stream data:

```
index=botsv3 earliest=0 sourcetype=stream:* protocol_stack!=*udp*
| rare dest_port
```

Port **3333** stood out: a PowerShell user agent downloading `/images/logos.png`, an unusual file for a PowerShell client to request. The image name was disguising the tool payload.

## 3. Persistence on FYODOR-L

A search for user-creation activity, filtered for noise, found a `net user /add` on `FYODOR-L`:

```
index=botsv3 earliest=0 "add" "user" NOT "Network Connected Devices Auto-Setup" NOT ec2-user sourcetype!="stream:mysql"
```

The new account is **`svcvnc`**, and Security EventCode 4732 shows it added to two local groups:

```
index=botsv3 earliest=0 svcvnc EventCode=4732
```

**Groups:** Administrators and Users. The account's password was visible in the process command line in Sysmon, which is a reminder of why command-line logging matters.

## 4. Discovery: the scanner

Scanning shows up as one process reaching many ports. Counting distinct destination ports per image on `FYODOR-L` isolated one program:

```
index=botsv3 earliest=0 host="FYODOR-L" source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats dc(DestinationPort) as DestinationPortDistinctCount by host, Image
| sort - DestinationPortDistinctCount
```

The program was `C:\Windows\Temp\hdoor.exe`, with MD5 `586ef56f4d8963dd546163ac31c865d7`. Running from the Temp directory is already suspicious.

## 5. Email and data access

The attackers worked inside Office 365:

- **Forwarding rule.** A `New-TransportRule` operation created a rule named **`SOX`** that BCC'd company mail to an outside address:
  ```
  index=botsv3 earliest=0 sourcetype=ms:o365:management Operation="New-TransportRule"
  ```
- **SharePoint searches.** `SearchQueryPerformed` events show what they looked for: `cromdale OR beer OR financial OR secret`. The events came from `104.47.0.0/16`, the netblock behind Frothly's Office 365 mail hosts (taken from the MX record), found with CIDR matching:
  ```
  index=botsv3 earliest=0 src_ip=104.47.0.0/16 source=https*
  ```
- **Account disabled.** Azure AD logs show `bgist@froth.ly` disabled, with `fyodor@froth.ly` as the acting user, which fits the attackers working through a compromised account.
- **Data theft.** The attackers emailed Grace Hoppy, boasting about stolen customer data. The linked paste contained **8 customer email addresses**.

## Detection ideas (not tested in the lab)

- Alert on `New-TransportRule` and `New-InboxRule` creation
- Alert on `AnonymousLinkUsed` from many distinct IPs
- Flag executables running from `C:\Windows\Temp` that make many outbound connections
- Alert on `net user /add` followed by 4732 group changes
- Alert on PowerShell downloading image files from non-standard ports
