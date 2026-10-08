# Coin mining: from CPU outlier to flow duration

Several Frothly endpoints showed signs of cryptocurrency mining. The goal was to find which endpoint actually mined, how the miner got there, and for how long it ran.

## 1. Finding the miner on the endpoint

osquery's `system_profile` query exposes CPU time per host. One host, `mars.i-08e52f8b5a034012d`, was a clear outlier:

```
index=botsv3 earliest=0 sourcetype="osquery:results" name=system_profile
| table hostIdentifier, columns.system_time, columns.user_time, columns.wall_time
| sort - columns.wall_time
```

Process-level CPU data lives in `PerfmonMk:Process`:

```
index=botsv3 earliest=0 sourcetype="PerfmonMk:Process" process_cpu_used_percent=100
| table _time, host, instance, process_cpu_used_percent
| sort + _time
```

On `BSTOLL-L`, Chrome processes hit 100% CPU. The Chrome binary's SHA256 (`268A0463...183F9BCA`) is signed by Google according to VirusTotal, so this was not a malicious binary. That points to a **browser-based miner (CoinHive-style JavaScript)** instead of dropped malware.

## 2. Symantec Endpoint Protection

The `symantec:ep:security:file` sourcetype records the detections. Many events share one `_time`, so I sorted on the event-level `Begin_Time` field to get a true "first seen" order:

```
index=botsv3 earliest=0 sourcetype=symantec:ep:security:file
| table _time, Application_Name, CIDS_Signature_ID, CIDS_Signature_String, Event_Description, Begin_Time
| sort + Begin_Time
```

- Signature IDs `30356` and `30358` appear one second apart at the start of the activity
- `BTUN-L` has Symantec alerts, so its mining attempt was most likely blocked
- By elimination, `BSTOLL-L` is the endpoint where the miner ran

Counting distinct intrusion URLs, with query strings stripped:

```
index=botsv3 earliest=0 jscoinminer
| stats count by Intrusion_URL
| rex field=Intrusion_URL "(?<endpoint>[^\?]+)"
| dedup endpoint
```

This returns 5 distinct endpoints, including `www.brewertalk.com/attachment.php`, the site's own attachment endpoint.

## 3. How long did it mine?

Cisco Network Visibility Module (NVM) flow data is not in its usual sourcetype. A saved search in the app referenced a `pap` field, so I searched the whole index for it and found the flows in `source=cisconvmflowdata`:

```
index=botsv3 earliest=0 pap=* | head 100
```

Listing the domains the user reached showed `coinhive.com` subdomains. Summing flow durations (`fst` = flow start, `fet` = flow end):

```
index=botsv3 earliest=0 source=cisconvmflowdata pap=BudStoll dh=*.coinhive.com
| table fst, fet
| eval start_epoch=strptime('fst', "%c")
| eval end_epoch=strptime('fet', "%c")
| eval difference=(end_epoch-start_epoch)
| stats sum(difference)
```

**Result:** 1,634 seconds, about 27 minutes of connections to CoinHive. Separately, Chrome on `BSTOLL-L` hit 100% CPU in two windows, around 6:37-6:38 AM and 7:59 AM.

## 4. The postmortem email

Bud emailed the whole company a postmortem titled "Postmortem on our issue with brewertalk", with a chart attached to explain the problem. The attachment is base64 encoded inside the SMTP stream data, so I extracted and decoded it:

```
cat base64.txt | base64 -d > ~/Desktop/image.jpg
```

The image shows a Splunk **column chart**.

A field-name gotcha cost me an event here. Filtering on `Subject` returned 12 events but a raw string search returned 13, because `stream:smtp` uses a lowercase `subject` field:

```
index=botsv3 earliest=0 (sourcetype=stream:smtp OR sourcetype=ms:o365:reporting:messagetrace) bstoll@froth.ly
| stats count by Subject
```

The same email also explains the root cause: the public bucket (see [cloud findings](01-cloud-s3-exposure-and-leaked-key.md)) let attackers inject the miner into the site's code.

## 5. The odd one out

To find the endpoint on a different Windows edition, I searched sourcetypes containing "windows" and used `WinHostMon`:

```
index=botsv3 earliest=0 sourcetype=winhostmon "windows 10" OR "windows 7"
| stats count by OS, host
| stats values(host) by OS
```

The Sysmon data supplied the full hostname: **`BSTOLL-L.froth.ly`**.

## Detection ideas (not tested in the lab)

- Alert on browser processes holding sustained 100% CPU
- Alert on DNS or NVM flows to known mining pool and CoinHive domains
- Track Symantec `jscoinminer` detections by host and by site
