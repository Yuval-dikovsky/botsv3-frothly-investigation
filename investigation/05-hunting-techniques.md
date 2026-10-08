# Hunting techniques: reusable queries

Queries from the investigation that are useful beyond this dataset. Each one says what it finds and why it works.

## Find which process connects to the most ports (scan detection)

A scanner reaches many destination ports. Counting distinct ports per process image surfaces it quickly.

```
index=botsv3 earliest=0 host="FYODOR-L" source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats dc(DestinationPort) as DestinationPortDistinctCount by host, Image
| sort - DestinationPortDistinctCount
```

## Rarest destination ports (non-standard channels)

Tool downloads and C2 often use unusual ports. `rare` shows the least common values.

```
index=botsv3 earliest=0 sourcetype=stream:* protocol_stack!=*udp*
| rare dest_port
```

## Extract a C2 URI from PowerShell script blocks

Script-block logging records what the script builds, even when the traffic is HTTPS.

```
index=botsv3 earliest=0 source="WinEventLog:Microsoft-Windows-PowerShell/Operational" Message!="PowerShell console*" Message="*/*"
| rex field=Message "\$t\=[\'\"](?<c2_uri>[^\'\"]+)"
| table c2_uri
| dedup c2_uri
```

## Find large base64 blobs hidden in logs

Payloads are often delivered or echoed as base64. A length-based regex finds them, and sorting by length puts the biggest first.

```
index=botsv3 earliest=0 NOT gawk NOT awk sourcetype!="aws:cloudtrail" sourcetype!=stream:smtp
| regex _raw="[A-Za-z0-9+\/\=]{500}"
| eval elength=len(_raw)
| table elength, sourcetype, source, _raw
| sort - elength
```

## Statistical outliers with the IQR upper fence

Process-creation counts per host are a good baseline. A host above `Q3 + 1.5 x IQR` is worth a look.

```
index=botsv3 earliest=0 EventCode=4688
| stats count by host
| eventstats perc75(count) as p75 perc25(count) as p25
| eval IQR=p75-p25
| eval upperFence=(p75+IQR*1.5)
```

The upper fence over the whole day was **1,368** events per host, across 7,427 total 4688 events.

## Measure ingestion lag

Detection is only as fast as the data arrives. This measures the gap between event time and index time per sourcetype.

```
index=botsv3 earliest=0 sourcetype=ms:aad:signin
| eval indextime=strftime(_indextime,"%Y-%m-%d %H:%M:%S")
| eval time=strftime(_time,"%Y-%m-%d %H:%M:%S")
| eval indextime_epoch=strptime(indextime,"%Y-%m-%d %H:%M:%S")
| eval time_epoch=strptime(time, "%Y-%m-%d %H:%M:%S")
| eval delta=indextime_epoch-time_epoch
| stats max(delta) as max_lag
| eval minutes=max_lag / 60
```

Maximum lag for Azure AD sign-ins was **51 minutes**, which matters when writing time-sensitive alerts.

## Extract a username from a firewall teardown log

Cisco ASA teardown events carry the VPN username in trailing parentheses, so it isn't extracted by default. A regex recovers it and bytes can be summed per user.

```
index=botsv3 earliest=0 sourcetype="cisco:asa" action=teardown "\("
| rex field=_raw "\((?<username>[^\)]+)"
| stats sum(bytes) as sum_bytes by username
| sort - sum_bytes
```

## Average length of distinct subdomains (DNS)

Long, random subdomains can indicate tunneling. The `dedup` matters: averaging every query instead of distinct subdomains gives a wrong answer.

```
index=botsv3 earliest=0 source=lambda:dns *.brewertalk.com
| rex field=_raw "Z149R7NEBZTKPN\s(?<query>[^\s]+)"
| rex field=query "\.?(?<third_level_subdomain>[^\.]+).brewertalk.com"
| dedup third_level_subdomain
| eval subdomain_length=len(third_level_subdomain)
| stats avg(subdomain_length)
```

Average length of distinct third-level subdomains: **8.10** characters.

## Sum flow durations to a domain

Turns flow start and end times into total connection time to a suspicious domain.

```
index=botsv3 earliest=0 source=cisconvmflowdata pap=BudStoll dh=*.coinhive.com
| table fst, fet
| eval start_epoch=strptime('fst', "%c")
| eval end_epoch=strptime('fet', "%c")
| eval difference=(end_epoch-start_epoch)
| stats sum(difference)
```

## Pull counts out of a summary line

When a log has a summary line, regex it instead of counting individual lines.

```
index=botsv3 earliest=0 source=/var/log/cloud-init-output.log packages dependent
| rex field=_raw "Install\s+(?<packages>[\d]+)\s+Packages\s+\(\+(?<dependencies>[\d]+)\sDependent\spackages\)"
| table _raw, packages, dependencies
```

## Habits worth keeping

- **Always scope by index first**, then sourcetype, then fields.
- **Field names differ between sourcetypes.** `Subject` and `subject` are different fields, and a field filter silently drops events from the other sourcetype.
- **Sysmon XML may need `rex`.** If a sourcetype has no extractions, use `rex` with `Data Name='FieldName'>` patterns to pull fields out.
- **Several events can share one `_time`.** Sort on an event-level time field to get true order.
- **Ambiguous question, ambiguous data.** State the interpretation you chose and why.
