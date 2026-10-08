# Cloud: public S3 bucket and leaked AWS key

Two linked cloud incidents in Frothly's AWS account: an S3 bucket made public by mistake, and an access key leaked to a public code repository.

## 1. Scoping the AWS environment

CloudTrail carries the account ID in `recipientAccountId`. One account appears across the data, which gives a reliable pivot for everything that follows.

```
index=botsv3 earliest=0 recipientAccountId
| stats count by recipientAccountId, sourcetype
```

Enumerating the IAM users that touched the account (field names are case sensitive):

```
index=botsv3 earliest=0 sourcetype=aws:cloudtrail 622676721278
| stats count by userIdentity.userName
```

**Users seen:** `bstoll`, `btun`, `splunk_access`, `web_admin`.

## 2. Detecting API activity without MFA

The documented filter, `additionalEventData.MFAUsed`, only appears on console sign-in events, so it misses most API calls. Searching every event for the string "mfa" and reading the field list found the better one:

```
index=botsv3 earliest=0 sourcetype=aws:cloudtrail *mfa*
```

**Field to alert on:** `userIdentity.sessionContext.attributes.mfaAuthenticated`.

## 3. The bucket made public

A search for Bud Stoll's name identified the user `bstoll`. Searching bucket ACL and policy activity returned only `GetBucketPolicy` and `GetBucketAcl`, which are read-only, so I listed all of his `put*` calls instead:

```
index=botsv3 earliest=0 bstoll eventName=put*
| stats count by eventName
```

He applied two different bucket ACLs. Inspecting the `AccessControlList` for the group `http://acs.amazonaws.com/groups/global/AllUsers` showed which call opened the bucket.

| | |
| --- | --- |
| Bucket | `frothlywebcode` (`requestParameters.bucketName`) |
| Public from | 2018-08-20T13:01:46Z |
| Event ID of the change | `ab45689d-69cd-41e7-8705-5350402cf7ac` |

## 4. What was uploaded while it was public

S3 access logs show uploads as `REST.PUT.OBJECT`:

```
index=botsv3 earliest=0 frothlywebcode "*.txt"
```

- `OPEN_BUCKET_PLEASE_FIX.txt`: a text file whose name flags the open bucket
- `frothly_html_memcached.tar.gz`: **2.93 MB**, uploaded after the bucket went public

```
index=botsv3 earliest=0 frothlywebcode "*.tar.gz" operation="REST.PUT.OBJECT" http_status=200
| table object_size
| eval mb=round(object_size/1024/1024,2)
```

The internal postmortem email (see [coin mining](02-coin-mining.md)) explains the impact: the open bucket let attackers modify the website's code and inject a coin miner.

## 5. Web server launches (cloud-init)

New auto-scaled web servers configure themselves through cloud-init. The summary line in the output log gives the package counts directly:

```
index=botsv3 earliest=0 source=/var/log/cloud-init-output.log packages dependent
| rex field=_raw "Install\s+(?<packages>[\d]+)\s+Packages\s+\(\+(?<dependencies>[\d]+)\sDependent\spackages\)"
| table _raw, packages, dependencies
```

**Result:** 7 packages plus 13 dependent packages installed.

## 6. The leaked access key

Bud committed AWS access keys to a public code repository. AWS emailed him, and the email contains the support case and the GitHub commit link.

```
index=botsv3 earliest=0 (sourcetype=stream:smtp OR sourcetype=ms:o365:reporting:messagetrace) "access key"
```

Next I looked for the key that caused the most distinct errors against IAM. Counting distinct `errorCode` values gave a three-way tie, but distinct `errorMessage` values restricted to IAM gave a clear outlier, and it matched the leaked key:

```
index=botsv3 earliest=0 sourcetype="aws:cloudtrail" *error* eventSource=iam.amazonaws.com
| stats dc(errorMessage) as distinct_error_messages by userIdentity.accessKeyId
| sort - distinct_error_messages
```

### What the adversary did with it

Everything below is filtered on the leaked key's access key ID (masked here as `AKIAJOGC****XUPA`) and the user `web_admin`.

| Action | Event | Detail |
| --- | --- | --- |
| Create a new key | `CreateAccessKey` (IAM) | Denied; the error message names the target resource `nullweb_admin` |
| Describe the account | `GetUser` (IAM) | User agent `ElasticWolf/5.1.6`, an AWS management client |
| Launch an Ubuntu instance | EC2 `RunInstances` | Attempted in **15 regions**, one AMI per region |

The AMI IDs differ by region even for the same image, so I resolved one with the AWS CLI to identify the operating system:

```
$ aws ec2 describe-images --image-ids ami-4d46d534 --region=eu-west-1
...
"Description": "Canonical, Ubuntu, 16.04 LTS, amd64 xenial image build on 2018-01-09"
```

The image the attacker tried to launch was **Ubuntu 16.04 LTS (Xenial Xerus)**.

## Detection ideas (not tested in the lab)

- Alert on `userIdentity.sessionContext.attributes.mfaAuthenticated="false"` for privileged API calls
- Alert on `PutBucketAcl` / `PutBucketPolicy` that grants `AllUsers`
- Alert on bursts of IAM `AccessDenied` errors from a single access key
- Alert on `RunInstances` attempts across many regions from one key
- Flag unfamiliar user agents on IAM calls
