# Brute-Force-Threat-hunt

## Introduction

### During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources.

<br><hr><br>
## Step 1 — Search for failed logins

***Query used:*** <br>

DeviceLogonEvents
| where DeviceName contains "windows-target"
| where ActionType == "LogonFailed"
| summarize FailedAttempts= count() by RemoteIP
| order by FailedAttempts desc

<br>
<img width="1325" height="897" alt="So many Brute force attempts" src="https://github.com/user-attachments/assets/ce10e3ed-25a9-453e-90f9-6c90ae65adef" />
<br>

<br><hr><br>
## Step 2 — Narrow down the search

I altered the search to limit the time scope to 7 days and to provide the number of failed logon attempts and a list of the different AccountNames the real bad actor tried to login as

***Query used:*** <br>
DeviceLogonEvents
| where Timestamp > ago(7d)
| where DeviceName contains "windows-target"
| where ActionType == "LogonFailed"
| summarize FailedAttempts=count(),
            TargetedAccounts=dcount(AccountName),
            Accounts=make_set(AccountName)
            by RemoteIP
| order by FailedAttempts desc
<br>
<img width="1406" height="921" alt="Bruite Force attempts in last 7 days by Account Name and number of attempts" src="https://github.com/user-attachments/assets/e6898db8-cf4c-4ae0-8757-be28c37cc541" />
<br>

<br><hr><br>
## Step 3 — Check for any successful logon attempts after failed logon attempts

We used the ***join*** to join two datasets... It's like the middle part of a Venn Diagram and will only include info found in both datasets... In this case there were no successful logon attempts after failed ones so there were no results.

***Query used:*** <br>
let Failed =
DeviceLogonEvents
| where Timestamp > ago(7d)
| where DeviceName contains "windows-target"
| where ActionType == "LogonFailed"
| summarize FailedAttempts=count() by RemoteIP, AccountName;
let Success =
DeviceLogonEvents
| where Timestamp > ago(7d)
| where DeviceName contains "windows-target"
| where ActionType == "LogonSuccess";
Failed
| join kind=inner Success on RemoteIP, AccountName
| project RemoteIP, AccountName, FailedAttempts
| order by FailedAttempts desc

<br>
<img width="1201" height="880" alt="No successful logon to the Windows VM after Brute Force attempt" src="https://github.com/user-attachments/assets/bd1b76cc-7213-4391-b9de-a3c01ba3b743" />
<br>

<br><hr><br>
## Conclusion

In this Threat Hunt we tested our hypothesis that during the time this VM was exposed to the internet someone might have gained access through Brute Force Logins. Luckily no one gained access to the VM and we created a detection rule to alert us in the future. Super strong passwords that are not used on other accounts such be required to combat against Brute Force logons. 
