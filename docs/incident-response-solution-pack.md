<h1 style="font-size:2rem;">FortiSOAR Incident Response Solution Pack – Out-of-the box Playbooks Collections</h1>

The FortiSOAR™ Incident Response Solution Pack (FSR-IR-SOLUTION-PACK or Solution Pack) provides you with a snapshot of the configuration data and other items that can help you to optimally use and experience FortiSOAR’s incident response.

This article provides a listing and brief description of the various types of playbook collections included in the Solution Pack. You can use the playbooks to perform various operations used to automate security processes across your organization. These playbooks can also be used to simulate use cases and provide training for FortiSOAR.

The following playbooks are categorized based on the type of functions they perform such as ingestion, enrichment, triaging, etc. 

- [Enrich Playbook Collection](#enrich-playbook-collection)
- [Triaging Playbook Collection](#triaging-playbook-collection)
- [Use Cases Playbook Collection](#use-cases-playbook-collection)
- [Actions Playbook Collection](#actions-playbook-collection)
- [Hunt Playbook Collection](#hunt-playbook-collection)
- [ChatOps Playbook Collection](#chatops-playbook-collection)
- [Case Management Playbook Collection](#case-management-playbook-collection)
- [Incident Response Playbook Collection](#incident-response-playbook-collection)
- [Utilities Playbook Collection](#utilities-playbook-collection)
- [Demo Playbook Collection](#demo-playbook-collection)
- [Training Playbook Collection](#training-playbook-collection)
- [Communication Playbook Collection](#communication-playbook-collection)
- [Hunt - Sunburst Playbook Collection](#hunt---sunburst-playbook-collection)

# Enrich Playbook Collection
You can use the playbooks in the *02-Enrich* collection to perform enrichment of data, which is one of the first incident response tasks. Automating data enrichment tasks help to better manage increasing volumes of threats and provide more actionable context to the analysts. An example of an enrichment type playbook would be retrieving the reputation of a file, domain, URL, etc. from threat intelligence platforms such as Anomali ThreatStream and VirusTotal.

I. Following is a table that lists the playbooks that are part of the **“02-Enrich”** collection in the Solution Pack:

|**SN**|**Playbook Name**|**Description**|
| :- | :- | :- |
|**1**|Asset - Get Running Process|Retrieves a list of all processes that are running on the specified host.|
|2|Attachment - Get File Reputation|Retrieves the reputation of a file that is submitted from FortiSOAR to VirusTotal.|
|3|Create Indicators (Batch)|Creates indicator records in bulk. |
|4|Extract Indicators|Extracts and creates indicators from the specified data and then enriches specific fields in alerts with the indicator data.|
|5|Extract Indicators - Manual|Extracts and creates indicators from the specified alert records and then enriches specific fields in alerts with the indicator data.|
|6|Fotinet Fortisandbox (Get Reputation) - Get Scan Results|Retrieves the job verdict details for submitted samples based on the specified job ID.|
|7|Get Related IOCs For An IP|Retrieves related IOCs for a specified IP address from threat intel sources.|
|8|Get Reputation After Specified Time|Re-enriches indicators after a specified time.|
|9|Indicator (Manual Trigger)  - Get Latest Reputation|Retrieves the reputation of indicators using configured threat intelligence tools. You can trigger this playbook by manually selecting the indicator(s). |
|10|Indicator (Type All) - Get Latest Reputation|Based on the type of indicator, this playbook retrieves the reputation of indicators using configured threat intelligence tools.|
|11|Indicator (Type Domain) > Get Reputation|Retrieves the reputation of indicators of type ‘Domain’ using configured threat intelligence tools.|
|12|Indicator (Type Email) - Get Reputation|Get Reputation of Email Address|
|13|Indicator (Type File) - Get Reputation|Uploads a file to a sandbox and then retrieves its reputation using configured threat intelligence tools. |
|14|Indicator (Type File) - Get Reputation (Fortinet Sandbox)|Submits a file to Fortinet Sandbox and then retrieves its reputation.|
|15|Indicator (Type File - MD5) - Get Reputation|Get Reputation of File identified by MD5 hash|
|16|Indicator (Type Host) - Get Reputation|Retrieves the reputation of indicators of type ‘Host’ using configured threat intelligence tools.|
|17|Indicator (Type IP) - Get Reputation|Get Reputation of IP address|
|18|Indicator (Type Port) - Get Reputation|Retrieves the reputation of indicators of type ‘Port’ using configured threat intelligence tools.|
|19|Indicator (Type Process) - Get Reputation|Retrieves the reputation of indicators of type ‘Process’ using configured threat intelligence tools.|
|20|Indicator (Type URL) - Get Reputation|Retrieves the reputation of indicators of type ‘URL’ using configured threat intelligence tools.|
|21|Indicator (Type URL) - Get Reputation (Fortinet Sandbox)|Submit URL to Fortinet FortiSandbox.|
|22|Indicator (Type User Account) - Get Details|Retrieves the details of indicators of type ‘User Account’ using configured threat intelligence tools.|


II. Following is a table that lists the playbooks that are a part of the **“02-Enrich (Pluggable)”** collection in the Solution Pack. 

The function of the playbooks in both Enrich and Enrich (Pluggable) collection is the same; however, the design approach is different. In the standard Enrich playbook, all the threat intelligence platforms for a particular indicator type are configured in a single playbook. In Enrich (Pluggable) collection, every threat intelligence platform for a particular indicator type has a separate playbook, which can be plugged/referenced in the Enrichment playbook.

|**SN**|**Playbook Name**|**Description**|
| :- | :- | :- |
|1|AlienValut OTX - File MD5 Reputation|Retrieves the reputation of indicators of type 'FileHash-MD5' using AlienValut OTX.|
|2|AlienValut OTX - IP Reputation|Retrieves the reputation of indicators of type 'IP Address' using AlienValut OTX.|
|3|AlienValut OTX - URL Reputation|Retrieves the reputation of indicators of type 'URL' using AlienValut OTX.|
|4|AlienVault-OTX - Domain Reputation|Retrieves the reputation of indicators of type 'Domain' using AlienValut OTX.|
|5|Anomali Threatstream - Domain Reputation|Retrieves the reputation of indicators of type 'Domain' using Anomali Threatstream.|
|6|Anomali Threatstream - Email Reputation|Retrieves the reputation of indicators of type 'Email' using Anomali Threatstream.|
|7|Anomali Threatstream - File MD5 Reputation|Retrieves the reputation of indicators of type 'FileHash-MD5' using Anomali Threatstream.|
|8|Anomali Threatstream - IP Reputation|Retrieves the reputation of indicators of type 'IP Address' using Anomali Threatstream.|
|9|Anomali Threatstream - URL Reputation|Retrieves the reputation of indicators of type 'URL' using Anomali Threatstream.|
|10|Cisco Threat Grid - File Reputation|Submits a file to Cisco Threat Grid and then retrieves its reputation.|
|11|Fortinet Web Filter Lookup - Domain Reputation|Retrieves the reputation of indicators of type 'Domain' using Fortinet Web Filter Lookup.|
|12|Fortinet Web Filter Lookup - URL Reputation|Retrieves the reputation of indicators of type 'URL' using Fortinet Web Filter Lookup.|
|13|Indicator (Domain) - Get Latest Reputation|Retrieves the reputation of indicators of type 'Domain' using configured threat intelligence playbooks.|
|14|Indicator (Email) - Get Latest Reputation|Retrieves the reputation of indicators of type 'Email' using configured threat intelligence playbooks.|
|15|Indicator (File) - Get Latest Reputation|Uploads a file to a sandbox and then retrieves its reputation using configured threat intelligence tools playbooks.|
|16|Indicator (File MD5) - Get Latest Reputation|Retrieves the reputation of indicators of type 'Filehash' using configured threat intelligence playbooks.|
|17|Indicator (IP Address) - Get Latest Reputation|Retrieves the reputation of indicators of type 'IP Address' using configured threat intelligence playbooks.|
|18|Indicator (Manual Trigger)  - Get Latest Reputation|Retrieves the reputation of indicators using configured threat intelligence tools. You can trigger this playbook by manually selecting the indicator(s).|
|19|Indicator (Type All) - Get Latest Reputation|Based on the type of indicator, this playbook retrieves the reputation of indicators using configured threat intelligence tools.|
|20|Indicator (Type File - MD5) - Get Reputation|Retrieves the reputation of a file, identified by its MD5 hash, using configured threat intelligence tools.|
|21|Indicator (Type Host) - Get Latest Reputation|Retrieves the reputation of indicators of type 'Host' using configured threat intelligence playbooks.|
|22|Indicator (Type Process) - Get Latest Reputation|Retrieves the reputation of indicators of type 'Process' using configured threat intelligence tools.|
|23|Indicator (URL) - Get latest Reputation|Retrieves the reputation of indicators of type 'URL' using configured threat intelligence playbooks.|
|24|IP Stack - Domain Geo Location|Retrieves the geolocation of indicators of type 'Domain' using IP Stack.|
|25|IP Stack - IP Reputation|Retrieves the geolocation of indicators of type 'IP Address' using IP Stack.|
|26|MXToolBox - IP Reputation|Retrieves the reputation of indicators of type 'IP Address' using MXToolBox.|
|27|Symantec Deepsight Intelligence - File MD5 Reputation|Retrieves the reputation of a file, identified by its MD5 hash, using Symantec DeepSight Intelligence.|
|28|ThreatQ - Email Reputation|Retrieves the reputation of indicators of type 'Email' using ThreatQ.|
|29|URLVoid - Domain Reputation|Retrieves the reputation of indicators of type 'Domain' using URLVoid.|
|30|URLVoid - URL Reputation|Retrieves the reputation of indicators of type 'URL' using URLVoid.|
|31|VirusTotal - Domain Reputation|Retrieves the reputation of indicators of type 'Domain' using VirusTotal.|
|32|Virustotal - File MD5 Reputation|Retrieves the reputation of indicators of type 'File Hash MD5' using VirusTotal.|
|33|Virustotal - File Reputation|Submits a file to VirusTotal and then retrieves its reputation.|
|34|Virustotal - IP Reputation|Retrieves the reputation of indicators of type 'IP Address' using VirusTotal.|
|35|VirusTotal - URL Reputation|Retrieves the reputation of indicators of type 'URL' using VirusTotal.|
|36|Whois - IP Reputation|Retrieves whois data for indicators of type 'IP Address' using Whois RDAP.|

# Triaging Playbook Collection
You can use the playbooks in the *03-Triage* collection to perform actions such as sorting, systematize, computing, etc. your enriched data, enabling you to quickly investigate the incident and take decisions for containment and resolution of the incident.

Following is a table that lists the playbooks that are part of the “03-Triage” collection in the Solution Pack:

|**SN**|**Playbook Name**|**Description**|
| :- | :- | :- |
|1|Compute Alert Priority Weight (Post Update)|Computes and sets the priority weight for an alert, when the alert is updated. The priority weight is calculated based on indicators related to the alert. |
|2|Compute Alert Priority Weight (Post Update - Indicator Linked)|Computes and sets the priority weight for an alert, when an indicator related to the alert is updated. The priority weight is calculated based on indicators related to the alert.|
|3|Compute Alert Priority Weight (Post Update - Indicator Reputation Update)|Computes and sets the priority weight for an alert, when the reputation of an indicator is updated. The priority weight is calculated based on indicators related to the alert.|
|4|Find and Relate Similar Alerts|Finds similar alerts based on the filter criteria you have specified and adds correlations to similar alerts. |
|5|Find and Relate Similar Alerts - ML|Finds similar alerts based on the filter criteria you have specified and adds correlations to similar alerts using the recommendation APIs (ML).|
|6|Flag Indicators Linked across multiple alerts|Flags changes made in indicators that are linked to multiple alerts.|
|7|Map Historical Alerts and Escalate for malicious Indicators|Creates a mapping for historical alerts and then escalates the alerts to incidents if malicious indicators are found in the historical alerts. If the incident already exists, then the information is updated into the incident; else a new incident is created.|
|8|Prioritize Alerts With VIP Assets|Raises the severity of the alert if it is associated with a super critical asset.|
|9|Update Alert Severity for Malicious Indicators|Sets the severity of the alert to ‘Critical’ if its associated indicators are found to be ‘malicious’.|

# Use Cases Playbook Collection
You can use the playbooks in the *04-Use Cases* collection to understand and perform various tasks or steps needed to deal with an incident, such as a Phishing attack or a Brute Force Attempt.

Following is a table that lists the playbooks that are part of the “04-Use Cases” collection in the Solution Pack:

|**SN**|**Playbook Name**|**Description**|
| :- | :- | :- |
|1|Get Microsoft CASB Alert Information|Fetches details related to Microsoft cloud access security broker(CASB) alert and extracts indicators from alert activity(s). This is reference playbook to Pickup and Enrich Microsoft CASB Alert|
|2|Investigate Brute Force Attempt|Investigates login failures and also identifies other impacted assets that have been victims of the brute force attempts from a particular source of attack|
|3|Investigate Brute Force Attempt (FortiSIEM)|Investigates login failures from FortiSIEM and also identifies other impacted assets that have been victims of the brute force attempts from a particular source of attack.|
|4|Investigate C2 Malware Traffic|Investigates C2 Malware Traffic and blocks malicious content if indicators associated with the alert are found to be ‘Malicious’. |
|5|Investigate Command & Control|Enriches alerts for command-and-control behavior by identifying the reputation of related artifacts such as source IP addresses and file hashes. Also, investigates any anomalous processes running on the host on which the attack has occurred and terminates those processes.|
|6|Investigate Compliance Alert|` `The security analyst manually investigates compliance alerts and provides their findings. |
|7|Investigate Concurrent login from different geo location|Investigates alerts of type ‘Concurrent Login’ by checking if the source IP address is in the specified CIDR range, and then performs remediation tasks based on the result.|
|8|Investigate DNS Exfiltration|Investigates an alert ingested from Splunk using threat intelligence reports retrieved from Intel471 and by querying Splunk. Containment tasks are performed if malicious activity is found.|
|9|Investigate Firewall Policy Violation|Investigates policy violations and retrieves information of the destination and source IP addresses along with the protocols and ports used, and then disables the system from the domain.|
|10|Investigate Lateral Movement & VPN Breach Detection|Investigates a FortiDeceptor Malicious IP Lateral Movement and performs containment and remediation tasks if a breach is detected.|
|11|Investigate Lost / Stolen device|Investigates lost or stolen devices using ServiceNow and Active Directory.|
|12|Investigate Malicious Indicator - Hunt|Referenced by 'Investigate Malicious Indicator' playbook to perform a hunt on malicious indicators using QRadar, Splunk, and FortiEDR.|
|13|Investigate Malicious Indicator - Hunt - QRadar Threat Hunt|Performs QRadar Threat Hunting for the last 7 days on the specified IOC.|
|14|Investigate Malicious Indicators|Hunts malicious indicators and provides their summary for review by analysts.|
|15|Investigate Malware Alert|Investigates malware alert by checking if any malicious indicator found on the endpoint and then performs hunt for malicious indicator to block the same on firewall. Also performs a full scan of endpoint.|
|16|Investigate Malware Infection|Investigates a malware infection by querying ElasticSearch and Active Directory.|
|17|Investigate Reconnaissance|Investigates alerts of type ‘Reconnaissance’ and blocks the source IP address on the firewall if it is found to be malicious.|
|18|Investigate S3 Bucket Permission Change|Investigate a change in the S3 permissions, and performs containment and remediation tasks if the change is in violation of the S3 policy.|
|19|Investigate Suspicious Email|Investigates an alert of type ‘Suspicious Email’, and escalates the alert to an ‘Incident’ if indicators associated with the alert are found to be ‘Malicious’.|
|20|Investigate Windows Sysmon event|Investigates a Windows Sysmon event, and escalates the alert to an ‘Incident’ if malware is detected.|
|21|Phishing Alert - Investigate and Escalate|Investigates an alert of type ‘Phishing’, and escalates the alert to an ‘Incident’ if indicators associated with the alert are found to be ‘Malicious’.|
|22|Pickup and Enrich Microsoft CASB Alert|Pickup and Enrich the alert is generated from Microsoft cloud access security broker (CASB)and investigates if any malicious indicator found|
|23|Process CarbonBlack Bit9 Approval Requests|Creates tasks against an incident to complete all requests listed in CarbonBlack Bit9 and sends requests for their approval process.|
|24|Process CarbonBlack Bit9 - Approval  Requests (Subroutine)|Subroutine of CarbonBlack Bit9 approval process.|
|25|Rapid7 - Fetch Scan and Deploy Patch|Automates patch deployments by looking up Rapid7 Scan results.|
|26|Rapid7 - Fetch Scan and Deploy Patch (Scheduled)|Creates schedules to initiate patch deployments.|
|27|Rapid7 -  Patch (Subroutine)|Deploys patches using MS SCCM.|

# Actions Playbook Collection
You can use the playbooks in the *05-Actions* collection to perform various operations or actions such as blocking or unblocking domains, URLs, hosts, etc.

Following is a table that lists the playbooks that are a part of the “05-Actions” collection in the Solution Pack:

|**SN**|**Playbook Name**|**Description**|
| :- | :- | :- |
|1|Action - Asset Mitigation|Carries out a sequence of processes such as Clean Asset, AV scan, etc. in order to decide whether to keep an asset in isolation or remove it from isolation.|
|2|Action - Domain - Block (Indicator)|Blocks the indicators of type 'Domain' on the firewall and marks the indicator as "Blocked" based on its Block status.|
|3|Action - Domain - Block (Specified by User)|Creates an indicator for the domain name specified by the user, blocks the domain on the firewall, and also marks the status of the indicator 'Blocked’. The indicator is also linked to the record on which the playbook is triggered. |
|4|Action - Domain - Unblock (Indicator)|Unblocks the indicators of type 'Domain' on the firewall and marks the indicator as "Unblocked" based on its block status.|
|5|Action - Domain - Unblock (Specified by User)|Creates indicator for the domain name specified by the user, unblocks the domain on the firewall, and also marks the status of the indicator as ‘Unblocked’. The indicator is also linked to the record on which the playbook is triggered.|
|6|Action - Email Address - Block (Indicator)|Blocks the indicators of type 'Email Address' on the firewall and marks indicator as "Blocked" based on its block status.|
|7|Action - Email Address - Block (Specified by User)|Creates indicator for the email address specified by the user, blocks the email on the firewall, and marks the status of the indicator as ‘Blocked’. The indicator is also linked to the record on which the playbook is triggered.|
|8|Action - Email Address - Unblock (Indicator)|Unblocks the indicators of type 'Email Address' on the firewall and mark indicator as "Unblocked" based on its block status.|
|9|Action - Email Address - Unblock (Specified by User)|Creates indicators for the email address specified by the user, unblocks the email on the firewall, and also marks the status of the indicator as Unblocked. The indicator is also linked to the record on which the playbook is triggered.|
|10|Action - File - Block (Indicator)|Blocks the indicators of type 'File' on the firewall and marks the indicator as "Blocked" based on its block status.|
|11|Action - File - Block (Specified by User)|Creates indicators for the file specified by the user, blocks the file on the firewall and also marks the status of the indicator as blocked. The indicator is also linked to the record on which the playbook is triggered.|
|12|Action - File MD5 - Block (Indicator)|Blocks the indicators of type 'Filehash' on the firewall and marks the indicator as "Blocked" based on its block status.|
|13|Action - File MD5 - Block (Specified by User)|Creates indicators for the filehash specified by the user, blocks the indicator on the firewall, and also marks the status of the indicator as blocked. The indicator is also linked to the record on which the playbook is triggered.|
|14|Action - File MD5- Unblock (Indicator)|Unblocks the indicators of type 'Filehash' on the firewall and marks the indicator as "Unblocked" based on its block status.|
|15|Action - File MD5 - Unblock (Specified by User)|Creates indicators for the filehash specified by the user, unblocks the indicator on the firewall, and also marks the indicator as unblocked. The indicator is also linked to the record on which the playbook is triggered.|
|16|Action - File - Unblock (Indicator)|Unblocks the indicators of type 'File' on the firewall and marks the indicator as "Unblocked" based on its block status.|
|17|Action - File - Unblock (Specified by User)|Creates indicators for the file specified by the user, unblocks the file on the firewall, and also mark the status of the indicator as unblocked. The indicator is also linked to the record on which the playbook is triggered.|
|18|Action - Host - Block (Indicator)|Blocks indicators of type 'Host' on the firewall and marks the indicator as "Blocked" based on its block status.|
|19|Action - Host - Block (Specified by User)|Creates indicators for the host specified by the user, blocks the host on the firewall, and also marks the indicator as blocked. The indicator is also linked to the record on which the playbook is triggered.|
|20|Action - Host - Isolate Host|Isolates indicators of type 'Host' and marks the indicator as "Isolated" based on its block status.|
|21|Action - Host - Unblock (Indicator)|Unblocks indicators of type 'Host' on the firewall and marks the indicators as "Unblocked" based on their block status.|
|22|Action - Host - Unblock (Specified by User)|Creates indicators for the host specified by the user, unblocks the host on the firewall, and also marks the indicator as Unblocked. The indicator is also linked to the record on which the playbook is triggered.|
|23|Action - IP Address - Block (Forticlient EMS)|Quarantines endpoint with the specified IP address on FortiClient EMS. |
|24|Action - IP Address - Block (Fortigate,FortiEDR)|Isolates and blocks specified IP addresses using FortiGate and FortiEDR. |
|25|Action - IP Address - Block (Indicator)|Blocks indicators of type 'IP Address' on the firewall and marks the indicators as "Blocked" based on their block status.|
|26|Action - IP Address - Block (Specified by User)|Creates indicators for the specified IP Address', blocks the IP address on the firewall, and marks the indicators as blocked. The indicator is also linked to the record on which the playbook is triggered.|
|27|Action - IP Address - Unblock (Indicator)|Unblocks indicators of type 'IP Address' on the firewall and marks the indicator as "Unblocked" based on their block status.|
|28|Action - IP Address - Unblock (Specified by User)|Creates indicators for the specified 'IP Address', unblocks the IP address on the firewall, and marks the indicators as unblocked. The indicator is also linked to the record on which the playbook is triggered.|
|29|Action (Type All) > Block Indicators|Blocks all types of indicators on the firewall based on their block status.|
|30|Action - URL - Block (Indicator)|Blocks indicators of type 'URL' on the firewall and marks the indicators as "Blocked" based on their block status.|
|31|Action - URL - Block (Specified by User)|Creates indicators for the specified 'URL', blocks the URL on the firewall, and marks the indicator as blocked. The indicator is also linked to the record on which the playbook is triggered.|
|32|Action - URL - Unblock (Indicator)|Unblocks indicators of type 'URL' on the firewall and marks the indicators as "Unblocked" based on their block status.|
|33|Action - URL - Unblock (Specified by User)|Creates indicators for the specified 'URL', unblocks the URL on the firewall, and marks the indicator as unblocked. The indicator is also linked to the record on which the playbook is triggered.|
|34|Alert - Disable Specific User |Disables the specified User Account from the Active Directory.|
|35|Asset - Deploy Patch|Deploys the specified Patch on the selected asset using 'Microsoft SCCM'.|
|36|Incident - Get Running Process|Retrieves details for all the running processes on the specified host.|

# Hunt Playbook Collection
You can use the playbooks in the *06-Hunt* collection to automate threat hunting processes and search and identify suspicious domains, malware, and other indicators in your environment and create alerts based on them.

Following is a table that lists the playbooks that are part of the “06-Hunt” collection in the Solution Pack:

|**SN**|**Playbook Name**|**Description**|
| :- | :- | :- |
|1|Hunt Indicators|Searches for the specified indicators in your environment using EDR tools, and create alerts for ones that are found.|

# ChatOps Playbook Collection
You can use the playbooks in the *07 - ChatOps* collection to perform various operations such as fetching alert and incident details, using a Bot.

Following is a table that lists the playbooks that are part of the “07-Chatops” collection in the Solution Pack:

|**SN**|**Playbook Name**|**Description**|
| :- | :- | :- |
|1|Bot command - Display Options|Displays a list of all the Bot commands.|
|2|Bot Command - Get Alerts|Retrieves details of a specific alert based on the provided alert ID.|
|3|Bot Command - Get Incidents|Retrieves details of a specific incident based on the provided incident ID.|
|4|Bot Command – Get Location|Retrieves the geolocation details for the specified indicator.|
|5|Bot Command - Get Reputation|Retrieves the reputation for the specified indicator.|
|6|Bot Command - Get Similar Alerts|Retrieves the alert records that are similar to a specific alert based on the provided alert ID.|
|7|Bot - Execute commands|Executes the specified Bot Command.|
|8|Code Snippet|Executes the provided Python code.|

# Case Management Playbook Collection
You can use the playbooks in the *08 – Case Management* collection to automate processes related to cases, including operations such as adding a user as a record owner, checking for SLA violations, calculating queued and resolution time for alerts, etc.

Following is a table that lists the playbooks that are part of the “08-Case Management” collection in the Solution Pack:

|**SN**|**Playbook Name**|**Description**|
| :- | :- | :- |
|1|Add a User to the Owners List|Checks if the specified module is user ownable, and then adds the selected user as an owner of the record / records irrespective of which team the user belongs.|
|2|Alert - [01] Capture All SLA (Upon Create)|Updates the alert's acknowledgement due date and response due date based on the alert’s severity.|
|3|Alert - [02] Capture Ack SLA (Upon Update)|Updates the alert's acknowledgement date and SLA Status based on when the alert status is changed.|
|4|Alert - [03] Capture Response SLA (Upon Update)|Updates the alert's response date and SLA Status based on when the alert status is changed.|
|5|Alert - [04] Check for SLA violations|Checks periodically for violations of acknowledgement SLA of the open alerts.|
|6|Alert - [05] Update Ack and Response Due dates (Post Severity Change)|Updates the alert’s acknowledge due date and response due date for change in the severity of alerts|
|7|Alert - Close Corresponding SIEM Alert|Closes the alert on the corresponding SIEM when an alert is closed in FortiSOAR.|
|8|Alert - Periodic Update Alert SLA Status|This is a subroutine playbook to periodically check violations of acknowledgement and response SLA of the open alerts.|
|9|Alert - Set Metrics (Upon Close)|Calculates queued and resolution time for a closed alert.|
|10|Alert - Update SLA Details|Updates an alert's acknowledgement due date and response due date based on the severity of the alert.|
|11|Approval - On Create|` `This playbook is triggered whenever an approval record is created, and an email is sent out to the intended approver(s).|
|12|Approval - On Email Receipt (Exchange)|This playbook is triggered whenever an email is received via Exchange; the playbook determines whether the received email is an approval mail, and, if yes, checks its approval status.|
|13|Approval - On Email Receipt (IMAP)|This playbook is triggered whenever an email is received via IMAP and it checks whether the received email is an approval mail along with its approval status.|
|14|Approval - On Email Receipt - Process Email|Checks if the email is an approval email and returns its approval status.|
|15|Assign Random User to Unassigned Alerts|Auto assigns alerts if their assignments were missed during alert creation.|
|16|Assign Random User to Unassigned Incidents|Auto assigns incidents if their assignments were missing during incident creation.|
|17|Escalated Alert - Copy Related Records to Incidents|Links related data from the alert to the incident, when an alert is escalated.|
|18|Escalated Alert - Related Asset Records to Incidents|Links related assets from the alert to the incident, when an alert is escalated.|
|19|Export Selected Records|Exports all selected records to a JSON file and creates an attachment record for the same.|
|20|Fetch SLA Details|Fetches SLA Details for incidents as per Service, that is, for MSSP or Enterprise.|
|21|Import Data|Imports a valid JSON file to a relevant module and creates subsequent records.|
|22|Incident - [01] Capture All SLA (Upon Create)|Updates an alert's acknowledgement due date and response due date based on the severity of the incident.|
|23|Incident - [02] Capture Ack SLA (Upon Update)|Updates an incident's acknowledgement date and SLA status when the status of the incident is changed.|
|24|Incident - [03] Capture Response SLA (Upon Update)|Update an incident's response date and SLA status when the status of the incident is changed.|
|25|Incident - [04] Check for SLA violations|Periodically check Acknowledgement SLA violations of the Open Incidents.|
|26|Incident - [05] Update Response and Ack Due date (Post Severity Change)|Update an incident's acknowledgement due date and response due date following a change in severity.|
|27|Incident - Periodic Update Incident SLA Status|This is a subroutine playbook to check and update an incident’s SLA status.|
|28|Incident (Post Create) Phase Change|Sets an incident's phase dates upon incident creation.|
|29|Incident (Post Update) Phase Change|Updates an incident's phase dates when incident phase is changed.|
|30|Incident - Set Phase Dates|Updates an incident's phase dates based on incident phase.|
|31|Incident Summary Notification|Sends a daily summary of incidents created and closed.|
|32|Incidents - Update SLA Details|Updates an alert's acknowledgement due date and response due date based on incident severity.|
|33|Indicator - Check Expiry Status|Checks periodically for the expiry date of the indicator and marks it as expired, if matched.|
|34|Indicator - Set Default Expiry Date|Sets the default expiry date when an indicator is created.|
|35|Indicator - Set First Seen Date|Sets the first seen date when an indicator is created.|
|36|Indicator - Set Last Seen Date|Tracks the occurrence of an indicator by updating the last seen date.|
|37|Notify Blocked Indicator Status to Linked Alerts|Adds a note about an indicator being blocked.|
|38|Pause SLA - Alerts|Pauses the alert's acknowledgement or response when its respective SLA status is changed to 'Awaiting Action'.|
|39|Pause SLA - Incidents|Pauses the incident's acknowledgement or response SLA when its respective SLA status is changed to 'Awaiting Action'.|
|40|Prompt when Indicator linked is to Campaign|Notifies an analyst via manual input when an indicator is linked to a campaign.|
|41|Set Prompt to an Alert|Displays a prompt on alerts when an indicator is linked to campaign.|
|42|[Temp] Create Demo Approval||
|43|[Temp] Pull Emails - Manual (Exchange)||

The Case Management (Extended) collection playbooks are for special use cases and can be enabled, if required, by the SOC management. Following is a table that lists the playbooks that are part of the “08-Case Management (Extended)” collection in the Solution Pack:

|**SN**|**Playbook Name**|**Description**|
| :- | :- | :- |
|1|Incident - [06] Check for Ack SLA violations|Notifies users of violation of Acknowledgement SLA.|
|2|Incident - [07] Check for Response SLA violations|Notifies users of violation of Response SLA.|
|3|Notify Ack SLA Violation|Checks every 5 minutes, for Acknowledgement SLA violations of open incidents.|
|4|Notify Response SLA Violation|Checks every 5 minutes for Response SLA violations of acknowledged incidents.|

# Incident Response Playbook Collection
You can use the playbooks in the *09 –* *Incident Response* collection to help you plan your response to an incident such as a malware attack, etc.

Following is a table that lists the playbooks that are part of the “09- Incident Response” collection in the Solution Pack:

|**SN**|**Playbook Name**|**Description**|
| :- | :- | :- |
|1|Incident Response Plan (Type - Malware)|Investigates incidents of type ‘Malware’ and executes the different phases of incident response using CarbonBlack Response.|
|2|Incident Response Plan (Type - NIST 800-61 - Generic)|Creates tasks for incident response and handling as per the guidelines provided in NIST 800-61.|
|3|NIST 800-61 - Upfront Tasks|Creates tasks for incident response and handling as per the guidelines provided in NIST 800-61.|

# Utilities Playbook Collection
You can use the playbooks in the *10 –* *Utilities* collection to perform various operations in FortiSOAR such as creating and linking assets to specified emails, alerts, or incidents, exporting all records or a specified module, or scheduling the health check of connectors and send appropriate notifications.

Following is a table that lists the playbooks that are part of the “10- Utilities” collection in the Solution Pack:

|**SN**|**Playbook Name**|**Description**|
| :- | :- | :- |
|1|Add Attacker Tag to Indicator (FortiDeceptor)|Finds the Attacker IP Address in a FortiDeceptor alert and adds the Attacker Tag to the indicator as well as updates the reputation of the indicator to Malicious.|
|2|Create and Link Asset|Creates an asset (if it doesn't exist already), and links it to the specified email, alert, or incident record.|
|3|Create and Link Indicator|Create an indicator (if it doesn't exist already), and links it to the specified email, alert, or incident record.|
|4|Download and Create Attachment|Downloads the file from a specified URL and creates an attachment record for the same.|
|5|Export as CSV|Export all records of the given module with specified filters in the CSV format.|
|6|Get Paginated Records|Gets paginated records data and appends them in a .CSV file. This playbook is a reference playbook for 'Export as CSV'.|
|7|Notify Connector Health Check Failures|Scheduled to check connectors’ health status and notify the specified recipients of any failed health check.|
|8|Notify Failed Playbook Executions|Notifies specified recipients of any playbook failure. It can be scheduled to run at specific intervals.|
|9|Scheduled Configuration Export|Export template name and email address to be updated in 'Configuration' step. Can be used to schedule Configuration Export and send as email.|

# Demo Playbook Collection
You can use the playbooks in the *11 –* *Demo* collection to create various artifacts required to demonstrate various scenarios, such as the creation of a demo incident record to demonstrate a malware incident response, creation of global various required by playbooks, creation of default SLA templates, etc.

Following is a table that lists the playbooks that are part of the “11- Demo” collection in the Solution Pack:

|**SN**|**Playbook Name**|**Description**|
| :- | :- | :- |
|1|Add to Exclude List|Adds specified indicators as global variables, which excludes them from being considered as IoCs.|
|2|Create Default Global Variables|Creates default global variables and SLA templates required for playbooks.|
|3|Create Default SLA Templates|Creates default SLA templates for varying severity of alerts and incidents.|
|4|Create Demo Campaigns|Creates demo campaigns and corelates different observables against the campaign record.|
|5|Create Sample Records - IR, Threat Intelligence and Vulnerability Management|Creates sample records for Alerts, Incidents, Indicators, Campaigns, Vulnerabilities, Assets, and Scans in order to carry out mock incident response, threat intelligence, and vulnerability management. This playbook is referenced in Demo Incident Response Records.|
|6|Create Sample Records - Legal, Physical Incidents|Generates sample records for legal and physical incidents.|
|7|Demo Incident Response Records|Creates sample records for Alerts, Incidents, Indicators, Campaigns, Vulnerabilities, Assets, and Scans in order to carry out mock incident response.|
|8|Demo Scenario #1 - Compromised Credential|Generates alert from a FortiSIEM incident for the ‘Compromised Credentials’ Scenario.|
|9|Download and Create Attachment|Downloads the file from a specified URL and creates an attachment record for the same.|
|10|Email Based Alert Ingestion|Ingests an incident from a FortiSIEM email notification and creates alerts for the same.|
|11|(Email Based Ingestion) Create Alert|Generates alerts for email-based alert ingestion.|
|12|Generate - Attachment Records|` `Generates attachment records for the file downloaded from a specified URL.|
|13|Generate - Malware Incident|Creates a demo incident record for demonstration of Malware IR.|
|14|Generate - Tenable Scan, Assets and Vulnerabilities|Creates sample Scan, Assets, Vulnerabilities records from Tenable.io.|
|15|Get Similar Alerts - Fetch Similar Alerts|Retrieves a list of alerts related to the specified indicator.|
|16|Reset Sample Records (Database)|Clears all records from different modules by directly connecting to the database using a Python script.|
|17|Sample - Create FortiSOAR Users|Creates FortiSOAR users for demo purposes.|
|18|Sample - Reset Environment|Clears all records from different modules using FortiSOAR APIs.|
|19|Sample Users|This is a reference playbook that creates FortiSOAR users.|
|20|Send Counseling Email|Sends the offending user a counseling email.|
|21|Setup Connector Configurations|Configures all connectors that are listed in the connector configuration file.|
|22|<p>Setup Connector Configurations </p><p>` `- Setup Connector</p>|Configures the specified connectors. This is a reference playbook for Setup Connector Configurations.|
|23|Setup Default Appliance Roles|Auto Configures the appliance roles for playbook execution.|
|24|Setup Default Configuration for Code Snippet|Creates default configuration for the Code Snippet connector. |
|25|Setup Default Configuration for SLA Calculator|Creates default configuration for the SLA Calculator connector.|
|26|Setup Default Configuration for SOC  Simulator|Creates default configuration for the SOC Simulator connector.|

# Training Playbook Collection
You can use the playbooks in the *12 –* *Training* collection to provide FortiSOAR training.

Following is a table that lists the playbooks that are part of the “12- Training” collection in the Solution Pack:

|**SN**|**Playbook Name**|**Description**|
| :- | :- | :- |
|1|01 - Investigate Filehash (Manual)|This is a manually triggered playbook and the security analyst use to determine the filehash reputation.|
|2|02 - Investigate Filehash (Semi Automated)|This is a manually triggered playbook that investigates filehash reputation using VirusTotal.|
|3|03 - Investigate Filehash (Fully Automated)|` `This playbook is triggered automatically following the creation of an alert; it investigates filehash reputation using VirusTotal.|

# Communication Playbook Collection
You can use the playbooks in the *14 –* *Communications* collection to automate various communication-related tasks such as sending a notification email or adding a note to a communication thread.

Following is a table that lists the playbooks that are part of the “14- Communications” collection in the Solution Pack:

|**SN**|**Playbook Name**|**Description**|
| :- | :- | :- |
|1|Add Note for Communication Linked|Adds a note stating a new communication has been linked to alert.|
|2|Add Note for Communication Linked (Received)|Adds a note stating a new communication that was received has been linked to alert.|
|3|Create Communication Record|` `Creates a record in the communications module and links it to an alert based off the information that is entered by the security analyst.|
|4|Create Communication Record (Email Reply)|Creates a record in the communications module based off a reply to a received email.|
|5|Link Communication Record|Links the communication record to the corresponding alert based on the message ID.|
|6|Link Previous Communications|Links existing communications records to create a conversation thread.|
|7|Manual Send Notification|Sends email notification for any selected communication record that is in either “Draft” or “Sending” state to the intended recipients. |
|8|Send Notification|Sends auto-notification of any new communication record that is in the “Sending” state to the intended recipients. .|

# Hunt - Sunburst Playbook Collection
You can use the playbooks in the *15 –* *Hunt - Sunburst* to demonstrate the Sunburst Hunt techniques.

Following is a table that lists the playbooks that are part of the “15- Hunt - Sunburst” collection in the Solution Pack:

|**SN**|**Playbook Name**|**Description**|
| :- | :- | :- |
|1|Block Sunburst Indicators|Blocks Sunburst indicators on FortiGate and FortiEDR.|
|2|Hunt Sunburst IOCs|Download IOCs from the threat intelligence feeds and hunt them.|
|3|Hunt Sunburst Indicator|Performs a hunt on the specified Sunburst indicators using Splunk and FortiEDR.|

