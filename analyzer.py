import os
import re
import json
import time
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

client = Groq(
    api_key=os.environ.get("GROQ_API_KEY")
)

# Daily token tracking
daily_token_count = 0
MAX_DAILY_TOKENS = 90000

SIEM_PROMPTS = {
    "Wazuh": """
Generate a production-grade Wazuh XML detection rule.
NEVER copy examples verbatim — adapt every field to the specific attack.

ATTACK SPECIFIC RULES:
- Detect the EXACT attack described
- Pick correct if_group based on attack type:
  SSH/Linux attacks    -> if_group: syslog
  Windows/PowerShell  -> if_group: windows
  Network traffic     -> if_group: firewall
  IDS alerts          -> if_group: ids

STRICT WAZUH SYNTAX:
1. Use UNIQUE rule_id provided below
2. level 12-15 for HIGH severity
3. level 8-11 for MEDIUM severity
4. ONE match OR ONE regex tag never both
5. NEVER multiple match tags
6. NEVER SQL operators in match tag
7. NEVER dstip or srcip inside windows if_group rules
   Windows process execution rules ONLY use regex or match tags
   IP tags are INVALID in windows if_group and will break the rule
   For T1059 ALWAYS use chained if_sid approach not srcip
8. dstport tag for port detection
9. frequency and timeframe for counting
10. same_source_ip for same source tracking
11. Always include description and mitre id tags
12. Add \\b word boundary at end of regex patterns
13. ALWAYS use srcip from ATTACKER SOURCE IPS provided — no other IP
14. ALWAYS use dstip from MALICIOUS DESTINATION IPS provided — no other IP
15. NEVER invent byte-volume thresholds
16. ALWAYS add whitelist rule with level 0 as the FIRST rule in the group
    Whitelist rule MUST be the VERY FIRST rule written inside the <group> tag
    NEVER place the whitelist rule after any other rule — it MUST come first
    WRONG order: IOC rule first, behavioural rule second, whitelist rule last
    CORRECT order: whitelist rule first, IOC rule second, behavioural rule third
    Whitelist rule ID MUST be RULE_ID_MINUS_2 — never same as main rule
    Every rule in the group MUST have a completely unique ID
    NEVER use the same rule ID twice — Wazuh will reject duplicate IDs
17. Whitelist ONLY known safe destination IPs like 8.8.8.8 or 1.1.1.1
18. NEVER whitelist internal IP ranges
19. NEVER add whitelist rules to syslog or windows if_group rules
    Whitelist rules are ONLY for firewall if_group rules

RULE GENERATION APPROACH — pick based on attack type:

FOR NETWORK/SSH ATTACKS (syslog, firewall if_group):
Generate TWO separate rules:
  Rule A — IOC Specific (level 14):
    - Use srcip or dstip with exact IP from ATTACKER SOURCE IPS
    - Lower frequency threshold — catches known attacker faster
    - Description prefix: "KNOWN ATTACKER:"
  Rule B — Behavioural (level 12):
    - NO srcip or dstip tags at all
    - Higher frequency threshold — catches any attacker
    - Use same_source_ip for grouping
    - Description prefix: "BEHAVIOURAL DETECTION:"
  Rule A and Rule B are INDEPENDENT — Rule B does NOT chain off Rule A

FOR PROCESS/POWERSHELL ATTACKS (windows if_group):
Generate TWO chained rules:
  Rule A — Base Detection (level 5):
    - Detects the command pattern using regex
    - NO srcip or dstip — NEVER use IP tags in windows rules
    - Description prefix: "BEHAVIOURAL DETECTION:"
  Rule B — Escalation (level 10):
    - Uses <if_sid> to chain off Rule A
    - Matches suspicious user context with <match>
    - NO srcip or dstip — NEVER use IP tags in windows rules
    - Description prefix: "KNOWN ATTACKER:"
    - Level MUST be higher than Rule A — Rule A is level 5, Rule B is level 10
  Rule B ONLY fires if Rule A already fired — they are linked via if_sid

NEVER mix these two approaches:
- Network rules are INDEPENDENT dual rules
- Process rules are CHAINED rules using if_sid
- NEVER add srcip or dstip to windows if_group rules
- NEVER use if_sid for network/SSH rules

STRICT XML FORMATTING — CRITICAL:
- ALWAYS use double quotes for ALL XML attributes — NEVER single quotes
- CORRECT: <rule id="101059" level="5">
- WRONG:   <rule id='101059' level='10'>
- Every tag and its content MUST be on the SAME line — NEVER split tag content across lines
- CORRECT: <if_group>windows</if_group>
- WRONG:   <if_group>
              windows</if_group>
- CORRECT: <description>BEHAVIOURAL DETECTION: Encoded PowerShell - T1059</description>
- WRONG:   <description>
              BEHAVIOURAL DETECTION: Encoded PowerShell - T1059</description>
- description and mitre tags MUST be INSIDE the rule tag
- ALWAYS format each rule across multiple lines but keep each tag's content inline

EXAMPLES (structure only — adapt all values):

SSH Brute Force dual rules:
<group name="custom_detection,">
  <rule id="RULE_ID_HERE" level="14" frequency="5" timeframe="120">
    <if_group>syslog</if_group>
    <match>Failed password</match>
    <srcip>ATTACKER_IP_FROM_REPORT</srcip>
    <same_source_ip />
    <description>KNOWN ATTACKER: SSH Brute Force - T1110</description>
    <mitre><id>T1110</id></mitre>
  </rule>
  <rule id="RULE_ID_HERE_PLUS_1" level="12" frequency="10" timeframe="60">
    <if_group>syslog</if_group>
    <match>Failed password</match>
    <same_source_ip />
    <description>BEHAVIOURAL DETECTION: SSH Brute Force - T1110</description>
    <mitre><id>T1110</id></mitre>
  </rule>
</group>

PowerShell dual rules with chaining:
<group name="custom_detection,">
  <rule id="RULE_ID_HERE" level="5">
    <if_group>windows</if_group>
    <regex>powershell.*-[Ee]ncodedCommand|powershell.*-[Ee]nc\b</regex>
    <description>BEHAVIOURAL DETECTION: Encoded PowerShell - T1059</description>
    <mitre><id>T1059</id></mitre>
  </rule>
  <rule id="RULE_ID_HERE_PLUS_1" level="10">
    <if_sid>RULE_ID_HERE</if_sid>
    <match>non_admin_user</match>
    <description>KNOWN ATTACKER: Encoded PowerShell Non-Admin User - T1059</description>
    <mitre><id>T1059</id></mitre>
  </rule>
</group>

Network Exfiltration dual rules with whitelist — ORDER IS MANDATORY: whitelist FIRST, IOC SECOND, behavioural THIRD:
<group name="custom_detection,">
  <rule id="RULE_ID_HERE_MINUS_1" level="0">
    <if_group>firewall</if_group>
    <dstip>8.8.8.8</dstip>
    <description>Whitelisted safe outbound traffic</description>
  </rule>
  <rule id="RULE_ID_HERE" level="14" frequency="5" timeframe="2700">
    <if_group>firewall</if_group>
    <dstip>MALICIOUS_IP_FROM_REPORT</dstip>
    <dstport>443</dstport>
    <same_source_ip />
    <description>KNOWN ATTACKER: Exfiltration to Malicious IP - T1041</description>
    <mitre><id>T1041</id></mitre>
  </rule>
  <rule id="RULE_ID_HERE_PLUS_1" level="12" frequency="10" timeframe="2700">
    <if_group>firewall</if_group>
    <dstport>443</dstport>
    <same_source_ip />
    <description>BEHAVIOURAL DETECTION: Unusual Outbound Traffic - T1041</description>
    <mitre><id>T1041</id></mitre>
  </rule>
</group>
CRITICAL REMINDER: In the output above, the whitelist rule (level="0") is FIRST. NEVER move it to second or third position.
""",

    "Splunk": """
Generate TWO Splunk SPL queries: IOC-specific and behavioural.
SOURCETYPES: SSH->linux_secure | Windows->WinEventLog:Security | Network->net_traffic
RULES: each pipe on NEW LINE | always field=_raw in rex | always end with eval severity and table

DUAL RULE STRUCTURE — always use these exact comments:
/* IOC-SPECIFIC RULE */ — filter exact attacker IP, lower threshold
/* BEHAVIOURAL RULE */ — no hardcoded IPs, higher threshold
NEVER mix sourcetypes between the two rules — both rules must use the SAME sourcetype

DUAL RULE SEPARATOR — CRITICAL:
- ALWAYS separate IOC rule and behavioural rule with a semicolon ; on its own
- NEVER join two rules with | index= — this is completely invalid SPL
- CORRECT: ...| table _time, fields; index=main sourcetype=X | rex...
- WRONG: ...| table _time, fields | index=main sourcetype=X | rex...

REX PATTERNS:
SSH: | rex field=_raw "Failed password for (?<user>[^ ]+) from (?<src_ip>[^ ]+)"
PowerShell: | rex field=_raw "(?i)CommandLine=(?<cmdline>.*)"
Network: | rex field=_raw "dstip=(?<dst_ip>[^ ]+).*bytes=(?<bytes>[0-9]+)"

SPL ORDER OF OPERATIONS — CRITICAL:
- ALWAYS follow this exact order: rex -> where (filter) -> stats -> where (threshold) -> eval -> table
- NEVER put where before rex
- NEVER put stats before where filter
- For SSH: rex -> where src_ip="X" -> stats count as attempts by src_ip, user -> where attempts > N -> eval -> table
- For Network: rex -> where dst_ip="X" -> where bytes > N -> eval -> table
- For PowerShell: rex -> where cmdline like "%X%" -> stats count as attempts by cmdline -> where attempts > N -> eval -> table

IOC INJECTION:
- SSH IOC: | where src_ip="EXACT_ATTACKER_IP" — use ATTACKER SOURCE IP only, NEVER destination IP
- Network IOC: | where dst_ip="EXACT_MALICIOUS_IP" then | where bytes > EXACT_THRESHOLD
- PowerShell IOC: | where cmdline like "%EXACT_ATTACKER_IP%" — NEVER use src_ip for Windows logs
NEVER use src_ip field in WinEventLog rules — it does not exist in Windows event logs
NEVER use internal IPs or target host IPs in the IOC filter — only attacker/malicious IPs


POWERSHELL SPECIFIC RULES:
- ALWAYS use (?i) not (i) for case insensitive regex
- ALWAYS generate TWO rules separated by a semicolon
- IOC rule: rex -> where cmdline like "%ATTACKER_IP%" -> stats count as attempts by cmdline -> where attempts > 1 -> eval -> table
- Behavioural rule: rex -> where cmdline like "%-Enc%" -> stats count as attempts by cmdline -> where attempts > 3 -> eval -> table
- Behavioural rule MUST have NO IP addresses — pattern matching only
- BOTH rules MUST end with eval severity and table
- table MUST always include attempts field: | table _time, cmdline, attempts, severity, technique
- NEVER omit attempts from the table — it must always be present

NETWORK SPECIFIC RULES:
- IOC rule: rex -> where dst_ip="MALICIOUS_IP" -> where bytes > EXACT_THRESHOLD -> eval -> table
- Behavioural rule: rex -> where bytes > HIGHER_THRESHOLD -> stats count by dst_ip -> where count > 5 -> eval -> table
- NEVER use stats sum(bytes) — always use where bytes > THRESHOLD directly
- Network behavioural table MUST include bytes field: | table _time, dst_ip, bytes, severity, technique
- NEVER replace bytes with count in the network table — bytes MUST always be present in the table output
- CRITICAL: even in the behavioural rule, the table MUST end with bytes not count: | table _time, dst_ip, bytes, severity, technique
- If you use stats count by dst_ip, you still MUST include bytes in the final table by projecting it from the where clause result

THRESHOLDS: exact values from evidence only — 44 attempts->threshold 40 | 2.3GB->2469606195
BEHAVIOURAL threshold must be HIGHER than IOC threshold — never copy IOC threshold to behavioural rule
NEVER use 2147483648 as a threshold — that is exactly 2GB and is a made up round number
ALWAYS use the exact byte value calculated from evidence — 2.3GB = 2469606195 exactly

ALWAYS end every query with:
| eval severity="HIGH", technique="TXXXX"
| table _time, [relevant fields], severity, technique

TIME WINDOW RULES:
- ALWAYS add earliest=-1h latest=now to every search head query
- Add it right after the sourcetype like: index=main sourcetype=X earliest=-1h latest=now
- NEVER leave out the time window — every query must have one

CRITICAL JSON SAFETY RULES FOR SPL CODE:
- NEVER use backslash in regex patterns inside JSON — use [^ ]+ instead of \\S+
- NEVER use \\d+ inside JSON — use [0-9]+ instead
- NEVER use \\w+ inside JSON — use [a-zA-Z0-9_]+ instead
- NEVER use \\b inside JSON
- Write all SPL on a SINGLE LINE separated by spaces — no literal newlines inside the code field
- NEVER use single quotes anywhere in SPL code — use double quotes only
""",

    "Microsoft Sentinel": """
Generate a production-grade Microsoft Sentinel KQL rule.

STRICT REQUIREMENTS:
- Detect the EXACT attack described
- Generate TWO queries separated by a semicolon: one IOC-specific and one behavioural
- ALWAYS use ago() for time window
- ALWAYS use summarize for aggregation
- ALWAYS use extend to add severity and technique fields
- ALWAYS use project for output fields
- NEVER use 2GB — use exact bytes: 2469606195 for 2.3GB
- ALWAYS inject known attacker IPs from evidence into where clause

CORRECT TABLE AND FIELD NAMES — CRITICAL:
SSH/Linux brute force -> Syslog table:
  - Time field: TimeGenerated
  - Message field: SyslogMessage
  - Source IP field: HostIP
  - CORRECT IOC rule: Syslog | where TimeGenerated >= ago(1h) | where SyslogMessage contains "Failed password" | where HostIP == "ATTACKER_IP" | summarize count() by HostIP, bin(TimeGenerated, 1m) | where count_ >= 40 | extend Severity = "High", Technique = "T1110" | project TimeGenerated, HostIP, count_, Severity, Technique
  - CORRECT Behavioural rule: Syslog | where TimeGenerated >= ago(1h) | where SyslogMessage contains "Failed password" | summarize count() by HostIP, bin(TimeGenerated, 1m) | where count_ >= 50 | extend Severity = "High", Technique = "T1110" | project TimeGenerated, HostIP, count_, Severity, Technique
  - BOTH rules MUST have extend and project — NEVER omit them from either rule
  - ALWAYS include HostIP in project — NEVER omit the source IP field
  - NEVER use srcip, dstip, Username — these fields do not exist in Syslog table
  - IOC threshold MUST match evidence — 44 attempts means threshold 40

Windows auth -> SecurityEvent table:
  - Time field: TimeGenerated
  - Event ID field: EventID
  - Account field: TargetUserName
  - Source IP field: IpAddress
  - CORRECT: SecurityEvent | where EventID == 4625 | where IpAddress == "ATTACKER_IP"
  - NEVER use srcip — use IpAddress

Process execution -> DeviceProcessEvents table:
  - Time field: Timestamp
  - Process field: InitiatingProcessFileName
  - Command field: ProcessCommandLine
  - ALWAYS add: | where InitiatingProcessFileName == "powershell.exe" to every PowerShell rule
  - CORRECT IOC rule: DeviceProcessEvents | where Timestamp >= ago(1h) | where InitiatingProcessFileName == "powershell.exe" | where ProcessCommandLine contains "ATTACKER_IP" | extend Severity = "MEDIUM", Technique = "T1059" | project Timestamp, InitiatingProcessFileName, ProcessCommandLine, Severity, Technique
  - CORRECT Behavioural rule: DeviceProcessEvents | where Timestamp >= ago(1h) | where InitiatingProcessFileName == "powershell.exe" | where ProcessCommandLine contains "-EncodedCommand" | extend Severity = "MEDIUM", Technique = "T1059" | project Timestamp, InitiatingProcessFileName, ProcessCommandLine, Severity, Technique
  - NEVER use summarize before project when projecting non-aggregated fields — if you use summarize you can only project aggregated fields
  - NEVER use SrcIp or RemoteIP — DeviceProcessEvents has NO IP field at all
  - IOC rule for PowerShell: filter by ProcessCommandLine contains attacker IP string
  - Behavioural rule for PowerShell: filter by ProcessCommandLine contains "-EncodedCommand" only — NO IP
  - NEVER swap IOC and behavioural — IOC always has the specific IP, behavioural never does

Network traffic -> DeviceNetworkEvents table:
  - Time field: Timestamp
  - Destination IP field: RemoteIP
  - Bytes field: SentBytes
  - CORRECT IOC rule: DeviceNetworkEvents | where Timestamp >= ago(1h) | where RemoteIP == "MALICIOUS_IP" | where SentBytes > 2469606195 | extend Severity = "High", Technique = "T1041" | project Timestamp, RemoteIP, SentBytes, Severity, Technique
  - CORRECT Behavioural rule: DeviceNetworkEvents | where Timestamp >= ago(1h) | where SentBytes > 3000000000 | summarize count() by RemoteIP, bin(Timestamp, 1m) | extend Severity = "High", Technique = "T1041" | project Timestamp, RemoteIP, count_, Severity, Technique
  - NEVER use dstip or bytes — use RemoteIP and SentBytes
  - NEVER use 2147483648 — use exact evidence value 2469606195 for 2.3GB
  - NEVER use summarize sum(SentBytes) — use where SentBytes > THRESHOLD directly
  - NEVER project InitiatingProcessFileName or ProcessCommandLine — these are process fields not network fields
  - project MUST only include network fields: Timestamp, RemoteIP, SentBytes or count_, Severity, Technique

DUAL RULE STRUCTURE:
- IOC rule: filter by exact attacker IP, lower threshold
- Behavioural rule: NO hardcoded IPs, higher threshold, pattern matching only
- Separate the two rules with a semicolon ;
- BOTH rules must end with extend and project
- NEVER use let variable = to wrap rules — write queries directly without variable assignment
- NEVER use let ioc_rule = or let behavioral_rule = — these are not executable alert queries
- CORRECT: Syslog | where TimeGenerated >= ago(1h) | where HostIP == "X" | summarize...
- WRONG: let ioc_rule = Syslog | where TimeGenerated >= ago(1h)...
- ALWAYS use double quotes never single quotes in KQL — single quotes cause syntax errors

CRITICAL JSON SAFETY RULES FOR KQL CODE:
- Write all KQL on a SINGLE LINE separated by spaces — no literal newlines inside the code field
- NEVER use backslash sequences in regex inside JSON
- ALWAYS wrap IP strings in quotes: RemoteIP == "1.2.3.4" not RemoteIP == 1.2.3.4
""",

    "Elastic": """
Generate a production-grade Elastic Security detection rule in EQL.

STRICT EQL SYNTAX RULES:
- ALWAYS use double quotes never single quotes
- ALWAYS generate TWO rules separated by a semicolon: IOC-specific and behavioural
- NEVER use sequence with runs where — that is invalid EQL
- NEVER use sum() inside EQL sequence
- NEVER add rule_id or text outside code

CORRECT EQL STRUCTURE BY ATTACK TYPE:

Brute Force (SSH):
  IOC rule: sequence with runs=40 [authentication where event.outcome == "failure" and source.ip == "ATTACKER_IP"]
  Behavioural rule: sequence with runs=50 [authentication where event.outcome == "failure"]
  ALWAYS wrap the authentication block in square brackets [ ] — NEVER omit them
  CORRECT: sequence with runs=40 [authentication where event.outcome == "failure" and source.ip == "X"]
  WRONG: sequence with runs=40 authentication where event.outcome == "failure" and source.ip == "X"
  NEVER add destination.ip to brute force rules — authentication events have no destination IP field
  NEVER use destination.ip == "10.0.0.47" or any target host IP — only use source.ip with attacker IP

Process Execution (PowerShell):
  IOC rule: process where event.category == "process" and process.name == "powershell.exe" and process.args : "*-EncodedCommand*" and process.command_line : "*ATTACKER_IP*"
  Behavioural rule: process where event.category == "process" and process.name == "powershell.exe" and process.args : "*-EncodedCommand*"
  ALWAYS include event.category == "process" in every process rule
  NEVER use source.ip in process rules — process events have no source IP field
  NEVER use bytes field in process rules

Network Exfiltration:
  IOC rule: network where destination.ip == "MALICIOUS_IP" and destination.bytes > 2469606195
  Behavioural rule: network where destination.bytes > 3000000000
  NEVER use sequence with runs for network rules — use network where directly
  CORRECT: network where destination.ip == "X" and destination.bytes > N
  WRONG: sequence with runs=1 [network where destination.ip == "X"]
  CORRECT bytes field: destination.bytes — NEVER use just "bytes"
  NEVER use 2147483648 — use exact evidence value 2469606195 for 2.3GB
  NEVER use destination.ip for process execution

ECS FIELD NAMES — CRITICAL:
- source.ip — attacker source IP in network and auth events
- destination.ip — destination IP in network events
- destination.bytes — bytes sent in network events
- user.name — username in auth events
- process.name — process name
- process.args — process arguments
- process.command_line — full command line
- event.action — action taken
- event.category — event category
- event.outcome — success or failure

CRITICAL JSON SAFETY RULES:
- Write all EQL on a SINGLE LINE — no literal newlines inside the code field
- ALWAYS use double quotes never single quotes
- Separate IOC and behavioural rules with a semicolon ;
""",

    "IBM QRadar": """
Generate a production-grade IBM QRadar AQL detection rule.

STRICT REQUIREMENTS:
- Detect the EXACT attack described
- Generate TWO queries separated by a semicolon: one IOC-specific and one behavioural
- ALWAYS use LOGSOURCETYPENAME(devicetype) not logsourcename
- ALWAYS use LAST keyword for time window: LAST 1 HOURS
- ALWAYS use HAVING for threshold logic
- ALWAYS use GROUP BY before HAVING
- NEVER add RULE_ID or AND RULE_ID at end of any query
- 2.3GB = 2430000000 bytes — NEVER use 2147483648
- ALWAYS inject known attacker IPs into WHERE clause for IOC rule
- Behavioural rule MUST have NO hardcoded IPs — pattern only

CRITICAL QUOTE RULES:
- ALWAYS use double quotes for string literals — NEVER single quotes
- CORRECT: sourceip = "192.168.1.105"
- WRONG: sourceip = '192.168.1.105'
- CORRECT: LOGSOURCETYPENAME(devicetype) = "Linux OS"
- WRONG: LOGSOURCETYPENAME(devicetype) = 'Linux OS'
- CORRECT: "Command" ILIKE "%EncodedCommand%"
- WRONG: 'Command' ILIKE '%EncodedCommand%'

CORRECT AQL STRUCTURE BY ATTACK TYPE:

Brute Force (SSH):
  IOC rule: SELECT sourceip, username, COUNT(*) as attempts FROM events WHERE LOGSOURCETYPENAME(devicetype) = "Linux OS" AND username = "admin" AND sourceip = "ATTACKER_IP" AND LAST 1 HOURS GROUP BY sourceip, username HAVING attempts > 40
  Behavioural rule: SELECT sourceip, username, COUNT(*) as attempts FROM events WHERE LOGSOURCETYPENAME(devicetype) = "Linux OS" AND LAST 1 HOURS GROUP BY sourceip, username HAVING attempts > 50
  NEVER use destinationip in brute force rules
  NEVER omit GROUP BY before HAVING

Process Execution (PowerShell):
  IOC rule: SELECT username, "Command", COUNT(*) as attempts FROM events WHERE LOGSOURCETYPENAME(devicetype) = "Microsoft Windows Security Event Log" AND "Command" ILIKE "%EncodedCommand%" AND "Command" ILIKE "%ATTACKER_IP%" AND LAST 1 HOURS GROUP BY username, "Command" HAVING attempts > 1
  Behavioural rule: SELECT username, "Command", COUNT(*) as attempts FROM events WHERE LOGSOURCETYPENAME(devicetype) = "Microsoft Windows Security Event Log" AND "Command" ILIKE "%EncodedCommand%" AND LAST 1 HOURS GROUP BY username, "Command" HAVING attempts > 3
  NEVER use sourceip for PowerShell rules — Windows event logs do not have sourceip field
  ALWAYS use GROUP BY and HAVING for threshold logic
  NEVER use destinationip for process execution rules
  ALWAYS use double quotes on field names — "Command" not 'Command'

Network Exfiltration:
  IOC rule: SELECT sourceip, destinationip, SUM(bytes) as total_bytes FROM events WHERE LOGSOURCETYPENAME(devicetype) = "Firewall" AND destinationip = "MALICIOUS_IP" AND LAST 1 HOURS GROUP BY sourceip, destinationip HAVING total_bytes > 2430000000
  Behavioural rule: SELECT sourceip, destinationip, SUM(bytes) as total_bytes FROM events WHERE LOGSOURCETYPENAME(devicetype) = "Firewall" AND LAST 1 HOURS GROUP BY sourceip, destinationip HAVING total_bytes > 3000000000
  ALWAYS use SUM(bytes) with GROUP BY for network rules
  NEVER use 2147483648 — always use exact evidence value 2430000000 for 2.3GB

DUAL RULE SEPARATOR:
- Separate IOC and behavioural rules with a semicolon ;
- IOC rule always filters by exact attacker IP
- Behavioural rule NEVER has hardcoded IPs

CRITICAL JSON SAFETY RULES:
- Write all AQL on a SINGLE LINE separated by spaces — no literal newlines inside the code field
- NEVER use backslash sequences inside JSON
"""
}

SOAR_PROMPTS = {
    "Shuffle": """
Generate a production-grade Shuffle SOAR workflow in JSON.
NEVER produce a generic template — tailor actions to the specific attack type.

STRICT REQUIREMENTS:
- Respond to EXACT attack described
- Valid Shuffle workflow JSON
- ALWAYS use double quotes never single quotes
- ALWAYS use ONLY these env variables: $env.FIREWALL_URL and $env.SOC_EMAIL
- NEVER invent new env variables

ATTACK-SPECIFIC ACTIONS:
Brute force/credential attack — ALL FIVE actions are MANDATORY in this exact order:
  1. Block source IP -> POST $env.FIREWALL_URL/block body: {"ip": "$trigger_1.sourceip"}
  2. Lock targeted account -> POST $env.FIREWALL_URL/lockaccount body: {"account": "$trigger_1.targetaccount"}
  3. Schedule IP unblock -> POST $env.FIREWALL_URL/unblock_schedule body: {"ip": "$trigger_1.sourceip", "ttl_hours": 24}
  4. Send SOC email
  5. Create incident ticket
  NEVER skip the unblock schedule — blocked IPs must always have a TTL
  NEVER hardcode account names — always use $trigger_1.targetaccount
  NEVER generate only the Create Ticket action — ALL actions are MANDATORY
  NEVER skip Block IP, Lock Account, or Schedule Unblock for brute force
  The actions array MUST always contain ALL attack-specific actions PLUS the final two
  Minimum 5 actions for brute force: Block IP + Lock Account + Schedule Unblock + Send Email + Create Ticket

Exfiltration/unusual outbound traffic — ALL FIVE actions are MANDATORY:
  1. Isolate source host -> POST $env.FIREWALL_URL/isolate body: {"hostname": "$trigger_1.hostname"}
  2. Block destination IP -> POST $env.FIREWALL_URL/block body: {"ip": "$trigger_1.dstip"}
  3. Revoke active sessions -> POST $env.FIREWALL_URL/revoke_sessions body: {"host": "$trigger_1.hostname"}
  4. Send SOC email
  5. Create incident ticket
  NEVER send empty body {} — always include the relevant field

Suspicious process/PowerShell/command execution:
  - Kill suspicious process -> POST $env.FIREWALL_URL/kill_process
  - Block outbound IP -> POST $env.FIREWALL_URL/block

MANDATORY LAST TWO ACTIONS FOR ALL ATTACKS WITHOUT EXCEPTION:
- Send SOC email with source IP, dest IP, timestamp, hostname, attack type, evidence
- Create incident ticket with priority based on severity
These two actions MUST ALWAYS be the last two actions in every playbook

STRICT JSON SCHEMA:
{
  "name": "Attack Response",
  "description": "Automated response",
  "triggers": [{"type": "webhook", "name": "SIEM Alert", "id": "trigger_1"}],
  "actions": [
    {
      "id": "action_1",
      "name": "Action Name",
      "app_name": "http",
      "app_version": "1.0",
      "app_id": "firewall",
      "action": "POST",
      "parameters": {
        "url": "$env.FIREWALL_URL/endpoint",
        "body": {"key": "value"}
      },
      "position": 1
    },
    {
      "id": "action_2",
      "name": "Alert SOC",
      "app_name": "email",
      "app_version": "1.0",
      "app_id": "email",
      "action": "send_email",
      "parameters": {
        "to": "$env.SOC_EMAIL",
        "subject": "Security Alert",
        "body": "Attack: [type] | Source: $trigger_1.sourceip | Host: $trigger_1.hostname | Time: $trigger_1.timestamp | Detail: $trigger_1.description"
      },
      "position": 2
    },
    {
      "id": "action_3",
      "name": "Create Ticket",
      "app_name": "shuffle_tools",
      "app_version": "1.0",
      "app_id": "ticketing",
      "action": "create_ticket",
      "parameters": {
        "title": "Security Incident",
        "priority": "high"
      },
      "position": 3
    }
  ]
}
""",

    "Palo Alto XSOAR": """
Generate a production-grade Cortex XSOAR playbook in Python.
IMPORTS: import demistomock as demisto | from CommonServerPython import *
NEVER: import demisto alone | demisto_client = Client()
ALWAYS: demisto.executeCommand() | demisto.args() | return_error() | demisto.results()

STRUCTURE — CRITICAL:
- ALWAYS wrap ALL logic inside def main(): — nothing outside main() except imports and the if __name__ block
- ALWAYS end the file with exactly: if __name__ in ("__main__", "__builtin__", "builtins"): main()
- The if __name__ line MUST be OUTSIDE and AFTER the main() function

CORRECT STRUCTURE EXAMPLE:
import demistomock as demisto; from CommonServerPython import *; def main(): src_ip = demisto.args().get("src_ip"); demisto.executeCommand("ip-block", {"ip": src_ip}); demisto.results("Done"); return;
if __name__ in ("__main__", "__builtin__", "builtins"): main()

WRONG STRUCTURE — code outside main():
import demistomock as demisto; dst_ip = demisto.args().get("dst_ip"); demisto.executeCommand("ip-block", {"ip": dst_ip}); demisto.results("Done"); return

ATTACK-SPECIFIC MANDATORY ACTIONS:
Brute force — ALL THREE mandatory:
  1. src_ip = demisto.args().get("src_ip") | executeCommand("ip-block", {"ip": src_ip})
  2. targeted_user = demisto.args().get("targeted_user") | executeCommand("disable-user", {"username": targeted_user})
  3. executeCommand("scheduled-task", {"command": "ip-unblock " + src_ip, "delay_hours": 24})
  NEVER hardcode username as string literal — always use demisto.args().get("targeted_user")
Exfiltration — ALL THREE mandatory:
  1. hostname = demisto.args().get("hostname") | executeCommand("endpoint-isolate", {"hostname": hostname})
  2. dst_ip = demisto.args().get("dst_ip") | executeCommand("ip-block", {"ip": dst_ip})
  3. executeCommand("revoke-sessions", {"hostname": hostname})
PowerShell/process — ALL TWO mandatory:
  1. executeCommand("process-kill", {"pid": demisto.args().get("pid"), "hostname": demisto.args().get("hostname")})
  2. executeCommand("ip-block", {"ip": demisto.args().get("dst_ip")})

IOC INJECTION: NEVER hardcode IP as string literal — always use variable from demisto.args()

MANDATORY LAST TWO ACTIONS inside main():
- send-mail MUST use EXACTLY these two fields: subject and body
- subject MUST always use src_ip not hostname — CORRECT: "[HIGH] Attack from " + demisto.args().get("src_ip")
- NEVER use hostname in the subject line — hostname goes in the body only
  CORRECT: demisto.executeCommand("send-mail", {"subject": "[HIGH] Attack from " + src_ip, "body": "src_ip: " + src_ip + ", dst_ip: " + demisto.args().get("dst_ip") + ", affected_user: " + demisto.args().get("affected_user") + ", timestamp: " + demisto.args().get("timestamp") + ", MITRE ID: T1234, evidence: " + demisto.args().get("evidence")})
  evidence in body MUST be demisto.args().get("evidence") — NEVER write "exact quote here" as a string literal
  WRONG: demisto.executeCommand("send-mail", {"src_ip": src_ip, "dst_ip": dst_ip})
  NEVER pass individual fields like src_ip, dst_ip as top level keys — always use subject and body only
- createNewIncident with severity from demisto.args().get("severity", "HIGH")

MANDATORY ENDING — TWO separate statements inside main() before closing:
- demisto.results("Done")
- return
- NEVER combine as: return demisto.results()

CRITICAL JSON SAFETY RULES FOR PYTHON CODE:
- Write all Python code on a SINGLE LINE using semicolons to separate statements
- Use double quotes for all Python strings inside the code field
- NEVER use single quotes inside the code field
- NEVER use f-strings — use string concatenation with + instead
- NEVER use literal newlines inside the code field
""",

    "Splunk SOAR": """
Generate a production-grade Splunk SOAR playbook in Python using the Phantom API.

STRICT PHANTOM API RULES:
- ALWAYS import phantom and phantom.rules: import phantom.app as phantom; import phantom.rules as phantom_rules
- NEVER use demistomock — that is Cortex XSOAR not Splunk SOAR
- NEVER use demisto.block_ip() — that function does not exist
- NEVER use demisto.send_email() — that function does not exist
- NEVER use demisto.create_ticket() — that function does not exist

CORRECT PHANTOM API FUNCTIONS:
- Block IP: phantom_rules.act("block ip", parameters=[{"ip": container["custom_fields"].get("src_ip", "")}], assets=["firewall"], name="block_ip", parent_action_id=0)
- Send email: phantom_rules.send_email(to="soc@company.com", subject="[HIGH] Attack Detected", body="src_ip: " + container["custom_fields"].get("src_ip", ""))
- Create ticket: phantom_rules.add_artifact(container=container, raw_data={}, cef_data={"severity": "high", "title": "Security Incident"}, label="incident", run_automation=False)

CRITICAL DICT ACCESS RULE:
- ALWAYS use container["custom_fields"].get("field", "") — NEVER use container["custom_fields"]["field"]
- Direct dict access with [] will throw KeyError if the field is missing at runtime
- CORRECT: container["custom_fields"].get("src_ip", "")
- WRONG:   container["custom_fields"]["src_ip"]
- CORRECT: container["custom_fields"].get("dst_ip", "")
- WRONG:   container["custom_fields"]["dst_ip"]
- CORRECT: container["custom_fields"].get("hostname", "")
- WRONG:   container["custom_fields"]["hostname"]
- CORRECT: container["custom_fields"].get("evidence", "")
- WRONG:   container["custom_fields"]["evidence"]
- This rule applies to EVERY field access in the entire playbook without exception

STRUCTURE — CRITICAL:
- ALWAYS wrap all logic in def on_start(container):
- ALWAYS end with: def on_finish(container, summary): pass
- NEVER use main() — Phantom uses on_start() not main()

CORRECT STRUCTURE EXAMPLE:
import phantom.app as phantom; import phantom.rules as phantom_rules; def on_start(container): src_ip = container["custom_fields"].get("src_ip", ""); phantom_rules.act("block ip", parameters=[{"ip": src_ip}], assets=["firewall"], name="block_ip", parent_action_id=0); phantom_rules.send_email(to="soc@company.com", subject="[HIGH] Attack from " + src_ip, body="src_ip: " + src_ip + ", evidence: " + container["custom_fields"].get("evidence", "")); phantom_rules.add_artifact(container=container, raw_data={}, cef_data={"severity": "high", "title": "Security Incident"}, label="incident", run_automation=False); def on_finish(container, summary): pass

ATTACK-SPECIFIC MANDATORY ACTIONS:
Brute force:
  1. Block source IP using phantom_rules.act("block ip")
  2. Disable user using phantom_rules.act("disable account")
  3. Send email with ALL SIX fields — NEVER hardcode any value:
     phantom_rules.send_email(to="soc@company.com", subject="[HIGH] Attack from " + container["custom_fields"].get("src_ip", ""), body="src_ip: " + container["custom_fields"].get("src_ip", "") + ", dst_ip: " + container["custom_fields"].get("dst_ip", "") + ", affected_user: " + container["custom_fields"].get("affected_user", "") + ", timestamp: " + container["custom_fields"].get("timestamp", "") + ", MITRE ID: T1110, evidence: " + container["custom_fields"].get("evidence", ""))
  4. Create artifact ticket
  NEVER hardcode dst_ip as "10.0.0.47" — always use container["custom_fields"].get("dst_ip", "")
  NEVER hardcode affected_user as "admin" — always use container["custom_fields"].get("affected_user", "")
  NEVER use container["custom_fields"]["field"] — always use container["custom_fields"].get("field", "")

Exfiltration:
  1. Isolate endpoint using phantom_rules.act("quarantine device")
  2. Block destination IP using phantom_rules.act("block ip")
  3. Revoke sessions using phantom_rules.act("terminate session")
  4. Send email with ALL SIX fields — NEVER hardcode any value:
     body must include: src_ip, dst_ip, affected_user, timestamp, MITRE ID, evidence — all from container["custom_fields"].get("field", "")
  5. Create artifact ticket
  NEVER use container["custom_fields"]["field"] — always use container["custom_fields"].get("field", "")

CRITICAL JSON SAFETY RULES FOR PYTHON CODE:
- Write all Python code on a SINGLE LINE using semicolons to separate statements
- Use double quotes for all Python strings inside the code field
- NEVER use single quotes inside the code field
- NEVER use literal newlines inside the code field
""",

    "Microsoft Sentinel Playbooks": """
Generate a production-grade Microsoft Sentinel Logic App playbook in JSON.

STRICT AZURE LOGIC APPS FORMAT:
The JSON MUST follow this exact structure with definition, triggers, and actions:

ATTACK-SPECIFIC ACTIONS — CRITICAL:
Generate DIFFERENT actions based on the attack type:

Brute Force / Credential Attack — FOUR actions in this exact order:
  1. Block_IP — block the attacker source IP via Azure Firewall
  2. Disable_Account — disable the targeted user account via Azure AD
  3. Send_Email — notify SOC via Office 365
  4. Add_Incident_Comment — add comment to Sentinel incident
  runAfter chain: Block_IP -> Disable_Account -> Send_Email -> Add_Incident_Comment

Exfiltration / Unusual Outbound Traffic — FIVE actions in this exact order:
  1. Isolate_Host — quarantine the source endpoint
  2. Block_IP — block the malicious destination IP via Azure Firewall
  3. Revoke_Sessions — revoke active sessions on the host
  4. Send_Email — notify SOC via Office 365
  5. Add_Incident_Comment — add comment to Sentinel incident
  runAfter chain: Isolate_Host -> Block_IP -> Revoke_Sessions -> Send_Email -> Add_Incident_Comment

PowerShell / Process Execution — THREE actions in this exact order:
  1. Kill_Process — terminate the suspicious process
  2. Send_Email — notify SOC
  3. Add_Incident_Comment — add comment to Sentinel incident
  runAfter chain: Kill_Process -> Send_Email -> Add_Incident_Comment

NEVER generate the same 3 generic actions for every attack type.
ALWAYS tailor the actions to the specific attack described.

CORRECT BRUTE FORCE EXAMPLE:
{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "triggers": {
      "Microsoft_Sentinel_incident": {
        "type": "ApiConnectionWebhook",
        "inputs": {
          "body": {"callback_url": "@{listCallbackUrl()}"},
          "host": {"connection": {"name": "@parameters('$connections')['azuresentinel']['connectionId']"}},
          "path": "/incident-creation"
        }
      }
    },
    "actions": {
      "Block_IP": {
        "type": "ApiConnection",
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['azurefirewall']['connectionId']"}},
          "method": "post",
          "path": "/block",
          "body": {"ip": "@triggerBody()?['object']?['properties']?['relatedEntities']?[0]?['properties']?['address']"}
        },
        "runAfter": {}
      },
      "Disable_Account": {
        "type": "ApiConnection",
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['azuread']['connectionId']"}},
          "method": "post",
          "path": "/v1.0/users/@{triggerBody()?['object']?['properties']?['relatedEntities']?[0]?['properties']?['accountName']}/disable"
        },
        "runAfter": {"Block_IP": ["Succeeded"]}
      },
      "Send_Email": {
        "type": "ApiConnection",
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['office365']['connectionId']"}},
          "method": "post",
          "path": "/v2/Mail",
          "body": {
            "To": "soc@company.com",
            "Subject": "Security Alert: @{triggerBody()?['object']?['properties']?['title']}",
            "Body": "Incident: @{triggerBody()?['object']?['properties']?['description']}"
          }
        },
        "runAfter": {"Disable_Account": ["Succeeded"]}
      },
      "Add_Incident_Comment": {
        "type": "ApiConnection",
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['azuresentinel']['connectionId']"}},
          "method": "post",
          "path": "/Incidents/Comment",
          "body": {
            "incidentArmId": "@triggerBody()?['object']?['id']",
            "message": "Automated response executed: IP blocked, account disabled, SOC notified"
          }
        },
        "runAfter": {"Send_Email": ["Succeeded"]}
      }
    }
  }
}

CORRECT EXFILTRATION EXAMPLE:
{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "triggers": {
      "Microsoft_Sentinel_incident": {
        "type": "ApiConnectionWebhook",
        "inputs": {
          "body": {"callback_url": "@{listCallbackUrl()}"},
          "host": {"connection": {"name": "@parameters('$connections')['azuresentinel']['connectionId']"}},
          "path": "/incident-creation"
        }
      }
    },
    "actions": {
      "Isolate_Host": {
        "type": "ApiConnection",
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['azuredefender']['connectionId']"}},
          "method": "post",
          "path": "/isolate",
          "body": {"hostname": "@triggerBody()?['object']?['properties']?['relatedEntities']?[0]?['properties']?['hostName']"}
        },
        "runAfter": {}
      },
      "Block_IP": {
        "type": "ApiConnection",
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['azurefirewall']['connectionId']"}},
          "method": "post",
          "path": "/block",
          "body": {"ip": "@triggerBody()?['object']?['properties']?['relatedEntities']?[0]?['properties']?['address']"}
        },
        "runAfter": {"Isolate_Host": ["Succeeded"]}
      },
      "Revoke_Sessions": {
        "type": "ApiConnection",
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['azuread']['connectionId']"}},
          "method": "post",
          "path": "/v1.0/users/@{triggerBody()?['object']?['properties']?['relatedEntities']?[0]?['properties']?['accountName']}/revokeSignInSessions"
        },
        "runAfter": {"Block_IP": ["Succeeded"]}
      },
      "Send_Email": {
        "type": "ApiConnection",
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['office365']['connectionId']"}},
          "method": "post",
          "path": "/v2/Mail",
          "body": {
            "To": "soc@company.com",
            "Subject": "Security Alert: @{triggerBody()?['object']?['properties']?['title']}",
            "Body": "Incident: @{triggerBody()?['object']?['properties']?['description']}"
          }
        },
        "runAfter": {"Revoke_Sessions": ["Succeeded"]}
      },
      "Add_Incident_Comment": {
        "type": "ApiConnection",
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['azuresentinel']['connectionId']"}},
          "method": "post",
          "path": "/Incidents/Comment",
          "body": {
            "incidentArmId": "@triggerBody()?['object']?['id']",
            "message": "Automated response executed: host isolated, IP blocked, sessions revoked, SOC notified"
          }
        },
        "runAfter": {"Send_Email": ["Succeeded"]}
      }
    }
  }
}

STRICT RULES:
- ALWAYS use @triggerBody() for dynamic values — NEVER hardcode IPs or usernames
- ALWAYS chain actions using runAfter in the correct attack-specific order
- NEVER use a made up JSON schema — always follow the exact Azure Logic Apps structure above
- NEVER omit the definition wrapper
- NEVER omit the triggers section
- ALWAYS close the definition object — the JSON MUST end with three closing braces }}}
- NEVER omit the final closing braces — valid ending: ...}}} where first } closes actions, second } closes definition, third } closes root

CRITICAL JSON SAFETY RULES:
- The Logic App JSON inside the "code" field MAY be formatted with newlines and indentation
- The frontend will pretty print it automatically — return it however the LLM finds natural
- ALWAYS use double quotes never single quotes
- ALWAYS use @{...} Azure expressions exactly as shown in the examples above
- NEVER escape the @ symbol — write @{triggerBody()} not \\@{triggerBody()}
""",

    "Tines": """
Generate a production-grade Tines workflow in JSON.

STRICT REQUIREMENTS:
- Respond to EXACT attack described
- Generate a complete Tines workflow with 4 agents
- ALWAYS use <<VARIABLE_NAME>> placeholders for all dynamic values
- NEVER hardcode credentials, URLs, or IP addresses

CORRECT TINES WORKFLOW STRUCTURE:
{
  "name": "Attack Response Workflow",
  "agents": [
    {
      "name": "Webhook Trigger",
      "type": "Agents::WebhookAgent",
      "options": {
        "secret": "<<WEBHOOK_SECRET>>",
        "verbs": "post"
      }
    },
    {
      "name": "Block IP",
      "type": "Agents::HTTPRequestAgent",
      "options": {
        "url": "<<FIREWALL_URL>>/block",
        "method": "post",
        "payload": {
          "ip": "<<webhook_trigger.body.src_ip>>"
        },
        "headers": {
          "Authorization": "Bearer <<FIREWALL_API_KEY>>"
        }
      }
    },
    {
      "name": "Send Email",
      "type": "Agents::SendEmailAgent",
      "options": {
        "to": "<<SOC_EMAIL>>",
        "subject": "Security Alert: <<webhook_trigger.body.attack_type>>",
        "body": "src_ip: <<webhook_trigger.body.src_ip>>, dst_ip: <<webhook_trigger.body.dst_ip>>, affected_user: <<webhook_trigger.body.affected_user>>, timestamp: <<webhook_trigger.body.timestamp>>, MITRE ID: <<webhook_trigger.body.mitre_id>>, evidence: <<webhook_trigger.body.evidence>>"
      }
    },
    {
      "name": "Create Ticket",
      "type": "Agents::HTTPRequestAgent",
      "options": {
        "url": "<<TICKETING_URL>>/tickets",
        "method": "post",
        "payload": {
          "title": "Security Incident: <<webhook_trigger.body.attack_type>>",
          "priority": "high",
          "description": "src_ip: <<webhook_trigger.body.src_ip>>, evidence: <<webhook_trigger.body.evidence>>"
        },
        "headers": {
          "Authorization": "Bearer <<TICKETING_API_KEY>>"
        }
      }
    }
  ]
}

ATTACK-SPECIFIC MANDATORY ACTIONS:
Brute force — ALL FIVE agents are MANDATORY in this exact order:
  1. Webhook Trigger agent (Agents::WebhookAgent) — ALWAYS first, NEVER skip
  2. Block source IP agent using <<webhook_trigger.body.src_ip>>
  3. Disable user account agent — POST to <<IDENTITY_URL>>/disable
  4. Schedule IP unblock agent — POST to <<FIREWALL_URL>>/unblock with ttl_hours: 24 — NEVER skip this
  5. Send email agent with all six fields
  6. Create ticket agent
  NEVER omit the Webhook Trigger as first agent
  NEVER omit the Schedule IP Unblock agent — brute force IPs must always have a TTL unblock

Exfiltration — ALL SIX agents are MANDATORY in this exact order:
  1. Webhook Trigger agent (Agents::WebhookAgent) — ALWAYS first, NEVER skip
  2. Isolate endpoint agent using <<webhook_trigger.body.hostname>>
  3. Block destination IP agent using <<webhook_trigger.body.dst_ip>>
  4. Revoke sessions agent — ALWAYS include as a separate agent in the JSON
  5. Send email agent with all six fields
  6. Create ticket agent

STRICT RULES:
- ALWAYS use <<VARIABLE_NAME>> for every dynamic value — NEVER hardcode
- ALWAYS include all six fields in email body: src_ip, dst_ip, affected_user, timestamp, MITRE ID, evidence
- NEVER use hardcoded IPs in any agent
- ALWAYS chain agents in correct order
- ALWAYS close every placeholder with >> — never leave unclosed like <<VARIABLE>
- ALWAYS include the Revoke Sessions agent in the JSON actions when listed in steps — NEVER mention in steps but omit from JSON
- ALWAYS include MITRE ID in every email body
- ALWAYS close each agent object with } before opening the next agent — NEVER nest agents inside each other
- Every agent MUST be a separate object in the agents array: [{...}, {...}, {...}]
- NEVER omit the Schedule IP Unblock agent for brute force attacks

CRITICAL JSON SAFETY RULES:
- The outer code field MUST be on a SINGLE LINE — no literal newlines inside the code field
- Write the entire Tines JSON as a single compact minified string
- The frontend will automatically pretty print it
"""
}


def clean_json_response(text):
    text = text.strip()
    text = text.replace("```json", "").replace("```JSON", "").replace("```", "")

    start = text.find("{")
    end = text.rfind("}") + 1
    if start != -1 and end != 0:
        text = text[start:end]

    fixed = []
    in_string = False
    i = 0
    while i < len(text):
        char = text[i]

        if char == '"' and (i == 0 or text[i - 1] != '\\'):
            in_string = not in_string
            fixed.append(char)
            i += 1
            continue

        if in_string:
            if char == '\\' and i + 1 < len(text):
                next_char = text[i + 1]
                valid_escapes = set('"\\/bfnrtu')
                if next_char in valid_escapes:
                    fixed.append(char)
                    fixed.append(next_char)
                    i += 2
                else:
                    fixed.append('\\\\')
                    fixed.append(next_char)
                    i += 2
            elif char == '\n':
                fixed.append('\\n')
                i += 1
            elif char == '\r':
                fixed.append('\\r')
                i += 1
            elif char == '\t':
                fixed.append('\\t')
                i += 1
            elif char == '"':
                fixed.append('\\"')
                i += 1
            elif ord(char) < 32:
                i += 1
            else:
                fixed.append(char)
                i += 1
        else:
            fixed.append(char)
            i += 1

    result = ''.join(fixed).strip()

    # Last resort — strip any remaining hidden control characters
    try:
        json.loads(result)
    except json.JSONDecodeError:
        result = re.sub(r'[\x00-\x1f\x7f](?![nrtu"\\])', '', result)

    # Fix unescaped single quotes
    result = result.replace("\\'", "'")

    # Fix unicode escaped single quotes that break frontend JSON.parse
    result = result.replace("\\u0027", "'")

    return result


def ensure_list(value):
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        lines = [
            line.strip()
            for line in value.split('\n')
            if line.strip()
        ]
        return lines if lines else [value]
    return []


def default_siem_rule():
    return {
        "simpleExplanation": "",
        "technicalDetail": "",
        "whatItDetects": "",
        "whyGenerated": "",
        "evidence": "",
        "filename": "",
        "code": ""
    }


def default_soar_playbook():
    return {
        "simpleExplanation": "",
        "technicalDetail": "",
        "steps": [],
        "whyGenerated": "",
        "evidence": "",
        "filename": "",
        "code": ""
    }


def generate_siem_and_soar(finding, siem, soar):
    severity = finding.get("severity", "LOW").upper()

    time.sleep(8)

    if severity == "LOW":
        return {
            "siem_rule": default_siem_rule(),
            "soar_playbook": None
        }

    siem_prompt = SIEM_PROMPTS.get(siem, "Generate a valid SIEM detection rule.")
    soar_prompt = SOAR_PROMPTS.get(soar, "Generate a valid SOAR response workflow.")

    evidence_list = finding.get("evidence_quotes", [])
    evidence_text = "\n".join(evidence_list) if evidence_list else "No evidence provided"

    mitre_number = finding.get("mitre_id", "T10000").replace("T", "")
    try:
        rule_id = 100000 + int(mitre_number)
    except Exception:
        rule_id = 100001

    source_ips = finding.get("source_ips", [])
    destination_ips = finding.get("destination_ips", [])
    affected_users = finding.get("affected_users", [])

    source_ip_str = ", ".join(source_ips) if source_ips else "unknown"
    destination_ip_str = ", ".join(destination_ips) if destination_ips else "unknown"
    affected_users_str = ", ".join(affected_users) if affected_users else "unknown"

    if severity == "HIGH":
        soar_instruction = f"""
Generate SOAR playbook using this format:
{soar_prompt}
Respond specifically to: {finding.get("attack_name")}
"""
    else:
        soar_instruction = "Set soar_playbook to null. MEDIUM severity does not require SOAR."

    is_splunk_xsoar = (siem == "Splunk" and soar == "Palo Alto XSOAR")

    prompt = f"""
You are a world class Detection Engineer and SOAR Automation Expert.
Generate 10/10 production quality security code.

ATTACK DETAILS:
Attack Name: {finding.get("attack_name")}
Attack Description: {finding.get("attack_description")}
MITRE ID: {finding.get("mitre_id")}
MITRE Technique: {finding.get("mitre_name")}
MITRE Tactic: {finding.get("mitre_tactic")}
Severity: {severity}

EVIDENCE FROM REPORT:
{evidence_text}

IOCs — USE THESE EXACTLY IN YOUR RULES:
ATTACKER SOURCE IPS (use as srcip): {source_ip_str}
MALICIOUS DESTINATION IPS (use as dstip): {destination_ip_str}
AFFECTED USERS (use in user context rules): {affected_users_str}

STRICT IP RULES:
- ONLY use IPs listed above in srcip and dstip tags
- If multiple source IPs listed create one IOC rule per IP
- NEVER use any IP from evidence text that is not listed above
- NEVER guess or invent IPs not in the list above

SIEM RULE REQUIREMENTS:
{siem_prompt}
Attack: {finding.get("attack_name")}
MITRE: {finding.get("mitre_id")} - {finding.get("mitre_name")}
RULE ID: {rule_id}
Replace RULE_ID_HERE with: {rule_id}

SOAR REQUIREMENTS:
{soar_instruction}

EXPLANATION FORMAT:
simpleExplanation: {"1 sentence only." if is_splunk_xsoar else "2 sentences max. Plain English. No jargon."}
technicalDetail: {"1 sentence only." if is_splunk_xsoar else "2 sentences max. Field names and thresholds only."}
whatItDetects: {"3 words only." if is_splunk_xsoar else "what attack this catches."}
whyGenerated: {"1 sentence only." if is_splunk_xsoar else "why this rule was created."}

CRITICAL RULES:
- Code specific to this exact attack
- Production ready no placeholders
- NEVER use 2147483648 for bytes — always use exact evidence value e.g. 2469606195 for 2.3GB
- NEVER multiple match tags in Wazuh
- NEVER dstip for process execution
- NEVER text outside JSON
- Return ONLY valid JSON

MOST IMPORTANT JSON SAFETY RULE:
The "code" field value MUST be a single line string with no literal newlines.
Use spaces to separate lines of code. Do NOT press Enter inside the code field.
NEVER use backslash+letter sequences like \\S \\d \\w \\b inside JSON strings.
Use [^ ]+ instead of \\S+ and [0-9]+ instead of \\d+ in all regex inside JSON.

PLATFORM SPECIFIC CRITICAL RULES:
Splunk:
- ALWAYS format as: index=main sourcetype=X
- NEVER use index=sourcetype_name alone
- ALWAYS use field=_raw in rex patterns
- Use [^ ]+ instead of \\S+ in all rex patterns
- NEVER use src_ip field in WinEventLog:Security rules
- ALWAYS follow SPL order: rex -> where filter -> stats -> where threshold -> eval -> table
- ALWAYS separate dual rules with semicolon ; — NEVER use | index= to join rules
- Network behavioural rule: use where bytes > THRESHOLD not stats sum(bytes)

Palo Alto XSOAR:
- ALWAYS start with: import demistomock as demisto; from CommonServerPython import *; def main():
- ALL logic MUST be inside def main():
- NEVER put code outside main() except imports and if __name__ block
- ALWAYS end with: demisto.results("Done"); return; on the main() line
- ALWAYS add on a NEW semicolon-separated line: if __name__ in ("__main__", "__builtin__", "builtins"): main()
- NEVER use f-strings — use string concatenation with + instead
- NEVER hardcode any IP — always use demisto.args().get("field")
- affected_user in email MUST be demisto.args().get("affected_user") not hardcoded

IBM QRadar:
- NEVER add RULE_ID at end of query
- NEVER use destinationip for process execution
- ALWAYS use double quotes for all string values — NEVER single quotes

Tines:
- ALWAYS use <<VARIABLE_NAME>> placeholders
- NEVER hardcode credentials or URLs
- ALWAYS close each agent with }} before starting the next one
- NEVER nest agent objects inside each other

{"Return ONLY valid JSON no text outside the JSON:" if is_splunk_xsoar else "Return ONLY this exact JSON with no text outside it:"}

{{
  "siem_rule": {{
    "simpleExplanation": "plain english explanation here",
    "technicalDetail": "technical detail here",
    "whatItDetects": "attack type here",
    "whyGenerated": "reason here",
    "evidence": "exact evidence line from report",
    "filename": "appropriate_filename.txt",
    "code": "ALL CODE HERE ON ONE SINGLE LINE NO NEWLINES"
  }},
  "soar_playbook": {{
    "simpleExplanation": "plain english explanation here",
    "technicalDetail": "technical detail here",
    "steps": [
      "Step 1: action with detail",
      "Step 2: action with detail",
      "Step 3: action with detail"
    ],
    "whyGenerated": "reason here",
    "evidence": "exact evidence line from report",
    "filename": "appropriate_filename.txt",
    "code": "ALL CODE HERE ON ONE SINGLE LINE NO NEWLINES"
  }}
}}
"""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.1,
            max_tokens=3000
        )

        response_text = response.choices[0].message.content
        global daily_token_count
        daily_token_count += response.usage.total_tokens
        if daily_token_count >= MAX_DAILY_TOKENS:
            raise Exception("Daily free token limit reached. Try again tomorrow.")

        print(f"RAW for {finding.get('mitre_id')}: {response_text[:300]}")
        response_text = clean_json_response(response_text)
        print(f"CLEANED for {finding.get('mitre_id')}: {response_text[:300]}")

        parsed = json.loads(response_text)

        siem_rule = parsed.get("siem_rule", {})
        if not isinstance(siem_rule, dict):
            siem_rule = default_siem_rule()

        soar_playbook = parsed.get("soar_playbook", None)

        if severity == "MEDIUM":
            soar_playbook = None
        elif soar_playbook is not None:
            if not isinstance(soar_playbook, dict):
                soar_playbook = None
            else:
                soar_playbook["steps"] = ensure_list(
                    soar_playbook.get("steps", [])
                )

        return {
            "siem_rule": siem_rule,
            "soar_playbook": soar_playbook
        }

    except json.JSONDecodeError as e:
        print(f"JSON ERROR for {finding.get('mitre_id')}: {str(e)}")
        return {
            "siem_rule": default_siem_rule(),
            "soar_playbook": None
        }

    except Exception as e:
        import traceback
        print(f"ERROR for {finding.get('mitre_id')}: {str(e)}")
        print(traceback.format_exc())
        return {
            "siem_rule": default_siem_rule(),
            "soar_playbook": None
        }


def analyze_report(report_text: str, siem: str, soar: str) -> dict:

    time.sleep(2)

    analysis_prompt = f"""
You are an expert SOC Analyst with 20 years of experience.

Analyze the SOC report and extract ALL security findings.

CRITICAL RULES:
- Extract every single finding in the report
- Do NOT stop after first finding
- Do NOT generate any code
- Only attack identification and MITRE mapping
- Use only evidence from the report
- Do not invent attacks not mentioned
- evidence_quotes must be exact lines from report

SEVERITY RULES based on evidence only:
HIGH: Evidence shows active exploitation confirmed,
      large number of attempts visible in evidence,
      data transfer amounts mentioned in evidence,
      command execution confirmed in evidence,
      multiple systems affected
MEDIUM: Suspicious activity observed in evidence
        but not fully confirmed,
        moderate attempts visible in evidence,
        unusual but not clearly malicious
LOW: Single events only,
     informational or reconnaissance only,
     no follow through visible in evidence

IOC EXTRACTION RULES:
- source_ips: IPs INITIATING the attack
  Look for phrases: "from IP", "originated from", "source IP",
  "attacker IP", "failed attempts from", "observed from"
  ORDER by most explicitly labeled as attacker first
  The SOURCE is always the one INITIATING the connection
- destination_ips: IPs RECEIVING connections or data sent TO
  Look for phrases: "to IP", "detected to", "outbound to",
  "external IP", "traffic to", "connected to"
  The DESTINATION is always the one RECEIVING the connection
- affected_users: usernames mentioned as victims or compromised accounts
- Extract ALL timestamps mentioned in evidence

RECOMMENDATIONS RULES:
- NEVER give generic advice
- ALWAYS reference specific IPs, usernames, timestamps from evidence
- Format: "Block [SPECIFIC_IP] immediately because [EXACT_EVIDENCE]"
- Minimum 3 specific recommendations per finding

REMEDIATION CHECKLIST RULES:
- Step by step checklist for human analyst
- Each step must reference specific IOCs from evidence
- Include immediate actions and follow-up investigation steps
- Minimum 5 checklist items per finding

Return ONLY this exact JSON:

{{
  "findings": [
    {{
      "attack_name": "specific attack name",
      "attack_description": "one sentence description",
      "evidence_quotes": [
        "exact verbatim quote from report",
        "another exact quote if available"
      ],
      "mitre_id": "T1234",
      "mitre_name": "Exact MITRE Technique Name",
      "mitre_tactic": "Exact MITRE Tactic Name",
      "severity": "HIGH",
      "explanation": "plain english explanation",
      "source_ips": ["ip1", "ip2"],
      "destination_ips": ["ip1", "ip2"],
      "affected_users": ["user1", "user2"],
      "recommendations": [
        "Block [SPECIFIC_IP] immediately because [EXACT_EVIDENCE]",
        "Investigate [SPECIFIC_USER] account because [EXACT_EVIDENCE]",
        "Check logs for [SPECIFIC_IP] lateral movement"
      ],
      "remediation_checklist": [
        "[ ] Block 192.168.1.105 at perimeter firewall immediately",
        "[ ] Reset admin account password",
        "[ ] Check successful logins between 02:00-02:14 UTC",
        "[ ] Review all auth logs for attacker IP",
        "[ ] Enable account lockout after 5 failed attempts"
      ]
    }}
  ]
}}

SOC REPORT:
{report_text}
"""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "user",
                    "content": analysis_prompt
                }
            ],
            temperature=0.1,
            max_tokens=3000
        )

        response_text = clean_json_response(
            response.choices[0].message.content
        )
        global daily_token_count
        daily_token_count += response.usage.total_tokens
        if daily_token_count >= MAX_DAILY_TOKENS:
            raise Exception("Daily free token limit reached. Try again tomorrow.")
        print(f"ANALYSIS RESPONSE: {response_text[:300]}")

        result = json.loads(response_text)

        for finding in result.get("findings", []):
            generated = generate_siem_and_soar(finding, siem, soar)
            finding["siem_rule"] = generated.get(
                "siem_rule",
                default_siem_rule()
            )
            finding["soar_playbook"] = generated.get(
                "soar_playbook",
                None
            )

        return result

    except json.JSONDecodeError as e:
        print(f"ANALYSIS JSON ERROR: {str(e)}")
        return {
            "findings": [],
            "error": "Failed to parse AI response"
        }

    except Exception as e:
        print(f"ANALYSIS ERROR: {str(e)}")
        return {
            "findings": [],
            "error": str(e)
        }