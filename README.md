# DNS Detection and Analytics Freeware

## Overview
DNS Detection and Analytics is released as an open-source tool to enable users to make sense of DNS data, analyse user behaviour and detect cybersecurity risks. It comes bundled with a no-restriction right to use of AttackFence's Threat Intelligence Cloud for threat detection.

## Table of Contents
- [Analytics Features](#analytics-features)
  - [Conversation Summary](#conversation-summary)
  - [Query/Response Summary](#queryresponse-summary)
  - [Query Type Breakup](#query-type-breakup)
  - [Response Code Breakup](#response-code-breakup)
  - [Query Name Length](#query-name-length)
  - [Label Count Length](#label-count-length)
  - [TTL Value](#ttl-value)
  - [Conversation Summary by TLD](#conversation-summary-by-tld)
  - [DGA Summary](#dga-summary)

- [Detection Features](#detection-features)
  - [Beaconing Detection](#beaconing-detection)
  - [DNS Tunneling Detection](#dns-tunneling-detection)
  - [DGA Detection](#dga-detection)
  - [IOC Correlation](#ioc-correlation)

- [Installation](#installation)
- [Usage](#usage)
- [PDF Report](#pdf-report)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

### Analytics Features
- Conversation Summary: Understand communication patterns between hosts, helping you identify normal and potentially suspicious interactions.

- Query/Response Summary: Gain insights into the overall DNS traffic flow, enabling you to assess the health and efficiency of your network.

- Query Type Breakup: Analyze the types of queries to better understand the nature of DNS requests and potential areas of interest.

- Response Code Breakup: Identify and troubleshoot issues by examining response codes, ensuring a smooth DNS resolution process.

- Query Name Length: Detect anomalies or potential security threats by analyzing variations in query name lengths.

- Label Count Length: Understand label count distributions, aiding in the identification of irregularities in DNS query structures.

- TTL Value: Optimize DNS performance and reliability by analyzing Time-to-Live (TTL) values.
- Conversation Summary by TLD: Profile DNS conversations by top-level domain, providing insights into the origin and nature of traffic.

- DGA Summary: Detect potential threats by identifying hosts exhibiting behaviour indicative of Domain Generation Algorithms (DGA).

### Detection Features
- Beaconing Detection: 
Identify hosts engaging in continuous outbound DNS traffic, a potential sign of beaconing, using a 24-hour timeframe.

- DNS Tunneling Detection: 
Spot abnormal DNS tunneling activities, safeguarding against potential security breaches.

- DGA Detection: 
Detect hosts using Domain Generation Algorithms to generate malicious domain names, providing an early warning of potential threats.

- IOC Correlation: 
Correlate domain names and IP addresses with AttackFence Threat Intel, enhancing your ability to identify and mitigate threats effectively.

-----

## Installation & Prerequisites

The installers check for the following prerequisites and install whatever is missing:

- Python: DNS Detection and Analytics requires Python. If you don't have Python installed, you can download and install it from the official [Python website](https://www.python.org/downloads/). The version must be lower than or equal to 3.11
  Download the exe file and run it on your system
- Wireshark: Although the package only requires Tshark but in Windows operating system you need to download the executable file of Wireshark from the Wireshark official [Wireshark website](https://www.wireshark.org/download.html). The tshark will be installed with it as well.
- Python packages: aiohttp and matplotlib (matplotlib generates the PDF report).
- Threat-intel access: copy `scripts/src/ti_config.example.json` to `scripts/src/ti_config.json` (in the Windows and/or Linux directory) and fill in the TI server address and licence key before installing or building Donatix.exe. `ti_config.json` is ignored by git; never commit it or publish a Donatix.exe built with it.

## Usage
### For Windows.
  - Run Donatix.exe from Windows Directory. It installs the project to C:\Donatix, installs any missing prerequisite (Python, Wireshark, aiohttp, matplotlib) and creates the scheduled tasks.
  - To run from a source checkout instead of installing, run install.bat from Windows Directory (it asks for administrator rights).
  - Donatix.exe is built from Donatix.iss with Inno Setup (```ISCC.exe Donatix.iss```) and must be rebuilt after changing any script.
    - Open task schedular application and go into the task schedular library and Run the following tasks with highest privileges.
      -   DNSDataAnalytics.
      -   TiAnalytics.
      -   findBeaconingHosts.
      -   DGAEvaluation.
      -   findDnsTunnelingHosts.
      -   TsharkQuery
      
### For Linux.
  - Run ``` sudo ./installPackages.sh ``` from Linux Directory.

## Uninstall
  - Windows: run uninstall.bat from Windows Directory (it asks for administrator rights).
  - Linux: run ``` sudo bash uninstall.sh ``` from Linux Directory.

Both remove the scheduled tasks / services and the installed scripts, and ask before deleting the captured DNS data. The prerequisites (Python, Wireshark/Tshark, aiohttp, matplotlib and the other packages) are left installed.

## PDF Report
The analytics and detections are published as a PDF, generated on demand from the captured data.

The easiest way is to stop Donatix with the report shortcut: it stops the capture and saves the report covering all captured data to your Downloads folder.

  - Windows: use the "Stop Donatix and get report" shortcut on the desktop or in the Start menu, or run StopDonatix.bat from the Windows directory. It asks for administrator rights and opens the report when it is ready.
  - Linux: run ```sudo bash stopDonatix.sh``` from the Linux directory. The report goes to ~/Downloads of the user who ran sudo, and the script prints the ```scp``` command that copies it to your own computer. Works on a headless server (e.g. Ubuntu Server minimal); no desktop is needed.
  - To start capturing again, use the "Start Donatix" Start menu shortcut or run StartDonatix.bat (Windows), or run ```sudo bash startDonatix.sh``` (Linux). Nothing is reinstalled and the captured data is kept.

To create a report without stopping Donatix:

  - Windows: run ```python generateReport.py``` from the Windows\scripts\src directory.
  - Linux: run ```sudo -u attackfence python3 /opt/attackfence/Donatix/Linux/scripts/src/generateReport.py -o /tmp/Donatix_Report.pdf```

Options:
  - ```-o report.pdf``` : where to write the report (default: Donatix_Report_<date>.pdf in the current directory).
  - ```--days N``` : only report on the last N days (default: all captured data).

Every chart carries a plain-language "What it shows" note and a "Takeaway" tagged ALERT, REVIEW, NORMAL or LIKELY FALSE ALARM. The takeaways, overall assessment and recommended actions are derived from the data by rules in generateReport.py.

Report contents:
  - Page 1, Executive Summary: overall risk assessment, the three attack patterns (DNS tunneling, DGA, beaconing) with their evidence, probable false alarms and blind spots.
  - Page 2, Overview: number of DNS queries, responses, hosts, domains queried, DGA domains and malicious/suspicious indicators, queries/responses over time (split into capture sessions) and takeaways for management.
  - Page 3, Traffic Breakdown: query types (A, AAAA, PTR, ...), response codes, top level domains and DNS servers by queries.
  - Page 4, Hosts and Domains: top domains, queries by host, distinct domains visited by host, and query name length, label count and TTL statistics.
  - Page 5, Threat Intelligence and DGA Detection: threat intel verdicts, flagged indicators, DGA queries by host and DGA domains.
  - Page 6, Beaconing and DNS Tunneling Detection: beaconing hosts, DNS tunneling domains and data quality notes.
  - Page 7, Recommended Next Steps and Glossary: prioritised actions and plain-language definitions.

