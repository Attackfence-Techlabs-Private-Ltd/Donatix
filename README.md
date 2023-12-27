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

Before installing DNS Detection and Analytics, ensure you have the following prerequisites installed:

- Python: DNS Detection and Analytics requires Python. If you don't have Python installed, you can download and install it from the official [Python website](https://www.python.org/downloads/). The version must be lower than or equal to 3.11
  Download the exe file and run it on your system
- Wireshark: Although the package only requires Tshark but in Windows operating system you need to download the executable file of Wireshark from the Wireshark official [Wireshark website](https://www.wireshark.org/download.html). The tshark will be installed with it as well.
- Install Power BI for visualization:
  - Download and install Power BI Desktop from [Power BI Desktop](https://powerbi.microsoft.com/en-us/desktop/) 

## Usage
### For Windows.
  - Run Donatix.exe to run the project from Windows Directory.
  - Power BI Setup:
    - Install Power BI Desktop on the New Machine:
      - In the new Power BI Desktop > Right click,  
      - Run as administrator.
      - go to File > Open and select the donatix.pbit file at location ‘C:\Donatix\Windows\scripts\src\donatix.pbit’.
      - It will start showing data.
    
    - Update Data Source Credentials (if applicable):
    If you used username/password or other credentials to connect to the SQLite database, you might need to update them for the new machine.
    Change the source path: Go to File > Options and settings > Data source settings  .
    
    - Refresh Data:
    Right-click on the dataset and select Refresh to ensure the connection and data are up-to-date.
    
    - Additional Considerations:
      - Gateway Configuration: If you used a gateway for data access, configure it appropriately on the new machine.
      - Visual Customizations: Any custom visuals you used need to be installed on the new machine as well.
      - Shared Data Sources: If the original data source is shared, ensure the new machine has access to it.
      - Version Compatibility: Use compatible Power BI versions on both machines to avoid issues.

    - Open task schedular application and go into the task schedular library and Run the following tasks with highest privileges.
      -   DNSDataAnalytics.
      -   TiAnalytics.
      -   findBeaconingHosts.
      -   DGAEvaluation.
      -   findDnsTunnelingHosts.
      -   TsharkQuery
      
### For Linux.
  - Run ``` sudo ./installPackages.sh ``` from Linux Directory.
