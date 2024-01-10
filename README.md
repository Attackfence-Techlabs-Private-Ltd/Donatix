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
- [Power-BI Details](#)
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
  - Run the powershell as administrator and run this command ```Set-ExecutionPolicy -RemoteSigned``` .
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

## Power-BI Details
### Slide 1:
  - Count of Threat Intel Verdict:
    - Purpose: Count of Threat Intel Verdict like benign, unknown, suspicious, malicious, etc.
    - Data Source:dns_query_data.
    - Fields:
      - Values = Count of tiVerdict ,
      - Category = tiVerdict.
  - Unknown Communication By Host:
    - Purpose: Count of Unknown Communication by Host.
    - Data Source:dns_query_data .
    - Fields: 
      - Values = Count of Unknown tiVerdict, 
      - Category = src.
  - Suspicious Communication By Host:
    - Purpose: Count of Suspicious Communication by Host.
    - Data Source:dns_query_data .
    - Fields: 
      - Values = Count of Unknown tiVerdict, 
      - Category = src.

### Slide 2:
  - Sum Of Label Length By Date:
    - Purpose: Sum of averageLabelLen, Sum of maximumLabelLen, and Sum of minimumLabelLen by Date.
    - Data Source: labelCountLength.
    - Fields: 
      - Values = averageLavelLen, maximumLabelLength, minimumLabelLengt,  
      - Category = Date.
  - Number Of Queries and Responses By Date:
    - Purpose: Total number of queries and Responses by date.
    - Data Source:queryResponseSummary.
    - Fields: 
      - Values = Sum of numQueries and numResponses, etc., 
      - Category = numQueries, numResponses.
  - Sum Of Query length By Date:
    - Purpose: Sum of averageQueryLen, Sum of maximumQueryLen, and Sum of minimumQueryLen by Date.
    - Data Source:queryNameLength .
    - Fields: 
      - Values = Sum of averageQueryLen, Sum of maximumQueryLen, and Sum of minimumQueryLen, 
      - Category = Date.
  - Sum Of DNS Record By Date:
    - Purpose: Sum of query type (e.g., A, AAAA, TXT) by Date.
    - Data Source: queryTypeBreakUp.
    - Fields: 
      - Values = Sum of Arecord, AAAArecord, OtherRecord., 
      - Category = Date.
  - Count Of Response Codes by Date:
    - Purpose: Count Of Response Code like (0,1,2,3 etc) By Date.
    - Data Source: responseCodeBreakUp.
    - Fields:  
      - Values =Count of noResponse, rcodeOne, rcodeThree, rcodeTwo, rcodeZero.
      - Category = Date.

### Slide 3:
  - Sum Of Queries and Responses By Source:
    - Purpose: Total number of queries and Responses by Source.
    - Data Source: tldConversationSummary.
    - Fields: 
      - Values = Sum of numQueries and numResponses, etc., 
      - Category = srcIp.
  - Count of Top Label Domains ( tld):
    - Purpose: Count of Top Label Domains ( tld).
    - Data Source: tldConversationSummary.
    - Fields: 
      - Values =Count of tld, 
      - Category = tld.

### Slide 4:
  - Top Domains By Query Volume
      - Purpose: Identify most frequently queried domains.
      - Data Source: dns_query_data
      - Fields:
        - Values = Count of qname,
        - Category = qname
  - Response Code Distribution
      - Purpose: Understand response code occurrences (e.g., successful, failed).
      - Data Source: responseCodeBreakUp
      - Fields:
        - Values = Count of rcodeZero, rcodeOne, etc.,
        - Category = rcodeZero, rcodeOne, etc.
  - Top DNS Servers
      - Purpose: Identify most used DNS servers.
      - Data Source: dns_query_data
      - Fields:
        - Values = Count of dst,
        - Category = dst.
  - Query Type Distribution
      - Purpose: Understand query type usage (e.g., A, AAAA, TXT).
      - Data Source: queryTypeBreakUp.
      - Fields:
        - Values = Count of Arecord, AAAArecord, etc.,
        - Category = Arecord, AAAArecord, etc.
  - Average TLD Conversation Length
      - Purpose: Analyze query lengths for different TLDs
      - Data Source: tldConversationSummary.
      - Fields:
        - Axis = tld,
        - Values = averageQueryLength.
  - Total DNS Queries
      - Purpose: Monitor overall DNS activity and potential load.
      - Data Source: queryResponseSummary table
      - Fields:
        - Value: totalQueryCount
      - Example Appearance: Large number with label "Total DNS Queries: 123,456".
        
### Slide 5:
  - Average DGA Score By Source
    - Purpose: Analyze DGA scores by sources.
    - Data Source: dgaSummary.
    - Fields:
      - Values = Average of isDGA ,
      - Category = src.
  - Average DGA Score by Source And Date
    - Purpose: Analyze DGA scores by sources and date.
    - Data Source: dgaSummary.
    - Fields:
      - Values = Average of isDGA,
      - Category = src, date.
  - Top 10 Source with Max DGA Scores.
    - Purpose: Monitor overall Source with their DGA Scores.
    - Data Source: dgaSummary table
    - Fields:
      - Value = Max of isDGA,
      - Category = src.
        
### Slide 6:
  - DNS Activity By User:
    - Purpose: Visualize DNS query and response patterns for individual users to identify unusual behavior or potential threats.
    - Data Source: dns_query_data table
    - Fields:
      - X-axis: Time (e.g., day, Month, Year),
      - Y-axis: Query/response count.

  - No Of Domains Visited By User:
    - Purpose: Reveals the most frequented domains by individual users for insights into browsing habits and potential risks.
    - Data Source: dns_query_data table
    - Fields:
      - Values: Query count for each domain

