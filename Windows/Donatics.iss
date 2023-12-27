; Script generated by the Inno Setup Script Wizard.
; SEE THE DOCUMENTATION FOR DETAILS ON CREATING INNO SETUP SCRIPT FILES!

[Setup]
AppName=DONATICS
AppVersion=1.0
DefaultDirName=C:\donaticsInstaller\
OutputDir=C:\
OutputBaseFilename=DNSFreeware

[Files]
Source: "C:\donaticsInstaller\Windows\scripts\src\noname.py"; DestDir: "C:\donaticsInstaller\Windows\scripts\src\";
Source: "C:\donaticsInstaller\Windows\scripts\src\analyseDNSData.py"; DestDir: "C:\donaticsInstaller\Windows\scripts\src\"; 
Source: "C:\donaticsInstaller\Windows\scripts\src\analyticsTIReq.py"; DestDir: "C:\donaticsInstaller\Windows\scripts\src\"; 
Source: "C:\donaticsInstaller\Windows\scripts\src\beaconingHosts.py"; DestDir: "C:\donaticsInstaller\Windows\scripts\src\"; 
Source: "C:\donaticsInstaller\Windows\scripts\src\dbasemgmt.py"; DestDir: "C:\donaticsInstaller\Windows\scripts\src\"; 
Source: "C:\donaticsInstaller\Windows\scripts\src\dnsTunnelingHosts.py"; DestDir: "C:\donaticsInstaller\Windows\scripts\src\"; 
Source: "C:\donaticsInstaller\Windows\dga_evaluate.exe"; DestDir: "C:\donaticsInstaller\Windows\"; 
Source: "C:\donaticsInstaller\Windows\scripts\services\tsharkQuery.ps1"; DestDir: "C:\donaticsInstaller\Windows\"; 
Source: "C:\donaticsInstaller\Windows\scripts\services\dns_data_insertion.bat"; DestDir: "C:\donaticsInstaller\Windows\scripts\services\"; 
Source: "C:\donaticsInstaller\Windows\scripts\services\dns_tunneling_hosts.bat"; DestDir: "C:\donaticsInstaller\Windows\scripts\services\"; 
Source: "C:\donaticsInstaller\Windows\scripts\services\run_tshark_data_query.bat"; DestDir: "C:\donaticsInstaller\Windows\scripts\services\"; 
Source: "C:\donaticsInstaller\Windows\scripts\services\dns_tunneling_hosts.bat"; DestDir: "C:\donaticsInstaller\Windows\scripts\services\"; 
Source: "C:\donaticsInstaller\Windows\scripts\services\analytics_ti_req.bat"; DestDir: "C:\donaticsInstaller\Windows\scripts\services\"; 
Source: "C:\donaticsInstaller\Windows\scripts\services\dga_evaluation.bat"; DestDir: "C:\donaticsInstaller\Windows\scripts\services\"; 
Source: "C:\donaticsInstaller\README.md"; DestDir: "C:\donaticsInstaller\"; 


[Run]
Filename: "C:\donaticsInstaller\Windows\scripts\services\run_tshark_data_query.bat"; Description: "Run Tshark batch"; Flags: postinstall shellexec
Filename: "C:\donaticsInstaller\Windows\scripts\services\dns_data_insertion.bat"; Description: "Run DNS Data batch"; Flags: postinstall shellexec
Filename: "C:\donaticsInstaller\Windows\scripts\services\analytics_ti_req.bat"; Description: "Run analyticsTIReq batch"; Flags: postinstall shellexec
Filename: "C:\donaticsInstaller\Windows\scripts\services\dga_evaluation.bat"; Description: "Run dga_evaluation batch"; Flags: postinstall shellexec
Filename: "C:\donaticsInstaller\Windows\scripts\services\beaconing_hosts.bat"; Description: "Run beaconingHosts batch"; Flags: postinstall shellexec
Filename: "C:\donaticsInstaller\Windows\scripts\services\dns_tunneling_hosts.bat"; Description: "Run DnsTunnelingHosts batch"; Flags: postinstall shellexec
