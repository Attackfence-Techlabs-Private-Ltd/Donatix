; Builds Donatix.exe. Compile with: ISCC.exe Donatix.iss

[Setup]
AppName=Donatix
AppVersion=1.1
AppPublisher=AttackFence
; dga_evaluate.exe has C:\Donatix compiled in, so the install location is fixed
DefaultDirName=C:\Donatix
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=.
OutputBaseFilename=Donatix
Compression=lzma2
SolidCompression=yes

[Files]
Source: "install.bat"; DestDir: "{app}\Windows"; Flags: ignoreversion
Source: "StopDonatix.bat"; DestDir: "{app}\Windows"; Flags: ignoreversion
Source: "StartDonatix.bat"; DestDir: "{app}\Windows"; Flags: ignoreversion
Source: "dga_evaluate.exe"; DestDir: "{app}\Windows"; Flags: ignoreversion
; The MSYS2 runtime libraries dga_evaluate.exe was built against, it does not start without them
Source: "*.dll"; DestDir: "{app}\Windows"; Flags: ignoreversion
Source: "scripts\services\*"; DestDir: "{app}\Windows\scripts\services"; Flags: ignoreversion
Source: "scripts\src\*.py"; DestDir: "{app}\Windows\scripts\src"; Flags: ignoreversion
; Threat-intel address and licence key; not in git, so the built Donatix.exe must not be published
Source: "scripts\src\ti_config.json"; DestDir: "{app}\Windows\scripts\src"; Flags: ignoreversion
Source: "scripts\src\brand\*"; DestDir: "{app}\Windows\scripts\src\brand"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Stops the capture and drops the PDF report into the user's Downloads folder
Name: "{autoprograms}\Stop Donatix and get report"; Filename: "{app}\Windows\StopDonatix.bat"
Name: "{autodesktop}\Stop Donatix and get report"; Filename: "{app}\Windows\StopDonatix.bat"
; Starts the capture again after it was stopped
Name: "{autoprograms}\Start Donatix"; Filename: "{app}\Windows\StartDonatix.bat"

[Run]
; Installs the missing prerequisites (Python, Wireshark, aiohttp, matplotlib) and creates the scheduled tasks
Filename: "{app}\Windows\install.bat"; StatusMsg: "Checking prerequisites and creating scheduled tasks..."

[UninstallRun]
Filename: "schtasks"; Parameters: "/delete /tn DNSDataAnalytics /f"; Flags: runhidden; RunOnceId: "DNSDataAnalytics"
Filename: "schtasks"; Parameters: "/delete /tn TiAnalytics /f"; Flags: runhidden; RunOnceId: "TiAnalytics"
Filename: "schtasks"; Parameters: "/delete /tn findBeaconingHosts /f"; Flags: runhidden; RunOnceId: "findBeaconingHosts"
Filename: "schtasks"; Parameters: "/delete /tn DGAEvaluation /f"; Flags: runhidden; RunOnceId: "DGAEvaluation"
Filename: "schtasks"; Parameters: "/delete /tn findDnsTunnelingHosts /f"; Flags: runhidden; RunOnceId: "findDnsTunnelingHosts"
Filename: "schtasks"; Parameters: "/delete /tn TsharkQuery /f"; Flags: runhidden; RunOnceId: "TsharkQuery"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\Windows\scripts\src\__pycache__"

[Code]
const
  InstallDir = 'C:\Donatix';

function GetFileAttributes(lpFileName: String): Integer;
  external 'GetFileAttributesW@kernel32.dll stdcall';

// Installing over a source checkout would overwrite it, and uninstalling would delete it.
// A link is checked for separately: Setup does not follow links made by non-administrators.
function InitializeSetup(): Boolean;
var
  Attributes: Integer;
begin
  Attributes := GetFileAttributes(InstallDir);
  Result := not (DirExists(InstallDir + '\.git') or
                 ((Attributes <> -1) and ((Attributes and FILE_ATTRIBUTE_REPARSE_POINT) <> 0)));
  if not Result then
    SuppressibleMsgBox(InstallDir + ' is a source checkout, or a link to one.' + #13#10 +
           'Run Windows\install.bat from the checkout instead, or remove the ' + InstallDir + ' link first.',
           mbError, MB_OK, IDOK);
end;
