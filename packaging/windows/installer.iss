#ifndef AppVersion
  #error AppVersion must be supplied by the build
#endif
#ifndef SourceDir
  #error SourceDir must be supplied by the build
#endif
#ifndef OutputDir
  #error OutputDir must be supplied by the build
#endif

[Setup]
AppId={{9F00CC77-27A7-4AE4-9965-D6059E53019C}
AppName=Advanced IP Analyser
AppVersion={#AppVersion}
AppPublisher=2E0LXY
AppPublisherURL=https://github.com/2E0LXY/Advanced-IP-Analyser
AppSupportURL=https://github.com/2E0LXY/Advanced-IP-Analyser/issues
AppUpdatesURL=https://github.com/2E0LXY/Advanced-IP-Analyser/releases
DefaultDirName={localappdata}\Programs\Advanced IP Analyser
DefaultGroupName=Advanced IP Analyser
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename=Advanced-IP-Analyser-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=force
RestartApplications=yes
SetupLogging=yes
UninstallDisplayIcon={app}\Advanced-IP-Analyser.exe

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Advanced IP Analyser"; Filename: "{app}\Advanced-IP-Analyser.exe"
Name: "{autodesktop}\Advanced IP Analyser"; Filename: "{app}\Advanced-IP-Analyser.exe"; Tasks: desktopicon
Name: "{userstartup}\Advanced IP Analyser Background Monitor"; Filename: "{app}\Advanced-IP-Analyser.exe"; Parameters: "--background-monitor"; Tasks: backgroundmonitor

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"
Name: "backgroundmonitor"; Description: "Start local network monitoring automatically when I sign in"; GroupDescription: "Monitoring:"; Flags: checkedonce

[Run]
Filename: "{app}\Advanced-IP-Analyser.exe"; Description: "Launch Advanced IP Analyser"; Flags: nowait postinstall skipifsilent
Filename: "{app}\Advanced-IP-Analyser.exe"; Flags: nowait; Check: SilentRelaunchRequested

[Code]
procedure StopProcessImage(const ImageName: String);
var
  ResultCode: Integer;
begin
  { Restart Manager cannot reliably close console-only MCP and background-monitor
    processes. Kill every process with our exact executable names before setup
    replaces files. /T also closes any child processes they started. }
  Exec(ExpandConstant('{sys}\taskkill.exe'),
    '/F /T /IM "' + ImageName + '"', '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode);
end;

procedure StopRunningApplicationProcesses;
var
  Attempt: Integer;
begin
  { Repeat to cover an MCP client attempting an immediate restart while setup is
    beginning. A missing process is expected and taskkill's exit code is ignored. }
  for Attempt := 1 to 3 do
  begin
    StopProcessImage('Advanced-IP-Analyser-MCP.exe');
    StopProcessImage('Advanced-IP-Analyser.exe');
    Sleep(250);
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopRunningApplicationProcesses;
  Result := '';
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
    StopRunningApplicationProcesses;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    StopRunningApplicationProcesses;
end;

function SilentRelaunchRequested: Boolean;
begin
  Result := WizardSilent and (ExpandConstant('{param:RELAUNCH|0}') = '1');
end;
