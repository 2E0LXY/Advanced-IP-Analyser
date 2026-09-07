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

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
Filename: "{app}\Advanced-IP-Analyser.exe"; Description: "Launch Advanced IP Analyser"; Flags: nowait postinstall skipifsilent
Filename: "{app}\Advanced-IP-Analyser.exe"; Flags: nowait; Check: SilentRelaunchRequested

[Code]
function SilentRelaunchRequested: Boolean;
begin
  Result := WizardSilent and (ExpandConstant('{param:RELAUNCH|0}') = '1');
end;
