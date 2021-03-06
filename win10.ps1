### Upgrade or uninstall applications
### 1 = upgrade or install
### 0 = uninstall
### remove or comment out unwanted apps
$apps = @{
    7Zip         = 1;
    CCleaner     = 1;
    Chromium     = 1;
    Discord      = 1;
    Dropbox      = 1;
    EqualizerApo = 1;
    Firefox      = 1;
    HandBrake    = 1;
    Laragon      = 1;
    MPC-HC       = 1;
    NVDA         = 1;
    PeaZip       = 1;
    Potplayer    = 1;
    PowerToys    = 1;
    SumatraPDF   = 1;
    Thunderbird  = 1;
    VSCode       = 1;
    WinCDEmu     = 1;
}

### Apply or rollback tweaks
### 1 = apply tweak
### 0 = rollback tweak (to default)
### remove or comment out unwanted tweaks
$tweaks = @{
    ActivityHistory     = 1;
    AdvertisingID       = 1;
    AppSuggestions      = 1;
    BackgroundApps      = 1;
    Cortana             = 1;
    Defender            = 1;
    DiagnosticsTracking = 1;
    ErrorReporting      = 1;
    Feedback            = 1;
    LocationTracking    = 1;
    MapUpdates          = 1;
    OOShutup            = 1;
    SmartScreen         = 1;
    TailoredExperiences = 1;
    Telemetry           = 1;
    WebSearch           = 1;
    WiFiSense           = 1;
}
function InstallChocolatey {
    $testchoco = powershell choco -v
    if (-not($testchoco)) {
        Write-Output "Installing Chocolatey"
        Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
        choco upgrade chocolatey-core.extension -y
    }
    else {
        Write-Output "Chocolatey Version $testchoco is already installed"
    }
}
function InstallApps {
    foreach ($app in $apps.keys) {
        if ($apps.$app -contains $true) {
            Write-Output "Installing or upgrading $app..."
            choco upgrade $app.ToLower() -y
        }
        elseif ($apps.$app -contains $false) {
            Write-Output "Unstalling $app..."
            choco uninstall $app.ToLower() -x
        }
    }
}
function LoadTweaks {
    Write-Output "Load Tweaks"
    Import-Module BitsTransfer
    Start-BitsTransfer -Source "https://raw.githubusercontent.com/svanlaere/win10script/master/tweaks.psm1" -Destination tweaks.psm1
    Import-Module ./tweaks.psm1
}
function ApplyTweaks {
    foreach ($tweak in $tweaks.keys) {
        $params = '-enable'
        $bool = [int]$tweaks.$tweak; 
        Invoke-Expression "$tweak $params $bool"
    }
}

InstallChocolatey
InstallApps
LoadTweaks
ApplyTweaks