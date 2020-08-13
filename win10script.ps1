### Upgrade or uninstall applications
### 1 = upgrade (or install)
### 0 = uninstall
$apps = @{
    Potplayer  = 1;
    SumatraPDF = 1;
}

### Enable or disable tweaks
### 1 = enable
### 0 = disable
$tweaks = @{
    OOShutup = 1;
    Defender = 1;
}

function LoadTweaks {
    Write-Output "Load Tweaks"
    Import-Module BitsTransfer
    Start-BitsTransfer -Source "https://raw.githubusercontent.com/svanlaere/win10script/master/tweaks.psm1" -Destination tweaks.psm1
    Import-Module ./tweaks.psm1
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
            choco upgrade $app.ToLower() -y
        }
        elseif ($apps.$app -contains $false) {
            choco uninstall $app.ToLower() -x
        }
    }
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