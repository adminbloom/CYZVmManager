using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace VmManager.Backends.HyperV;

/// <summary>
/// Import, clone, locale configuration and disk reset operations.
/// </summary>
public class HyperVImportService
{
    private readonly ILogger<HyperVImportService> _logger;
    private readonly PowerShellRunner _ps;

    public HyperVImportService(ILogger<HyperVImportService> logger, PowerShellRunner ps)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(ps);
        _logger = logger;
        _ps = ps;
    }

    public async Task ImportVmAsync(
        string extractedFolder,
        string localVmPath,
        int memoryMb,
        int cpuCount,
        string? vmName = null,
        bool skipDefaultNetwork = false,
        string? vmSwitch = null
    )
    {
        _logger.LogInformation(
            "Importing VM {VmName} from {Folder} (Memory={MemoryMb}MB, CPU={CpuCount})",
            vmName ?? "auto",
            extractedFolder,
            memoryMb,
            cpuCount
        );
        string parentVhdx =
            Directory
                .GetFiles(extractedFolder, "*.vhdx", SearchOption.AllDirectories)
                .Concat(Directory.GetFiles(extractedFolder, "*.avhdx", SearchOption.AllDirectories))
                .FirstOrDefault()
            ?? throw new FileNotFoundException(
                $"No .vhdx / .avhdx file found in: {extractedFolder}"
            );

        string folderName = Path.GetFileName(extractedFolder);
        string? baseName = vmName;
        if (string.IsNullOrEmpty(baseName))
        {
            baseName = Regex.Replace(folderName, @"-\d+$", "");
            if (string.IsNullOrEmpty(baseName))
                baseName = folderName;
        }

        long memBytes = (long)memoryMb * 1024 * 1024;
        string script = $$"""
            $baseName  = {{PowerShellRunner.Q(baseName)}}
            $sourceVhd = {{PowerShellRunner.Q(parentVhdx)}}
            $vmRoot    = {{PowerShellRunner.Q(localVmPath)}}

            $taken  = @(Get-VM | Select-Object -ExpandProperty Name)
            $vmName = $baseName
            $c = 2
            while ($taken -contains $vmName) { $vmName = $baseName + '-' + $c; $c++ }

            $vmDir = Join-Path $vmRoot $vmName
            New-Item -ItemType Directory -Path $vmDir -Force | Out-Null

            $vmVhd = Join-Path $vmDir ($vmName + '.vhdx')
            $vhdInfo = Get-VHD -Path $sourceVhd
            if ($vhdInfo.ParentPath) {
                Write-Host 'Source is a differencing disk - converting to standalone...'
                Convert-VHD -Path $sourceVhd -DestinationPath $vmVhd -VHDType Dynamic
            } else {
                Write-Host 'Copying VHDX...'
                Copy-Item -Path $sourceVhd -Destination $vmVhd -Force
            }

            $vm = New-VM -Name $vmName -Generation 2 -VHDPath $vmVhd -MemoryStartupBytes {{memBytes}} -Path $vmDir
            Set-VMProcessor -VMName $vmName -Count {{cpuCount}}
            Set-VMMemory -VMName $vmName -DynamicMemoryEnabled $false -StartupBytes {{memBytes}}

            Set-VMFirmware    -VMName $vmName -EnableSecureBoot Off
            Set-VMKeyProtector -VMName $vmName -NewLocalKeyProtector
            Enable-VMTPM       -VMName $vmName

            {{(skipDefaultNetwork ? "" : @$"$switchName = {PowerShellRunner.Q(vmSwitch ?? "Default Switch")}
            $sw = Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue
            if (-not $sw) {{ $sw = Get-VMSwitch | Select-Object -First 1 }}
            if ($sw) {{ Add-VMNetworkAdapter -VMName $vmName -SwitchName $sw.Name }}")}}
            """;

        await _ps.RunPsAsync(script);
    }

    public async Task CloneVmFromSnapshotAsync(string vmName, string snapshotName, string newVmName)
    {
        string script = $$"""
            $exportPath = Join-Path $env:TEMP "vmm-clone-$([Guid]::NewGuid().ToString('N'))"
            try {
                $snap = Get-VMSnapshot -VMName {{PowerShellRunner.Q(
                vmName
            )}} -Name {{PowerShellRunner.Q(snapshotName)}}
                if (-not $snap) { throw 'Snapshot not found.' }

                Export-VMSnapshot -VMSnapshot $snap -Path $exportPath

                $vmcxFile = Get-ChildItem -Path $exportPath -Recurse -Filter '*.vmcx' | Select-Object -First 1
                if (-not $vmcxFile) { throw 'Export did not produce a .vmcx file.' }

                $defaultPath = (Get-VMHost).VirtualMachinePath
                $vmDest = Join-Path $defaultPath {{PowerShellRunner.Q(newVmName)}}
                $vhdDest = Join-Path $vmDest 'Virtual Hard Disks'

                $imported = Import-VM -Path $vmcxFile.FullName -Copy -GenerateNewId `
                    -VirtualMachinePath $vmDest `
                    -SnapshotFilePath $vmDest `
                    -SmartPagingFilePath $vmDest `
                    -VhdDestinationPath $vhdDest

                Rename-VM -VM $imported -NewName {{PowerShellRunner.Q(newVmName)}}
            } finally {
                Remove-Item $exportPath -Recurse -Force -ErrorAction SilentlyContinue
            }
            """;
        await _ps.RunPsAsync(script);
    }

    public async Task ResetDiskAsync(string name)
    {
        _logger.LogInformation("Resetting VM {VmName} to base snapshot", name);
        string script = $$"""
            $vm = Get-VM -Name {{PowerShellRunner.Q(name)}}
            if ($vm.State -ne 'Off') { Stop-VM -Name {{PowerShellRunner.Q(name)}} -Force -TurnOff }

            $base = Get-VMSnapshot -VMName {{PowerShellRunner.Q(
                name
            )}} -Name 'Base' -ErrorAction SilentlyContinue
            if ($base) {
                Restore-VMSnapshot -VMSnapshot $base -Confirm:$false
            } else {
                $oldest = Get-VMSnapshot -VMName {{PowerShellRunner.Q(
                name
            )}} -ErrorAction SilentlyContinue |
                    Sort-Object CreationTime | Select-Object -First 1
                if ($oldest) {
                    Restore-VMSnapshot -VMSnapshot $oldest -Confirm:$false
                } else {
                    $vhd = Get-VM -Name {{PowerShellRunner.Q(
                name
            )}} | Get-VMHardDiskDrive | Select-Object -First 1
                    if (-not $vhd) { throw 'No hard disk found on VM.' }
                    $vhdPath = $vhd.Path
                    $info = Get-VHD -Path $vhdPath
                    if (-not $info.ParentPath) { throw 'Disk is not a differencing disk - cannot reset.' }
                    $parentPath = $info.ParentPath
                    Remove-Item $vhdPath -Force
                    New-VHD -Path $vhdPath -ParentPath $parentPath -Differencing | Out-Null
                }
            }
            """;
        await _ps.RunPsAsync(script);
    }

    public async Task ConfigureLocaleAsync(
        string vmName,
        string username,
        string password,
        string locale = "de-DE",
        string keyboardLayout = "00000407",
        string timezone = "",
        Action<string>? onStatus = null
    )
    {
        onStatus?.Invoke("Applying locale via PowerShell Direct...");
        if (string.IsNullOrWhiteSpace(keyboardLayout))
            keyboardLayout = "00000409";

        // InputMethodTip format is "LCID_hex_4digit:KLID" e.g. "0407:00000407" for German
        // The LCID comes from the locale's CultureInfo, formatted as 4-digit lowercase hex
        CultureInfo culture = CultureInfo.GetCultureInfo(locale);
        string lcidHex4 = culture.LCID.ToString("x4");
        string inputMethodTip = $"{lcidHex4}:{keyboardLayout}";

        string script = $$"""
            $vmName = {{PowerShellRunner.Q(vmName)}}
            $username = {{PowerShellRunner.Q(username)}}
            $password = {{PowerShellRunner.Q(password)}}
            $locale = {{PowerShellRunner.Q(locale)}}
            $kbLayout = {{PowerShellRunner.Q(keyboardLayout)}}
            $inputTip = {{PowerShellRunner.Q(inputMethodTip)}}
            $tz = {{PowerShellRunner.Q(timezone)}}

            try {
                $vm = Get-VM -Name $vmName
                if ($vm.State -ne 'Running') {
                    $startTries = 0
                    while ($startTries -lt 5) {
                        try {
                            Start-VM -Name $vmName -ErrorAction Stop
                            break
                        } catch {
                            $startTries++
                            if ($startTries -ge 5) { throw }
                            Start-Sleep -Seconds 2
                        }
                    }
                }

                $cred = New-Object PSCredential($username, (ConvertTo-SecureString $password -AsPlainText -Force))
                $session = $null
                $tries = 0
                while ($tries -lt 40 -and -not $session) {
                    try {
                        $session = New-PSSession -VMName $vmName -Credential $cred -ErrorAction Stop
                    } catch {
                        Start-Sleep -Seconds 2
                        $tries++
                    }
                }
                if (-not $session) { throw "VM '$vmName' did not become responsive within 80 seconds." }

                Invoke-Command -Session $session -ScriptBlock {
                    param($loc, $kbLayout, $inputTip, $tzId)

                    $langList = New-WinUserLanguageList $loc
                    $langList[0].InputMethodTips.Clear()
                    $langList[0].InputMethodTips.Add($inputTip)
                    Set-WinUserLanguageList $langList -Force

                    Set-WinDefaultInputMethodOverride -InputTip $inputTip -ErrorAction SilentlyContinue
                    Set-WinUILanguageOverride -Language $loc -ErrorAction SilentlyContinue

                    reg load 'HKU\TempDefault' 'C:\Users\Default\NTUSER.DAT' 2>$null
                    $lcid = [System.Globalization.CultureInfo]::new($loc).LCID
                    $lcidHex = '{0:x8}' -f $lcid
                    foreach ($hive in @('HKU\TempDefault')) {
                        reg add "$hive\Keyboard Layout\Preload" /v 1 /t REG_SZ /d $kbLayout /f 2>$null
                        reg delete "$hive\Keyboard Layout\Preload" /v 2 /f 2>$null
                        reg add "$hive\Control Panel\International" /v Locale /t REG_SZ /d $lcidHex /f 2>$null
                        reg add "$hive\Control Panel\International" /v LocaleName /t REG_SZ /d $loc /f 2>$null
                    }
                    reg unload 'HKU\TempDefault' 2>$null

                    $curSid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
                    reg add "HKU\$curSid\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f 2>$null
                    reg add "HKU\$curSid\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f 2>$null

                    Set-WinSystemLocale -SystemLocale $loc
                    Copy-UserInternationalSettingsToSystem -WelcomeScreen $true -NewUser $true

                    if ($tzId) { Set-TimeZone -Id $tzId }
                } -ArgumentList $locale, $kbLayout, $inputTip, $tz

                Invoke-Command -Session $session -ScriptBlock { Restart-Computer -Force }
                Remove-PSSession $session

                Start-Sleep -Seconds 5
                $session2 = $null
                $tries2 = 0
                while ($tries2 -lt 40 -and -not $session2) {
                    try {
                        $session2 = New-PSSession -VMName $vmName -Credential $cred -ErrorAction Stop
                    } catch {
                        Start-Sleep -Seconds 2
                        $tries2++
                    }
                }
                if ($session2) {
                    Invoke-Command -Session $session2 -ScriptBlock {
                        param($loc, $inputTip)
                        $langList = New-WinUserLanguageList $loc
                        $langList[0].InputMethodTips.Clear()
                        $langList[0].InputMethodTips.Add($inputTip)
                        Set-WinUserLanguageList $langList -Force
                        Set-WinDefaultInputMethodOverride -InputTip $inputTip -ErrorAction SilentlyContinue
                        Set-WinUILanguageOverride -Language $loc -ErrorAction SilentlyContinue
                        Copy-UserInternationalSettingsToSystem -WelcomeScreen $true -NewUser $true
                    } -ArgumentList $locale, $inputTip
                    Remove-PSSession $session2
                }
            } finally {
                $vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
                if ($vm -and $vm.State -ne 'Off') {
                    Stop-VM -Name $vmName -Force -ErrorAction SilentlyContinue
                }
            }
            """;
        await _ps.RunPsAsync(script);
    }

    public async Task RunPostCreationAsync(
        string vmName,
        string username,
        string password,
        bool renameComputer,
        string? postCreationScript = null,
        Action<string>? onStatus = null
    )
    {
        if (!renameComputer && string.IsNullOrWhiteSpace(postCreationScript))
            return;

        onStatus?.Invoke("Running post-creation tasks...");

        string renameBlock = renameComputer
            ? $"Invoke-Command -Session $session -ScriptBlock {{ Rename-Computer -NewName {PowerShellRunner.Q(vmName)} -Force }} -ErrorAction SilentlyContinue"
            : "";

        string scriptBlock = !string.IsNullOrWhiteSpace(postCreationScript)
            ? $"Invoke-Command -Session $session -ScriptBlock {{ {postCreationScript} }}"
            : "";

        string ps = $$"""
            $vmName = {{PowerShellRunner.Q(vmName)}}
            $username = {{PowerShellRunner.Q(username)}}
            $password = {{PowerShellRunner.Q(password)}}

            try {
                $vm = Get-VM -Name $vmName
                if ($vm.State -ne 'Running') {
                    Start-VM -Name $vmName -ErrorAction Stop
                }

                $cred = New-Object PSCredential($username, (ConvertTo-SecureString $password -AsPlainText -Force))
                $session = $null
                $tries = 0
                while ($tries -lt 40 -and -not $session) {
                    try {
                        $session = New-PSSession -VMName $vmName -Credential $cred -ErrorAction Stop
                    } catch {
                        Start-Sleep -Seconds 2
                        $tries++
                    }
                }
                if (-not $session) { throw "VM did not become responsive within 80 seconds." }

                {{renameBlock}}
                {{scriptBlock}}

                Remove-PSSession $session

                Invoke-Command -Session (New-PSSession -VMName $vmName -Credential $cred) -ScriptBlock { Restart-Computer -Force }
                Start-Sleep -Seconds 10
            } finally {
                $tries3 = 0
                while ($tries3 -lt 30) {
                    $vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
                    if ($vm -and $vm.State -eq 'Off') { break }
                    if ($vm -and $vm.State -ne 'Off' -and $tries3 -ge 25) {
                        Stop-VM -Name $vmName -Force -ErrorAction SilentlyContinue
                    }
                    Start-Sleep -Seconds 2
                    $tries3++
                }
            }
            """;
        await _ps.RunPsAsync(ps);
    }
}
