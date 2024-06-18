function quickAudit() {

    $params = @{
        All         = $true
        ReportType  = 'XML' 
    }
    $report = Get-GPOReport @params
    $xml = [xml]$report

    $defaultdomain = $xml.GPOS.GPO | Where-Object {($_.Name -eq "Default Domain Policy") -or ($_.Name -eq "Default Domain Controllers Policy")}
    $origin = $xml.GPOS.GPO | Where-Object {($_.Name -ne "Default Domain Policy") -and ($_.Name -ne "Default Domain Controllers Policy")}

    $enctypes =  $origin.Computer.ExtensionData.Extension.SecurityOptions | Where-Object {$_.KeyName -eq "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes"}
    $enctype = $enctypes.SettingNumber

    if (($enctype -ne 16) -and ($enctype -ne 24)) {
        Write-Host "Kerberos encryption supports weak algorithms such as RC4 or DES.Consider enforcing AES only." -ForegroundColor Red
    } else {
        Write-Host "Kerberos encryption is enforced to use AES." -ForegroundColor Green
    }

    $deftickets = $defaultdomain.Computer.ExtensionData.Extension.Account | Where-Object {$_.Type -eq "Kerberos"}
    $tickets = $origin.Computer.ExtensionData.Extension.Account | Where-Object {$_.Type -eq "Kerberos"}
    $maxrenew = 0
    $maxservice = 0
    $maxticketage = 0

    foreach ($policy in $tickets) {
        if ($policy.Name -eq "MaxRenewAge") {
            $maxrenew = [int]$policy.SettingNumber
            break
        }
    }

    if ($maxrenew -eq 0) {
        foreach ($policy in $deftickets) {
            if ($policy.Name -eq "MaxRenewAge") {
                $maxrenew = [int]$policy.SettingNumber
                break
            }    
        }
    }


    foreach ($policy in $tickets) {
        if ($policy.Name -eq "MaxTicketAge") {
            $maxticketage = [int]$policy.SettingNumber
            break
        }
    }

    if ($maxticketage -eq 0) {
        foreach ($policy in $deftickets) {
            if ($policy.Name -eq "MaxRenewAge") {
                $maxticketage = [int]$policy.SettingNumber
                break
            }    
        }
    }

    foreach ($policy in $tickets) {
        if ($policy.Name -eq "MaxServiceAge") {
            $maxservice = [int]$policy.SettingNumber
            break
        }
    }

    if ($maxservice -eq 0) {
        foreach ($policy in $deftickets) {
            if ($policy.Name -eq "MaxRenewAge") {
                $maxservice = [int]$policy.SettingNumber
                break
            }    
        }
    }

    
    if ($maxrenew -gt 7) {
        Write-Host "Ticket Max Renewal is $maxrenew days. Consider decreasing it to at most 7 days." -ForegroundColor Red
    } else {
        Write-Host "Ticket Max Renewal is $maxrenew days." -ForegroundColor Green
    }

    if ($maxservice -gt 10) {
        Write-Host "Service Max Renewal is $maxservice minutes. Consider decreasing it to at most 10 minutes." -ForegroundColor Red
    } else {
        Write-Host "Service Max Renewal is $maxservice minutes." -ForegroundColor Green
    }

    if ($maxticketage -gt 10) {
        Write-Host "Max Ticket Age is $maxticketage hours. It is recommended to decrease it to at most 10 hours."  -ForegroundColor Red
    } else {
        Write-Host "Max Ticket Age is $maxticketage hours." -ForegroundColor Green
    }

    $deflockout = $defaultdomain.Computer.ExtensionData.Extension.Account | Where-Object {$_.Type -eq "Account Lockout"}
    $lockout = $origin.Computer.ExtensionData.Extension.Account | Where-Object {$_.Type -eq "Account Lockout"}

    $LockoutBadCount = 0
    $LockoutDuration = 0
    $ResetLockoutCount = 0

    foreach ($policy in $lockout) {
        if ($policy.Name -eq "LockoutBadCount") {
            $LockoutBadCount = [int]$policy.SettingNumber
            break
        }
    }

    if ($LockoutBadCount -eq 0) {
        foreach ($policy in $deflockout) {
            if ($policy.Name -eq "LockoutBadCount") {
                $LockoutBadCount = [int]$policy.SettingNumber
                break
            }    
        }
    }

    foreach ($policy in $lockout) {
        if ($policy.Name -eq "LockoutDuration") {
            $LockoutDuration = [int]$policy.SettingNumber
            break
        }
    }

    if ($LockoutDuration -eq 0) {
        foreach ($policy in $deflockout) {
            if ($policy.Name -eq "LockoutDuration") {
                $LockoutDuration = [int]$policy.SettingNumber
                break
            }    
        }
    }

    foreach ($policy in $lockout) {
        if ($policy.Name -eq "ResetLockoutCount") {
            $ResetLockoutCount = [int]$policy.SettingNumber
            break
        }
    }

    if ($LockoutDuration -eq 0) {
        foreach ($policy in $deflockout) {
            if ($policy.Name -eq "ResetLockoutCount") {
                $ResetLockoutCount = [int]$policy.SettingNumber
                break
            }
        }
    }

    if ($LockoutBadCount -lt 10) {
        Write-Host "Current lockout is $LockoutBadCount failed attempts.  Microsoft's guideline suggests adjusting it to 10 attempts." -ForegroundColor Red
    } else {
        Write-Host "Current lockout is $LockoutBadCount failed attempts." -ForegroundColor Green
    }

    if ($LockoutDuration -lt 30) {
        Write-Host "Lockout duration is $LockoutDuration minutes. Microsoft's guideline suggests adjusting it to 30 minutes." -ForegroundColor Red
    } else {
        Write-Host "Lockout duration is $LockoutDuration minutes." -ForegroundColor Green
    }

    if ($ResetLockoutCount -lt 30) {
        Write-Host "Lockout reset duration is $ResetLockoutCount minutes. Microsoft's guideline suggests adjusting it to 30 minutes."  -ForegroundColor Red
    } else {
        Write-Host "Lockout reset duration is $ResetLockoutCount minutes." -ForegroundColor Green
    }

    $defpasswd = $defaultdomain.Computer.ExtensionData.Extension.Account | Where-Object {$_.Type -eq "Password"}
    $passwd = $origin.Computer.ExtensionData.Extension.Account | Where-Object {$_.Type -eq "Password"}

    $MaximumPasswordAge = 0
    $MinimumPasswordAge = 0
    $MinimumPasswordLength = 0
    $PasswordComplexity = $false
    $PasswordHistorySize = 0

    foreach ($policy in $passwd) {
        if ($policy.Name -eq "MaximumPasswordAge") {
            $MaximumPasswordAge = [int]$policy.SettingNumber
            break
        }
    }

    if ($MaximumPasswordAge -eq 0) {
        foreach ($policy in $defpasswd) {
            if ($policy.Name -eq "MaximumPasswordAge") {
                $MaximumPasswordAge = [int]$policy.SettingNumber
                break
            }
        }
    }

    if ($MaximumPasswordAge -gt 90) {
        Write-Host "Max password age is $MaximumPasswordAge days. Microsoft's guideline suggests adjusting it to between 60-90 days, or use the default setting (42 days)."  -ForegroundColor Red
    } else {
        Write-Host "Max password age is $MaximumPasswordAge days." -ForegroundColor Green
    }

    foreach ($policy in $passwd) {
        if ($policy.Name -eq "MinimumPasswordAge") {
            $MinimumPasswordAge = [int]$policy.SettingNumber
            break
        }
    }

    if ($MinimumPasswordAge -eq 0) {
        foreach ($policy in $defpasswd) {
            if ($policy.Name -eq "MinimumPasswordAge") {
                $MinimumPasswordAge = [int]$policy.SettingNumber
                break
            }
        }
    }

    if ($MinimumPasswordAge -eq 0) {
        Write-Host "Min password age is $MinimumPasswordAge days. Microsoft's guideline suggests adjusting it to 1 day. This prevents rapid password changes."  -ForegroundColor Red
    } else {
        Write-Host "Min password age is $MinimumPasswordAge days." -ForegroundColor Green
    }

    foreach ($policy in $passwd) {
        if ($policy.Name -eq "MinimumPasswordLength") {
            $MinimumPasswordLength = [int]$policy.SettingNumber
            break
        }
    }

    if ($MinimumPasswordLength -eq 0) {
        foreach ($policy in $defpasswd) {
            if ($policy.Name -eq "MinimumPasswordLength") {
                $MinimumPasswordLength = [int]$policy.SettingNumber
                break
            }
        }
    }

    if ($MinimumPasswordLength -lt 8) {
        Write-Host "Min password length is $MinimumPasswordLength characters. Microsoft's security baseline recommends using at least 8 characters."  -ForegroundColor Red
    } else {
        Write-Host "Min password length is $MinimumPasswordLength characters." -ForegroundColor Green
    }

    foreach ($policy in $passwd) {
        if ($policy.Name -eq "PasswordComplexity") {
            $PasswordComplexity = $policy.SettingBoolean
            break
        }
    }

    if ($PasswordComplexity -ne 'true') {
        foreach ($policy in $defpasswd) {
            if ($policy.Name -eq "PasswordComplexity") {
                $PasswordComplexity = $policy.SettingBoolean
                break
            }
        }
    }

    if ($PasswordComplexity -ne 'true') {
        Write-Host "Password complexity is disabled. Enabling complexity increases the password strength."  -ForegroundColor Red
    } else {
        Write-Host "Password complexity is enabled." -ForegroundColor Green
    }

    foreach ($policy in $passwd) {
        if ($policy.Name -eq "PasswordHistorySize") {
            $PasswordHistorySize = [int]$policy.SettingNumber
            break
        }
    }

    if ($PasswordHistorySize -eq 0) {
        foreach ($policy in $defpasswd) {
            if ($policy.Name -eq "PasswordHistorySize") {
                $PasswordHistorySize = [int]$policy.SettingNumber
                break
            }
        }
    }

    if ($PasswordHistorySize -lt 24) {
        Write-Host "Password History records the last $PasswordHistorySize passwords. Microsoft's security baseline recommends using the maximum setting available to prevent password reuse (24)."  -ForegroundColor Red
    } else {
        Write-Host "Password History records the last $PasswordHistorySize passwords." -ForegroundColor Green
    }

}

function linkGPO($gpo_name) {
    $currDomain = Get-ADDomain -Current LoggedOnUser | Select DistinguishedName
    foreach ($d in $currDomain) {
        $linking = New-GPLink -Name $gpo_name -Target $d.DistinguishedName -LinkEnabled Yes -Enforced Yes 2>$null
        Write-Host "Linked : $gpo_name" -ForegroundColor Green
    }
}

function ImportGPOLocal($gpo_id, $gpo_name) {
  
    $params = @{
        BackupId       = $gpo_id
        TargetName     = $gpo_name
        path           = '.\GPO'
        CreateIfNeeded = $true
    }
    $currDomain = Get-ADDomain -Current LoggedOnUser | Select DistinguishedName
    $linkedGPO = Get-GPInheritance -Target $currDomain.DistinguishedName | Select-Object -ExpandProperty GpoLinks | Select Displayname 2>$null
    foreach ($GPO in $linkedGPO) {
        if ($GPO.Displayname -eq $gpo_name) {
            Write-Host "The GPO '$gpo_name' is already imported and linked. Importing aborted." -ForegroundColor Yellow
            return
        }
    }

    $importing = Import-GPO @params 2>$null
    Write-Host "Imported : $gpo_name" -ForegroundColor Green
    linkGPO($gpo_name)

    
}

function PromptUser($gpo_name, $gpo_desc, $gpo_id) {

    Write-Host "Importing GPO" $gpo_name -ForegroundColor Yellow
    Write-Host "Description:" $gpo_desc -ForegroundColor Yellow

    $answer = "Y"
    $answer = Read-Host "Do you want to continue? (Y/N)"
    $answer = $answer.ToUpper()
    
    if ($answer -eq "Y") {
        ImportGPOLocal $gpo_id $gpo_name
        
    } else {
        Write-Host "Did not import GPO" $gpo_name -ForegroundColor Red
    }
}

$GPOLIST = @(
    @{ name = 'KRB Disable Weak Encryption'; id = '8C7CE887-FEB7-4CE2-81C4-D09DE156B025'; 
    desc = 'This GPO enforces the use of AES256 and AES128 algorithms for Kerberos authentication. Do not import this GPO if your enviroment has older systems or applications which might not support AES encryption, potentially causing authentication failures for those clients.'},
    @{ name = 'KRB Ticket Lifetime'; id = 'F75F4348-7014-4642-9FC1-CB344F7D38DD'; 
    desc = 'This GPO enforces stricter ticket lifetimes. This mitigates the usage of illegitimate or stolen tickets.'},
    @{ name = 'Password Policy'; id = 'B2E06B69-21FC-42D4-B957-D67CB6CEA4D3'; 
    desc = 'This GPO sets a password policy as recommended by Microsoft standards. This ensures that a standard password policy is applied.'}
    @{ name="Account Lockout Policy"; id = '6CCD36E7-D5FD-4A01-8EFA-8FC9E6ADC36E'; 
    desc = 'This GPO sets an account lockout policy of 10 attempts. This is set to mitigate brute-force attacks.'}
    @{ name="Kerberos Event Logging"; id = '94D1FCCA-12D6-474C-95AC-0C344A7EA30D'; 
    desc = 'This GPO sets a policy to enable audit logs for Kerberos ticket events (4768, 4769). This ensures logs that can potentially detect suspicious activities are logged.'}
)

function DisplayMenu() {

Write-Host "
         ______  _______ __   __ _______ ___ __    _                                                             
        |      ||       |  |_|  |   _   |   |  |  | |                                                            
        |  _    |   _   |       |  |_|  |   |   |_| |                                                            
        | | |   |  | |  |       |       |   |       |                                                            
        | |_|   |  |_|  |       |       |   |  _    |                                                            
        |       |       | ||_|| |   _   |   | | |   |                                                            
        |______||_______|_|   |_|__| |__|___|_|  |__|                                                            
         _______ __   __ _______ __   __ _______ __    _ _______ ___ _______ _______ _______ ___ _______ __    _ 
        |   _   |  | |  |       |  | |  |       |  |  | |       |   |       |   _   |       |   |       |  |  | |
        |  |_|  |  | |  |_     _|  |_|  |    ___|   |_| |_     _|   |       |  |_|  |_     _|   |   _   |   |_| |
        |       |  |_|  | |   | |       |   |___|       | |   | |   |       |       | |   | |   |  | |  |       |
        |       |       | |   | |       |    ___|  _    | |   | |   |      _|       | |   | |   |  |_|  |  _    |
        |   _   |       | |   | |   _   |   |___| | |   | |   | |   |     |_|   _   | |   | |   |       | | |   |
        |__| |__|_______| |___| |__| |__|_______|_|  |__| |___| |___|_______|__| |__| |___| |___|_______|_|  |__|
         __   __ _______ ______   ______  _______ __    _ ___ __    _ _______                                    
        |  | |  |   _   |    _ | |      ||       |  |  | |   |  |  | |       |                                   
        |  |_|  |  |_|  |   | || |  _    |    ___|   |_| |   |   |_| |    ___|                                   
        |       |       |   |_||_| | |   |   |___|       |   |       |   | __                                    
        |       |       |    __  | |_|   |    ___|  _    |   |  _    |   ||  |                                   
        |   _   |   _   |   |  | |       |   |___| | |   |   | | |   |   |_| |                                   
        |__| |__|__| |__|___|  |_|______||_______|_|  |__|___|_|  |__|_______|                                   " -ForegroundColor Green

while($True){
        Write-Host "

               #      |            Name            |                                       Description                                        
         -------------|----------------------------|------------------------------------------------------------------------------------------ 
          0           | Exit                       | Exits script.                                                                            
          1           | Walkthrough                | This will guide you through all the domain policies provided.                            
          2           | Kerberos Encryption Types  | This policy changes the encryption types used in authentication.                         
          3           | Kerberos Ticket Lifetime   | This policy changes the lifetime of Kerberos tickets.                                    
          4           | Password Policy            | This policy will apply a password policy using Microsoft's recommended standard.         
          5           | Account Lockout Policy     | This policy will apply an account lockout policy using Microsoft's recommended standard. 
          6           | Check current configuration| This will run a check on the currently used domain policy configuration.
          7           | Enable Kerberos Event Logs | This will apply a policy to enable Kerberos ticket event logging.  
          
          "

        $answer = "0"
        $answer = Read-Host "Please select an option"

        if ($answer -eq "1") {
            foreach ($GPO in $GPOLIST) {
                PromptUser $GPO.name $GPO.desc $GPO.id
            }
        } elseif ($answer -eq "2") {
            $GPO = $GPOLIST[0]
            PromptUser $GPO.name $GPO.desc $GPO.id
        } elseif ($answer -eq "3") {
            $GPO = $GPOLIST[1]
            PromptUser $GPO.name $GPO.desc $GPO.id
        } elseif ($answer -eq "4") {
            $GPO = $GPOLIST[2]
            PromptUser $GPO.name $GPO.desc $GPO.id
        } elseif ($answer -eq "5") {
            $GPO = $GPOLIST[3]
            PromptUser $GPO.name $GPO.desc $GPO.id
        } elseif ($answer -eq "6") {
            quickAudit
        } elseif ($answer -eq "7") {
            $GPO = $GPOLIST[4]
            PromptUser $GPO.name $GPO.desc $GPO.id
        } elseif ($answer -eq "0") {
             Write-Host "Exiting script." -ForegroundColor Yellow
            return 
        } else {
            Write-Host "Please enter a valid option." -ForegroundColor Yellow
        }
    }
}

DisplayMenu
