$pass = Convertto-securestring "Password1" -asplaintext -force 
$Cre = Get-Credential -Credential "SrvAdmin"
$ADUsers = Import-Csv "C:\PS\ADUsersImport.csv"

foreach ($user in $ADUsers)
{
    $Firstname = $user.givenname
    $Lastname = $user.surname
    $Logonname = $user.samaccountname
    $Disting = $user.distinguishedname
    $Office = $user.office
    # $OU = $user.OU (Path indsat i CSV-fil)

    if ($Office -like "HR")
    {
        $OU = "OU=HR,DC=SDEDOM,DC=local" #Ingen path i CSV-fil
        $SG = "SG_HR"
    }

    elseif ($Office -like "Salg")
    {
        $OU = "OU=Salg,DC=SDEDOM,DC=local" #Ingen path i CSV-fil
        $SG = "SG_Salg"
    }
    else
    {
            Write-Host "Fejl"
    }

    if (Get-ADUser -Filter {Samaccountname -eq $Logonname})
    
    {
            Write-Warning "Bruger $logonname eksisterer allerede i AD"
    } 
    else
    {
    New-aduser -Name "$Firstname $Lastname" -SamAccountName $Logonname -Surname $Lastname -GivenName $Firstname -DisplayName "$Firstname $Lastname" -UserPrincipalName "$Logonname@SDEDOM.local" -Office $Office -Credential $Cre -AccountPassword $pass -Enabled $true -Path $OU -ChangePasswordAtLogon $true
    

    Add-ADGroupMember -Identity $SG -Members $Logonname
    Write-Host "$Firstname $Lastname er tilføjet til $SG"
    }
}

    
   


