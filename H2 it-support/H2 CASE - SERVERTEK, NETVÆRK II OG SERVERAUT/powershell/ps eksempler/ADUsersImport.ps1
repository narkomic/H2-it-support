$pass = ConvertTo-SecureString "Password1" -AsPlainText -force
$Cre = Get-Credential -Credential "SrvAdmin"
$ADUSERS = Import-Csv "C:\PS\ADUsersImport.csv"

foreach ($user in $ADUsers)
{
    $Firstname = $user.givenname
    $Lastname = $user.surname
    $Logonname = $user.samaccountname
    $Office = $user.office
    $OU = $user.OU

#Tjek om user eksisterer
if (Get-ADUser -Filter {Samaccountname -eq $Logonname})
    {
            Write-Warning "Bruger $logonname eksisterer allerede i AD"
    } 
else
    {
    New-aduser -Name "$Firstname $Lastname" -SamAccountName $Logonname -Surname $Lastname -GivenName $Firstname -DisplayName "$Firstname $Lastname" -UserPrincipalName "$Logonname@SDEDOM.local" -Office $Office -Credential $Cre -AccountPassword $pass -Enabled $true -Path $OU -ChangePasswordAtLogon $true
    }
}