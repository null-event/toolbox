$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() 
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString) 
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain

#Filter the below as needed
#Default is to search for all user objects: SAM_USER_OBJECT 0x30000000
#Other filters could include: $Searcher.filter="name=tboyle_admin"

$Searcher.filter="samAccountType=805306368"

$Result = $Searcher.FindAll()
Foreach($obj in $Result)
{
  Foreach($prop in $obj.Properties)
  {
    $prop
  }
Write-Host "------------------------" 
}
