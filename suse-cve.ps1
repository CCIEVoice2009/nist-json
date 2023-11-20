$suse_baseurl = "https://ftp.suse.com/pub/projects/security/csaf-vex/"
$suse_url = $suse_baseurl + "?_gl=1*1yqmwf3*_ga*NzM4MzE4MzEuMTY5NjMxNDIxMA..*_ga_JEVBS2XFKK*MTY5NjQwODIyOS4zLjEuMTY5NjQwODQyOS4zNC4wLjA."
$suse_security_dir = invoke-webrequest $suse_url
$x = $suse_security_dir.Links | select innertext | Where {$_.innertext -like "*cve-2023*"}
$y = for ($i = 0; $i -lt $x.Length; $i++) { [int]$x[$i].innertext.substring(9, $x[$i].innertext.length - 9 - 4 - 1) }  
$y = $y | sort
$x = $y[$y.Length - 1]
#$x = "4354"
$x = $y | select -Last 100


for ($i = 0; $i -lt $x.Length; $i++)
{

$suse_cve_url = "https://ftp.suse.com/pub/projects/security/csaf-vex/cve-2023-" + $x[$i].ToString() + ".json"

$suse_security = invoke-webrequest $suse_cve_url | ConvertFrom-Json

$suse_date = ""
$suse_description = ""
$suse_CVE = ""
$suse_status = ""
$suse_date = ""
$suse_referurl = ""
$suse_scores = ""
$suse_baseSeverity = ""

$suse_description = ($suse_security.document.notes | where {$_.category -eq "Description"} | select text).text
$suse_CVE = $suse_security.document.title
$suse_status = $suse_security.document.tracking.status
$suse_date = $suse_security.document.tracking.initial_release_date.Substring(0, 10)
$suse_referurl = $suse_security.vulnerabilities.ids.text
$suse_scores = $suse_security.vulnerabilities.scores.cvss_v3.baseScore
$suse_baseSeverity = $suse_security.vulnerabilities.scores.cvss_v3.baseSeverity

$suse_description
$suse_CVE
$suse_status
$suse_date
$suse_referurl
$suse_scores
$suse_baseSeverity



#if (($suse_baseSeverity -ne $null) -and ($suse_scores -ne $null) -and ($suse_date -ne $null) -and (!$suse_description.Contains("** RESERV")))
#{
#Write-Host "Description =" $suse_description
#Write-Host "CVE = " $suse_CVE
#Write-Host "Status = " $suse_status
#Write-Host "Date = " $suse_date.Substring(0, 10)
#Write-Host "URL = " $suse_referurl
#Write-Host "CVSS Scores = " $suse_scores
#Write-Host "Severity = " $suse_baseSeverity
#if ($suse_date.Substring(0, 10) -gt "2023-09-10")
#{
# Write-Host $suse_description " | " $suse_CVE " | " $suse_status " | " $suse_date.Substring(0, 10) " | " $suse_referurl " | " $suse_scores " | " $suse_baseSeverity
#}
#}
}
