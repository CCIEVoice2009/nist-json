$current_date = Get-Date -Format "yyyy-MM-dd"
$nist_std_url = "https://nvd.nist.gov/vuln/detail/"
$last_checkdate = "2023-09-12"
$high_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate=" + $last_checkdate + "T00:00:00.000&pubEndDate=" + $current_date + "T00:00:00.000&cvssV3Severity=HIGH"
$critical_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate=" + $last_checkdate + "T00:00:00.000&pubEndDate=" + $current_date + "T00:00:00.000&cvssV3Severity=CRITICAL"

$cvemetadata_high = ( (invoke-webrequest $high_url) | convertfrom-json)
$cvemetadata_critical = ( (invoke-webrequest $critical_url) | convertfrom-json)

foreach ($i in $cvemetadata_critical.vulnerabilities)
{
    $result = ""
    if ($i.cve.vulnStatus -eq "Analyzed")
    {
        if ($i.cve.metrics.cvssMetricV31.cvssData.baseScore[0] -ge 9.9)
        {
            $nist_rank = "Critical"
        }
        elseif ($i.cve.metrics.cvssMetricV31.cvssData.baseScore[0] -ge 9)
            {
                $nist_rank = "High"
            }
            elseif ($i.cve.metrics.cvssMetricV31.cvssData.baseScore[0] -ge 6)
            {
                $nist_rank = "Medium"
            }
            else
            {
                $nist_rank = "Low"
            }
            $i.cve.descriptions[0].value = $i.cve.descriptions[0].value -replace("`r", $null)
            $i.cve.descriptions[0].value = $i.cve.descriptions[0].value -replace("`n", $null)
        $result = $i.cve.id + "|" + $i.cve.vulnStatus + "|" + $i.cve.descriptions[0].value + "|" + $i.cve.metrics.cvssMetricV31.cvssData.baseScore[0] + "|" + $nist_rank + "|" + $i.cve.published.Substring(0,10) + "|" + $nist_std_url  + $i.cve.id + "|" + $i.cve[0].references.url + "`r`n"
       
        $result | Out-File "c:\temp\critical.txt" -Append
    }
}


foreach ($i in $cvemetadata_high.vulnerabilities)
{

    $result = ""
    if ($i.cve.vulnStatus -eq "Analyzed")
    {
        if ($i.cve.metrics.cvssMetricV31.cvssData.baseScore[0] -ge 9.9)
        {
            $nist_rank = "Critical"
        }
        elseif ($i.cve.metrics.cvssMetricV31.cvssData.baseScore[0] -ge 9)
            {
                $nist_rank = "High"
            }
            elseif ($i.cve.metrics.cvssMetricV31.cvssData.baseScore[0] -ge 6)
            {
                $nist_rank = "Medium"
            }
            else
            {
                $nist_rank = "Low"
            }

           
        $result = $i.cve.id + "|" + $i.cve.vulnStatus + "|" + $i.cve.descriptions[0].value + "|" + $i.cve.metrics.cvssMetricV31.cvssData.baseScore[0] + "|" + $nist_rank + "|" + $i.cve.published.Substring(0,10) + "|" + $nist_std_url  + $i.cve.id + "|" + $i.cve[0].references.url + "`r`n"
        $result | Out-File "c:\temp\high.txt" -Append
    }
}

