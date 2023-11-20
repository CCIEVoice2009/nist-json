$ubuntu_url = "https://lists.ubuntu.com/archives/ubuntu-security-announce/2023-September/date.html"
$url_head = "https://lists.ubuntu.com/archives/ubuntu-security-announce/2023-September/"
$ubuntu_security = invoke-webrequest $url
$ubuntu_href = $ubuntu_security.links | select href

foreach ($i in $ubuntu_href)
{
    if ($i.href.Contains("00"))
    {
        $url_head + $i.href
        $ubuntu_security = invoke-webrequest ($url_head + $i.href)
        if ($ubuntu_security.Content.Contains("Ubuntu 18.04"))
        {
            $ubuntu_security_array = $ubuntu_security.Content -split "`n"
            for ($j = 0; $j -lt $ubuntu_security_array.Length; $j++)
            {
                if ($ubuntu_security_array[$j].contains("================="))
                {
                    $security_date = $ubuntu_security_array[$j + 2]
                    $security_date
                    $security_vul = $ubuntu_security_array[$j + 4]
                    $security_vul
                    $j = $j + 5
                }
               
                if ($ubuntu_security_array[$j].contains("Summary:"))
                {
                    $security_content_start = $j
                }

                if ($ubuntu_security_array[$j].contains("Details:"))
                {
                    $security_content_end = $j
                }
            }
           
            $security_content = ""
            for ($k = $security_content_start + 1; $k -lt $security_content_end; $k++)
            {
                $security_content = $security_content + $ubuntu_security_array[$k]
            }
            $security_content
        }
    }
}
