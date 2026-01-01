$report = "notes/pcap_summary_report.md"
"# PCAP Summary Report`n`nGenerated: $(Get-Date -Format s)`n" | Set-Content -Path $report -Encoding UTF8

$pcapRoots = @("pcaps/normal", "pcaps/stress")
$pcaps = @()
foreach ($root in $pcapRoots) {
    if (Test-Path $root) {
        $pcaps += Get-ChildItem -Path $root -Recurse -File |
            Where-Object { $_.Name -match "\.(pcap|pcapng)$" }
    }
}
$pcaps = $pcaps | Sort-Object FullName

foreach ($f in $pcaps) {
    $name = $f.Name
    $path = $f.FullName
    Add-Content -Path $report -Value ("## {0}`n" -f $name)
    Add-Content -Path $report -Value ("Source: {0}`n" -f $path)
    $output = & go run .\cmd\cipdip pcap-summary --input $path 2>&1
    Add-Content -Path $report -Value '```text'
    Add-Content -Path $report -Value $output
    Add-Content -Path $report -Value '```'
    Add-Content -Path $report -Value ""
}
