param(
  [string]$PcapDir = ".\pcaps",
  [string]$TsharkPath = "C:\Program Files\Wireshark\tshark.exe",
  [string]$OutCsv = ".\cip_pcap_summary.csv",
  [string]$OutTxt = ".\cip_pcap_summary.txt",

  # Transport “not conducive” thresholds (tune)
  [int]$MaxTcpRst = 5,
  [int]$MaxTcpRetrans = 500,
  [int]$MaxTcpLostSeg = 5,

  # “Fuzz / invalid” heuristics (tune)
  [double]$MaxCipErrorRate = 0.05,     # >5% CIP error responses => suspicious
  [int]$MaxMalformed = 0,              # any malformed => deformation
  [int]$MaxExpertErrors = 0            # any expert errors => deformation
)

if (-not (Test-Path $PcapDir)) { throw "PCAP directory not found: $PcapDir (cwd: $(Get-Location))" }
if (-not (Test-Path $TsharkPath)) { throw "tshark.exe not found at: $TsharkPath" }

function Count-Tshark {
  param([string]$Pcap, [string]$Filter)
  $n = & $TsharkPath -r $Pcap -Y $Filter 2>$null | Measure-Object -Line | Select-Object -ExpandProperty Lines
  if ($null -eq $n) { return 0 }
  return [int]$n
}

function Get-ExpertSummary {
  param([string]$Pcap)
  $out = & $TsharkPath -r $Pcap -q -z expert 2>$null
  $text = ($out | Out-String)

  $errors = 0; $warns = 0; $notes = 0; $chats = 0
  if ($text -match "(?im)^\s*Error\s+(\d+)\s*$") { $errors = [int]$Matches[1] }
  if ($text -match "(?im)^\s*Warn(ing)?\s+(\d+)\s*$") { $warns = [int]$Matches[2] }
  if ($text -match "(?im)^\s*Note\s+(\d+)\s*$") { $notes = [int]$Matches[1] }
  if ($text -match "(?im)^\s*Chat\s+(\d+)\s*$") { $chats = [int]$Matches[1] }

  return [pscustomobject]@{
    ExpertErrors = $errors
    ExpertWarnings = $warns
    ExpertNotes = $notes
    ExpertChats = $chats
  }
}

# Enumerate pcaps
$pcaps = Get-ChildItem -Path $PcapDir -Recurse -File |
  Where-Object { $_.Name -match "\.(pcap|pcapng)$" } |
  Sort-Object FullName

if (-not $pcaps -or $pcaps.Count -eq 0) { throw "No .pcap/.pcapng files found under $PcapDir" }

Write-Host "Found $($pcaps.Count) capture(s) under $PcapDir"
Write-Host "Using tshark: $TsharkPath"
Write-Host "Noise thresholds: RST>$MaxTcpRst, Retrans>$MaxTcpRetrans, LostSeg>$MaxTcpLostSeg"
Write-Host "Fuzz thresholds: CipErrorRate>$MaxCipErrorRate, Malformed>$MaxMalformed, ExpertErrors>$MaxExpertErrors"
Write-Host ""

$rows = @()

foreach ($f in $pcaps) {
  $p = $f.FullName

  # Basic protocol presence
  $enipHits = Count-Tshark $p "enip || tcp.port==44818 || udp.port==44818 || udp.port==2222"
  $cipHits  = Count-Tshark $p "cip"

  $listId = Count-Tshark $p "enip.command==0x0063"
  $io2222 = Count-Tshark $p "udp.port==2222"

  # Integrity signals
  $malformed = Count-Tshark $p "_ws.malformed"
  $expert = Get-ExpertSummary $p

  # Transport noise
  $tcpRst     = Count-Tshark $p "tcp.flags.reset==1"
  $tcpRetr    = Count-Tshark $p "tcp.analysis.retransmission"
  $tcpLostSeg = Count-Tshark $p "tcp.analysis.lost_segment"

  # CIP error-rate heuristic (invalid/unsupported/fuzz-like)
  # cip.response == 1 indicates responses; non-zero general status suggests error.
  # We count any response with general status != 0 as "CIP error response".
  $cipResponses = Count-Tshark $p "cip && cip.response"
  $cipErrorResp = Count-Tshark $p "cip && cip.response && cip.genstat && cip.genstat != 0"
  $cipErrorRate = 0.0
  if ($cipResponses -gt 0) { $cipErrorRate = [math]::Round(($cipErrorResp / $cipResponses), 4) }

  # “Obvious deformation” signals beyond malformed:
  $badChecksum = Count-Tshark $p "ip.checksum_bad==1 || tcp.checksum_bad==1 || udp.checksum_bad==1"
  $reasmErr    = Count-Tshark $p "tcp.reassembled.data && expert.message matches \"reassembly\""

  # Classification axis 1: Integrity bucket (same as before)
  $integrity = "PROTOCOL_NORMAL"
  $integrityReasons = New-Object System.Collections.Generic.List[string]

  if ($enipHits -eq 0 -and $cipHits -eq 0) {
    $integrity = "NOT_CIP_ENIP"
    $integrityReasons.Add("no_enip_or_cip_detected")
  } else {
    if ($malformed -gt 0 -or $expert.ExpertErrors -gt 0) {
      $integrity = "PROTOCOL_ANOMALOUS"
      if ($malformed -gt 0) { $integrityReasons.Add("malformed=$malformed") }
      if ($expert.ExpertErrors -gt 0) { $integrityReasons.Add("expertErrors=$($expert.ExpertErrors)") }
    } else {
      if ($tcpRst -gt $MaxTcpRst -or $tcpRetr -gt $MaxTcpRetrans -or $tcpLostSeg -gt $MaxTcpLostSeg) {
        $integrity = "TRANSPORT_NOISY"
        if ($tcpRst -gt $MaxTcpRst) { $integrityReasons.Add("tcpRst=$tcpRst") }
        if ($tcpRetr -gt $MaxTcpRetrans) { $integrityReasons.Add("retrans=$tcpRetr") }
        if ($tcpLostSeg -gt $MaxTcpLostSeg) { $integrityReasons.Add("lostSeg=$tcpLostSeg") }
      }
    }
  }

  # Classification axis 2: “Operational suitability / fuzz/deformation” flags
  $flags = New-Object System.Collections.Generic.List[string]

  # Deformations
  if ($malformed -gt $MaxMalformed) { $flags.Add("deformation:malformed") }
  if ($expert.ExpertErrors -gt $MaxExpertErrors) { $flags.Add("deformation:expert_error") }
  if ($badChecksum -gt 0) { $flags.Add("deformation:bad_checksum") }

  # Invalid/unsupported/fuzz-like: high CIP error rate
  if ($cipResponses -gt 0 -and $cipErrorRate -gt $MaxCipErrorRate) {
    $flags.Add("fuzz_or_invalid:high_cip_error_rate")
  }

  # Not conducive to normal operations: extreme noise
  if ($tcpRetr -gt ($MaxTcpRetrans * 10)) { $flags.Add("ops_bad:extreme_retrans") }
  if ($tcpLostSeg -gt ($MaxTcpLostSeg * 5)) { $flags.Add("ops_bad:extreme_loss") }
  if ($tcpRst -gt ($MaxTcpRst * 10)) { $flags.Add("ops_bad:extreme_resets") }

  # Informational flags
  if ($listId -gt 0) { $flags.Add("has_discovery:list_identity") }
  if ($io2222 -gt 0) { $flags.Add("has_io:udp2222") }

  # Human output line
  $flagText = ($flags -join ",")
  $reasonText = ($integrityReasons -join "; ")

  if ($flagText -and $reasonText) {
    Write-Host ("[{0}] {1} :: {2} :: {3}" -f $integrity, $f.Name, $reasonText, $flagText)
  } elseif ($reasonText) {
    Write-Host ("[{0}] {1} :: {2}" -f $integrity, $f.Name, $reasonText)
  } elseif ($flagText) {
    Write-Host ("[{0}] {1} :: {2}" -f $integrity, $f.Name, $flagText)
  } else {
    Write-Host ("[{0}] {1}" -f $integrity, $f.Name)
  }

  $rows += [pscustomobject]@{
    File = $f.Name
    Path = $p

    ENIP_Hits = $enipHits
    CIP_Hits = $cipHits
    ListIdentity = $listId
    UDP2222_IO = $io2222

    Malformed = $malformed
    ExpertErrors = $expert.ExpertErrors
    ExpertWarnings = $expert.ExpertWarnings
    BadChecksums = $badChecksum

    TCP_RST = $tcpRst
    TCP_Retrans = $tcpRetr
    TCP_LostSeg = $tcpLostSeg

    CIP_Responses = $cipResponses
    CIP_ErrorResponses = $cipErrorResp
    CIP_ErrorRate = $cipErrorRate

    Integrity = $integrity
    IntegrityReasons = $reasonText
    Flags = $flagText
  }
}

$rows | Sort-Object Integrity, File | Export-Csv -NoTypeInformation -Path $OutCsv

# Summaries
$normal = $rows | Where-Object Integrity -eq "PROTOCOL_NORMAL"
$noisy  = $rows | Where-Object Integrity -eq "TRANSPORT_NOISY"
$anom   = $rows | Where-Object Integrity -eq "PROTOCOL_ANOMALOUS"
$none   = $rows | Where-Object Integrity -eq "NOT_CIP_ENIP"

$fuzz = $rows | Where-Object { $_.Flags -match "fuzz_or_invalid" }
$deform = $rows | Where-Object { $_.Flags -match "deformation" }
$opsbad = $rows | Where-Object { $_.Flags -match "ops_bad" }

@"
CIP/ENIP PCAP Classification Summary
Generated: $(Get-Date)
PCAP directory: $PcapDir
tshark: $TsharkPath

Integrity buckets:
  PROTOCOL_NORMAL
  TRANSPORT_NOISY
  PROTOCOL_ANOMALOUS
  NOT_CIP_ENIP

Counts:
  PROTOCOL_NORMAL:     $($normal.Count)
  TRANSPORT_NOISY:     $($noisy.Count)
  PROTOCOL_ANOMALOUS:  $($anom.Count)
  NOT_CIP_ENIP:        $($none.Count)

Additional flags:
  deformation:*         = malformed/expert errors/bad checksum signals
  fuzz_or_invalid:*     = high CIP error rate (unsupported/invalid/fuzz-like)
  ops_bad:*             = extreme transport conditions not conducive to normal ops
  has_discovery:*       = discovery present
  has_io:*              = UDP 2222 I/O present

Flagged sets:
  Deformation: $($deform.Count)
  Fuzz/Invalid: $($fuzz.Count)
  Ops bad: $($opsbad.Count)

CSV: $OutCsv
"@ | Out-File -Encoding utf8 $OutTxt

Write-Host "`nWrote:`n  $OutCsv`n  $OutTxt"
