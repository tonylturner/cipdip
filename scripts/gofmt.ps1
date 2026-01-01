param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

$gofmt = Get-Command gofmt -ErrorAction SilentlyContinue
if (-not $gofmt) {
    Write-Error "gofmt not found in PATH. Install Go or add gofmt to PATH."
    exit 1
}

$rg = Get-Command rg -ErrorAction SilentlyContinue
if ($rg) {
    $files = & $rg --files -g "*.go" $RepoRoot
} else {
    $files = Get-ChildItem -Path $RepoRoot -Recurse -Filter *.go | ForEach-Object { $_.FullName }
}

$fullPaths = $files | ForEach-Object {
    if ([System.IO.Path]::IsPathRooted($_)) {
        $_
    } else {
        Join-Path $RepoRoot $_
    }
}

Write-Host "Running gofmt on $($fullPaths.Count) files..."
& $gofmt -w $fullPaths
if ($LASTEXITCODE -ne 0) {
    Write-Error "gofmt failed with exit code $LASTEXITCODE."
    exit $LASTEXITCODE
}

Write-Host "gofmt completed."
