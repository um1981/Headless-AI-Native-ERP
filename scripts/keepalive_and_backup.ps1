# ============================================================================
# Daily Keep-Alive & Ledger Snapshot Backup Script (Rule 4 Mitigation)
# Prevents Supabase 7-day Free Tier inactivity pause & exports ledger snapshot
# ============================================================================

param(
    [string]$SupabaseUrl = $env:SUPABASE_URL,
    [string]$SupabaseKey = $env:SUPABASE_ANON_KEY,
    [string]$AgentToken  = $env:ERP_AGENT_TOKEN,
    [string]$BackupDir   = "$PSScriptRoot\..\backups"
)

$ErrorActionPreference = "Stop"

# Load from local mcp-server/.env if environment variables are not set
$localEnvFile = "$PSScriptRoot\..\mcp-server\.env"
if (Test-Path $localEnvFile) {
    Get-Content $localEnvFile | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
            $k = $matches[1].Trim()
            $v = $matches[2].Trim()
            if ($k -eq "SUPABASE_URL" -and -not $SupabaseUrl) { $SupabaseUrl = $v }
            if ($k -eq "SUPABASE_ANON_KEY" -and -not $SupabaseKey) { $SupabaseKey = $v }
            if ($k -eq "ERP_AGENT_TOKEN" -and -not $AgentToken) { $AgentToken = $v }
        }
    }
}

if (-not $SupabaseUrl -or -not $SupabaseKey) {
    throw "Missing SUPABASE_URL or SUPABASE_ANON_KEY. Set environment variables or configure mcp-server/.env"
}

if (-not (Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
}

$headers = @{
    "apikey"        = $SupabaseKey
    "Authorization" = "Bearer $SupabaseKey"
    "Content-Type"  = "application/json"
}

Write-Host "[1/2] Sending Keep-Alive Heartbeat to Supabase..." -ForegroundColor Cyan
$beatBody = @{ p_source = "powershell_daily_keepalive" } | ConvertTo-Json
$beatResult = Invoke-RestMethod -Method Post -Uri "$SupabaseUrl/rest/v1/rpc/rpc_health_keepalive" -Headers $headers -Body $beatBody
Write-Host "Heartbeat OK: $($beatResult | ConvertTo-Json -Compress)" -ForegroundColor Green

if ($AgentToken) {
    $dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $snapshotFile = Join-Path $BackupDir "erp_ledger_snapshot_$dateStamp.json"

    Write-Host "[2/2] Exporting PAT-Authenticated Ledger Snapshot to $snapshotFile..." -ForegroundColor Cyan
    $exportBody = @{ p_agent_token = $AgentToken } | ConvertTo-Json
    $snapshot = Invoke-RestMethod -Method Post -Uri "$SupabaseUrl/rest/v1/rpc/rpc_export_ledger_snapshot" -Headers $headers -Body $exportBody
    $snapshot | ConvertTo-Json -Depth 10 | Set-Content -Path $snapshotFile -Encoding UTF8
    Write-Host "Backup complete: $snapshotFile" -ForegroundColor Green
} else {
    Write-Host "[2/2] Skipped Ledger Snapshot Export (ERP_AGENT_TOKEN not provided)." -ForegroundColor Yellow
}
