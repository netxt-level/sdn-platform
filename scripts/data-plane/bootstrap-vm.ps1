param(
    [string]$VmName = "sdn-lab",
    [int]$Cpus = 4,
    [string]$Memory = "8G",
    [string]$Disk = "40G",
    [string]$Image = "24.04",
    [ValidateSet("dataplane", "full")][string]$Profile = "dataplane",
    [string]$AnalyzerInterface = "auto"
)

$ErrorActionPreference = "Stop"

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Command failed with exit code $LASTEXITCODE"
    }
}

function Wait-HttpEndpoint {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [ValidateSet("Get", "Head")][string]$Method = "Get"
    )

    for ($Attempt = 1; $Attempt -le 30; $Attempt++) {
        try {
            Invoke-WebRequest -Uri $Uri -Method $Method -TimeoutSec 5 -UseBasicParsing | Out-Null
            return
        } catch {
            if ($Attempt -eq 30) {
                throw "Endpoint did not become ready: $Uri"
            }
            Start-Sleep -Seconds 2
        }
    }
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$CloudInit = Join-Path $RepoRoot "infrastructure\multipass\cloud-init.yaml"
$ProvisionScript = Join-Path $RepoRoot "scripts\data-plane\provision-ubuntu.sh"
$EnvFile = Join-Path $RepoRoot ".env"
$MainCompose = Join-Path $RepoRoot "docker-compose.yml"
$ControlCompose = Join-Path $RepoRoot "docker-compose.control-plane.yml"
$VmProjectDir = "/home/ubuntu/sdn-platform"
$RemoteArchive = "/home/ubuntu/sdn-platform-source.tar.gz"
$Archive = Join-Path ([System.IO.Path]::GetTempPath()) "sdn-platform-$([guid]::NewGuid()).tar.gz"

if (-not (Get-Command multipass -ErrorAction SilentlyContinue)) {
    throw "Multipass is not installed or is not available in PATH."
}

if (-not (Get-Command tar -ErrorAction SilentlyContinue)) {
    throw "tar is not available in PATH."
}

if ($Profile -eq "dataplane" -and -not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker is required on the host for the dataplane profile."
}

if (-not (Test-Path $EnvFile)) {
    throw "Missing $EnvFile"
}

if (-not (Test-Path $CloudInit)) {
    throw "Missing $CloudInit"
}

& multipass info $VmName *> $null
$InstanceExists = $LASTEXITCODE -eq 0

if ($InstanceExists) {
    Write-Host "Reusing Multipass instance: $VmName"
    & multipass start $VmName *> $null
} else {
    Write-Host "Creating ${VmName}: Ubuntu ${Image}, ${Cpus} CPU, ${Memory} RAM, ${Disk} disk"
    Invoke-Native "multipass" @(
        "launch", $Image,
        "--name", $VmName,
        "--cpus", $Cpus.ToString(),
        "--memory", $Memory,
        "--disk", $Disk,
        "--cloud-init", $CloudInit
    )
}

Write-Host "Waiting for cloud-init to finish..."
Invoke-Native "multipass" @(
    "exec", $VmName, "--",
    "sudo", "cloud-init", "status", "--wait"
)

try {
    Write-Host "Ensuring Ubuntu packages are installed..."
    Invoke-Native "multipass" @(
        "transfer", $ProvisionScript,
        "${VmName}:/home/ubuntu/provision-ubuntu.sh"
    )
    Invoke-Native "multipass" @(
        "exec", $VmName, "--",
        "sudo", "bash", "/home/ubuntu/provision-ubuntu.sh"
    )
    Invoke-Native "multipass" @(
        "exec", $VmName, "--",
        "rm", "-f", "/home/ubuntu/provision-ubuntu.sh"
    )

    Write-Host "Packing the project without generated files..."
    Push-Location $RepoRoot
    try {
        Invoke-Native "tar" @(
            "-czf", $Archive,
            "--format=ustar",
            "--exclude=.git",
            "--exclude=.venv",
            "--exclude=.pytest_cache",
            "--exclude=frontend/node_modules",
            "--exclude=frontend/.next",
            "--exclude=frontend/tsconfig.tsbuildinfo",
            "--exclude=*/__pycache__",
            "--exclude=*.pyc",
            "."
        )
    } finally {
        Pop-Location
    }

    Write-Host "Synchronizing the project into ${VmName}:${VmProjectDir}..."
    Invoke-Native "multipass" @("transfer", $Archive, "${VmName}:${RemoteArchive}")
    Invoke-Native "multipass" @("exec", $VmName, "--", "rm", "-rf", "/home/ubuntu/sdn-platform-next")
    Invoke-Native "multipass" @("exec", $VmName, "--", "mkdir", "-p", "/home/ubuntu/sdn-platform-next")
    Invoke-Native "multipass" @("exec", $VmName, "--", "tar", "-xzf", $RemoteArchive, "-C", "/home/ubuntu/sdn-platform-next")
    Invoke-Native "multipass" @("exec", $VmName, "--", "rm", "-rf", $VmProjectDir)
    Invoke-Native "multipass" @("exec", $VmName, "--", "mv", "/home/ubuntu/sdn-platform-next", $VmProjectDir)
    Invoke-Native "multipass" @("exec", $VmName, "--", "rm", "-f", $RemoteArchive)

    $Info = & multipass info $VmName
    $IpLine = $Info | Select-String -Pattern '^IPv4:' | Select-Object -First 1
    $VmIp = ($IpLine.ToString() -split '\s+')[1]

    if ($Profile -eq "dataplane") {
        $DefaultRoute = & multipass exec $VmName -- ip route show default
        if ($LASTEXITCODE -ne 0) {
            throw "Could not determine the host gateway from the VM."
        }
        $RouteParts = (($DefaultRoute -join " ").Trim() -split '\s+')
        $HostGateway = $RouteParts[2]
        $ResolvedAnalyzerInterface = $AnalyzerInterface
        if ($ResolvedAnalyzerInterface -eq "auto") {
            $DevIndex = [Array]::IndexOf($RouteParts, "dev")
            if ($DevIndex -lt 0 -or $DevIndex + 1 -ge $RouteParts.Length) {
                throw "Could not determine the Analyzer interface in the VM."
            }
            $ResolvedAnalyzerInterface = $RouteParts[$DevIndex + 1]
        }
        $BackendUrl = "http://${HostGateway}:8000"
        $FrontendPort = if ($env:FRONTEND_PORT) { $env:FRONTEND_PORT } else { "3000" }
        $FrontendUrl = "http://${HostGateway}:${FrontendPort}"
        $ControlArgs = @("compose", "-f", $MainCompose, "-f", $ControlCompose)

        Write-Host "Starting backend, frontend, and databases on the host..."
        Invoke-Native "docker" ($ControlArgs + @("config", "--quiet"))
        & docker @($ControlArgs + @("stop", "analyzer")) *> $null
        & docker @($ControlArgs + @("rm", "-f", "analyzer")) *> $null
        Invoke-Native "docker" ($ControlArgs + @(
            "up", "-d", "--build",
            "postgres", "influxdb", "elasticsearch", "backend", "frontend"
        ))

        Write-Host "Waiting for the host PostgreSQL service..."
        $PostgresReady = $false
        for ($Attempt = 1; $Attempt -le 30; $Attempt++) {
            & docker @($ControlArgs + @(
                "exec", "-T", "postgres", "sh", "-c",
                'pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
            )) *> $null
            if ($LASTEXITCODE -eq 0) {
                $PostgresReady = $true
                break
            }
            Start-Sleep -Seconds 2
        }
        if (-not $PostgresReady) {
            throw "Host PostgreSQL did not become ready."
        }

        Write-Host "Applying database migrations on the host..."
        Invoke-Native "docker" ($ControlArgs + @("run", "--rm", "migrate"))

        Write-Host "Stopping the previous full stack in the VM, if present..."
        Invoke-Native "multipass" @(
            "exec", $VmName, "--",
            "docker", "compose", "-f", "${VmProjectDir}/docker-compose.yml",
            "down", "--remove-orphans"
        )

        Write-Host "Starting the Analyzer in the VM..."
        Invoke-Native "multipass" @(
            "exec", $VmName, "--",
            "env", "BACKEND_BASE_URL=${BackendUrl}", "ANALYZER_INTERFACE=${ResolvedAnalyzerInterface}",
            "docker", "compose", "-f", "${VmProjectDir}/docker-compose.dataplane.yml",
            "up", "-d", "--build"
        )

        Write-Host "Verifying the hybrid data-plane environment..."
        Invoke-Native "multipass" @(
            "exec", $VmName, "--",
            "bash", "${VmProjectDir}/scripts/data-plane/verify-environment.sh",
            $VmProjectDir, "dataplane", $BackendUrl, $FrontendUrl
        )

        Wait-HttpEndpoint "http://127.0.0.1:8000/health"
        Wait-HttpEndpoint "http://127.0.0.1:${FrontendPort}" "Head"

        Write-Host ""
        Write-Host "Hybrid SDN lab is ready."
        Write-Host "Profile:   dataplane"
        Write-Host "VM:        $VmName ($VmIp)"
        Write-Host "Analyzer:  VM host network ($ResolvedAnalyzerInterface)"
        Write-Host "Frontend:  http://127.0.0.1:${FrontendPort}"
        Write-Host "Backend:   http://127.0.0.1:8000"
        Write-Host "API docs:  http://127.0.0.1:8000/docs"
    } else {
        Write-Host "Building and starting the full platform in the VM..."
        Invoke-Native "multipass" @(
            "exec", $VmName, "--",
            "docker", "compose", "-f", "${VmProjectDir}/docker-compose.yml",
            "config", "--quiet"
        )
        Invoke-Native "multipass" @(
            "exec", $VmName, "--",
            "docker", "compose", "-f", "${VmProjectDir}/docker-compose.yml",
            "up", "-d", "--build"
        )

        Write-Host "Applying database migrations in the VM..."
        Invoke-Native "multipass" @(
            "exec", $VmName, "--",
            "docker", "compose", "-f", "${VmProjectDir}/docker-compose.yml",
            "run", "--rm",
            "-v", "${VmProjectDir}/alembic.ini:/app/alembic.ini:ro",
            "-v", "${VmProjectDir}/migrations:/app/migrations:ro",
            "backend", "alembic", "upgrade", "head"
        )

        Write-Host "Verifying Mininet, OVS, Docker, and service health..."
        Invoke-Native "multipass" @(
            "exec", $VmName, "--",
            "bash", "${VmProjectDir}/scripts/data-plane/verify-environment.sh",
            $VmProjectDir, "full"
        )

        Write-Host ""
        Write-Host "Full VM SDN lab is ready."
        Write-Host "Profile:  full"
        Write-Host "VM:       $VmName ($VmIp)"
        Write-Host "Frontend: http://${VmIp}:3000"
        Write-Host "Backend:  http://${VmIp}:8000"
        Write-Host "API docs: http://${VmIp}:8000/docs"
    }
} finally {
    if (Test-Path $Archive) {
        Remove-Item -Force $Archive
    }
    & multipass exec $VmName -- rm -f $RemoteArchive *> $null
}
