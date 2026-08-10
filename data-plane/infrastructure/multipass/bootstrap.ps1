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

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$CloudInit = Join-Path $PSScriptRoot "cloud-init.yaml"
$ProvisionScript = Join-Path $PSScriptRoot "provision.sh"
$EnvFile = Join-Path $RepoRoot ".env"
$MainCompose = Join-Path $RepoRoot "docker-compose.yml"
$ControlCompose = Join-Path $RepoRoot "docker-compose.control-plane.yml"
$ControllerRestPort = if ($env:CONTROLLER_REST_PORT) { $env:CONTROLLER_REST_PORT } else { "8080" }
$SensorInterface = if ($env:SENSOR_INTERFACE) { $env:SENSOR_INTERFACE } else { "sdn-sensor0" }
$MirrorInterface = if ($env:MIRROR_INTERFACE) { $env:MIRROR_INTERFACE } else { "sdn-mirror0" }
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

    $ResolvedAnalyzerInterface = $AnalyzerInterface
    if ($ResolvedAnalyzerInterface -eq "auto") {
        $ResolvedAnalyzerInterface = $SensorInterface
    }
    if ([string]::IsNullOrWhiteSpace($ResolvedAnalyzerInterface)) {
        throw "Analyzer interface must not be empty."
    }

    if ($ResolvedAnalyzerInterface -eq $SensorInterface) {
        Write-Host "Preparing the Analyzer sensor veth in the VM..."
        Invoke-Native "multipass" @(
            "exec", $VmName, "--",
            "sudo", "python3", "${VmProjectDir}/data-plane/mininet/sensor.py", "setup",
            "--sensor-interface", $SensorInterface,
            "--mirror-interface", $MirrorInterface
        )
    } else {
        Write-Host "Using the custom Analyzer interface: $ResolvedAnalyzerInterface"
    }

    if ($Profile -eq "dataplane") {
        $DefaultRoute = & multipass exec $VmName -- ip route show default
        if ($LASTEXITCODE -ne 0) {
            throw "Could not determine the host gateway from the VM."
        }
        $RouteParts = (($DefaultRoute -join " ").Trim() -split '\s+')
        $HostGateway = $RouteParts[2]
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

        Write-Host "Starting the Controller in the VM..."
        Invoke-Native "multipass" @(
            "exec", $VmName, "--",
            "docker", "compose", "--profile", "dataplane",
            "-f", "${VmProjectDir}/docker-compose.yml",
            "up", "-d", "--build", "controller"
        )

        Write-Host "Starting the Analyzer in the VM..."
        Invoke-Native "multipass" @(
            "exec", $VmName, "--",
            "env", "COMPOSE_IGNORE_ORPHANS=true",
            "BACKEND_BASE_URL=${BackendUrl}", "ANALYZER_INTERFACE=${ResolvedAnalyzerInterface}",
            "docker", "compose",
            "-f", "${VmProjectDir}/docker-compose.yml",
            "-f", "${VmProjectDir}/docker-compose.dataplane.yml",
            "up", "-d", "--build", "--force-recreate", "--no-deps", "analyzer"
        )

        Write-Host "Verifying the hybrid data-plane environment..."
        Invoke-Native "multipass" @(
            "exec", $VmName, "--",
            "bash", "${VmProjectDir}/data-plane/infrastructure/multipass/verify-vm.sh",
            $VmProjectDir, "dataplane", $BackendUrl, $FrontendUrl,
            "http://127.0.0.1:${ControllerRestPort}/health",
            $ResolvedAnalyzerInterface
        )

        Wait-HttpEndpoint "http://127.0.0.1:8000/health"
        Wait-HttpEndpoint "http://127.0.0.1:${FrontendPort}" "Head"

        Write-Host ""
        Write-Host "Hybrid SDN lab is ready."
        Write-Host "Profile:   dataplane"
        Write-Host "VM:        $VmName ($VmIp)"
        Write-Host "Analyzer:  VM host network ($ResolvedAnalyzerInterface)"
        Write-Host "Controller: http://${VmIp}:${ControllerRestPort}"
        Write-Host "Frontend:  http://127.0.0.1:${FrontendPort}"
        Write-Host "Backend:   http://127.0.0.1:8000"
        Write-Host "Health:    http://127.0.0.1:8000/health"
    } else {
        Write-Host "Building and starting the full platform in the VM..."
        Invoke-Native "multipass" @(
            "exec", $VmName, "--",
            "env", "BACKEND_BASE_URL=http://127.0.0.1:8000",
            "ANALYZER_INTERFACE=${ResolvedAnalyzerInterface}",
            "docker", "compose", "--profile", "dataplane",
            "-f", "${VmProjectDir}/docker-compose.yml",
            "-f", "${VmProjectDir}/docker-compose.dataplane.yml",
            "config", "--quiet"
        )
        Invoke-Native "multipass" @(
            "exec", $VmName, "--",
            "env", "BACKEND_BASE_URL=http://127.0.0.1:8000",
            "ANALYZER_INTERFACE=${ResolvedAnalyzerInterface}",
            "docker", "compose", "--profile", "dataplane",
            "-f", "${VmProjectDir}/docker-compose.yml",
            "-f", "${VmProjectDir}/docker-compose.dataplane.yml",
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
            "bash", "${VmProjectDir}/data-plane/infrastructure/multipass/verify-vm.sh",
            $VmProjectDir, "full",
            "http://127.0.0.1:8000", "http://127.0.0.1:3000",
            "http://127.0.0.1:${ControllerRestPort}/health",
            $ResolvedAnalyzerInterface
        )

        Write-Host ""
        Write-Host "Full VM SDN lab is ready."
        Write-Host "Profile:  full"
        Write-Host "VM:       $VmName ($VmIp)"
        Write-Host "Frontend: http://${VmIp}:3000"
        Write-Host "Backend:  http://${VmIp}:8000"
        Write-Host "Controller: http://${VmIp}:${ControllerRestPort}"
        Write-Host "Health:   http://${VmIp}:8000/health"
    }
} finally {
    if (Test-Path $Archive) {
        Remove-Item -Force $Archive
    }
    & multipass exec $VmName -- rm -f $RemoteArchive *> $null
}
