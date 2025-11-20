<#
Script: deploy_migrate_railway.ps1
Propósito: Hacer backup de la base de datos PostgreSQL en Railway y ejecutar las migraciones Django

Requisitos:
- Tener instalado `pg_dump` (cliente PostgreSQL), `python` y `railway` CLI (opcional pero recomendado).
- Estar autenticado en Railway CLI y el proyecto vinculado si va a usar `railway run`.
- Tener la variable de entorno `DATABASE_URL` o `RAILWAY_DATABASE_URL` configurada (formato: postgres://user:pass@host:port/dbname)

Uso:
PowerShell desde la carpeta `backend`:
    .\scripts\deploy_migrate_railway.ps1    # hace backup y aplica migraciones
    .\scripts\deploy_migrate_railway.ps1 -BackupOnly  # sólo hace backup

Precaución: revisa el script antes de ejecutarlo en producción. Siempre haz backup manual también.
#>

param(
    [switch]$BackupOnly
)

Set-StrictMode -Version Latest

function Fail([string]$msg) {
    Write-Error $msg
    exit 1
}

# Obtener DATABASE_URL
$databaseUrl = $env:DATABASE_URL
if (-not $databaseUrl) { $databaseUrl = $env:RAILWAY_DATABASE_URL }
if (-not $databaseUrl) { Fail "No se encontró DATABASE_URL ni RAILWAY_DATABASE_URL en el entorno." }

try {
    $uri = [uri]$databaseUrl
} catch {
    Fail "DATABASE_URL inválida: $databaseUrl"
}

$userinfo = $uri.UserInfo -split ':'
if ($userinfo.Length -lt 2) { Fail "DATABASE_URL no contiene user:password en UserInfo." }
$dbUser = $userinfo[0]
$dbPass = $userinfo[1]
$dbHost = $uri.Host
$dbPort = $uri.Port
$dbName = $uri.AbsolutePath.TrimStart('/')

Write-Host "DB host: $dbHost port: $dbPort db: $dbName user: $dbUser"

# Preparar carpeta de backups
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$projectRoot = Resolve-Path (Join-Path $scriptDir '..')
$backupDir = Join-Path $projectRoot 'backups'
if (-not (Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir | Out-Null }

$timestamp = Get-Date -Format yyyyMMddHHmm
$dumpFile = Join-Path $backupDir "prod_db_backup_$timestamp.dump"

Write-Host "Creando backup en: $dumpFile"

# Ejecutar pg_dump
if (-not (Get-Command pg_dump -ErrorAction SilentlyContinue)) {
    Fail "No se encontró 'pg_dump' en el PATH. Instala cliente PostgreSQL." 
}

$env:PGPASSWORD = $dbPass

$pgArgs = @( '-h', $dbHost, '-p', $dbPort.ToString(), '-U', $dbUser, '-F', 'c', '-b', '-v', '-f', $dumpFile, $dbName )

Write-Host "Ejecutando pg_dump..."
& pg_dump @pgArgs
if ($LASTEXITCODE -ne 0) { Fail "pg_dump falló (exit code $LASTEXITCODE). Revisa la conexión y permisos." }

Write-Host "Backup completado: $dumpFile"

if ($BackupOnly) { Write-Host "BackupOnly=true, saliendo después del backup."; exit 0 }

# Ejecutar migraciones
Write-Host "Preparando para ejecutar migraciones Django..."

# Intentar usar Railway CLI si está disponible
if (Get-Command railway -ErrorAction SilentlyContinue) {
    Write-Host "railway CLI detectado. Ejecutando migraciones dentro del entorno Railway (railway run)."
    # Ejecuta migrate dentro de Railway (usa la imagen del proyecto)
    & railway run python manage.py migrate --noinput
    if ($LASTEXITCODE -ne 0) { Fail "railway run migrate falló (exit code $LASTEXITCODE)." }
    Write-Host "Migraciones aplicadas via railway run."
} else {
    Write-Host "railway CLI no detectado. Intentando ejecutar 'python manage.py migrate' usando la variable DATABASE_URL localmente."
    # Ejecutar migrate local con la misma DATABASE_URL (asegúrate de activar el virtualenv si hace falta)
    Push-Location $projectRoot
    try {
        & python manage.py migrate --noinput
        if ($LASTEXITCODE -ne 0) { Fail "python manage.py migrate falló (exit code $LASTEXITCODE)." }
        Write-Host "Migraciones aplicadas localmente (usando DATABASE_URL del entorno)."
    } finally {
        Pop-Location
    }
}

Write-Host "Proceso terminado correctamente. Verifica logs y tablas en la base de datos."

Write-Host "Rollback (si necesario): para revertir esta migración ejecutar 'python manage.py migrate notificacion zero' y/o restaurar el dump con pg_restore." 
