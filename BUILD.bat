@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo.
echo ╔════════════════════════════════════════╗
echo ║  CHROME UNIVERSAL RECOVERY v3.0         ║
echo ║  Build Script                           ║
echo ╚════════════════════════════════════════╝
echo.

REM Vérifier Go
echo [*] Vérification de Go...
go version >nul 2>&1
if errorlevel 1 (
    echo.
    echo [✗] Go n'est pas installé!
    echo.
    echo Installez depuis: https://golang.org/dl
    echo.
    pause
    exit /b 1
)
echo [✓] Go trouvé

REM Initialiser le projet Go
echo [*] Configuration du projet...
if not exist "go.mod" (
    go mod init chrome_universal >nul
)

REM Télécharger dépendances
echo [*] Téléchargement des dépendances...
go get golang.org/x/sys/windows >nul 2>&1
go get github.com/mattn/go-sqlite3 >nul 2>&1
go mod tidy >nul 2>&1

REM Compilation
echo [*] Compilation...
set GOOS=windows
set GOARCH=amd64
go build -o ChromeUniversal.exe ChromeUniversal.go

if errorlevel 1 (
    echo [✗] Erreur compilation!
    echo.
    pause
    exit /b 1
)

echo [✓] Compilation réussie!
echo.
echo ╔════════════════════════════════════════╗
echo ║  PRÊT À LANCER                          ║
echo ║  Fichier: ChromeUniversal.exe           ║
echo ╚════════════════════════════════════════╝
echo.
echo [*] Lancement...
echo.

ChromeUniversal.exe

pause
