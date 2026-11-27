# Sentinel Security

Sentinel Security es una aplicación experimental de seguridad para Windows 11. Analiza archivos con SHA-256 y heurística estática, admite ClamAV y YARA, vigila carpetas y aísla archivos bajo confirmación. El panel identifica los motores disponibles y muestra los errores de cobertura de los análisis.

## Ejecutar en Windows

1. Instala [Microsoft .NET Desktop Runtime 10 para Windows x64](https://dotnet.microsoft.com/download/dotnet/10.0).
2. Extrae `SentinelSecurity-win-x64.zip` y ejecuta `SentinelSecurity.UI.exe` desde la carpeta extraída.
3. En **Actualizaciones**, selecciona **Configurar todos los motores**. El asistente descarga y verifica los componentes, configura las firmas y prueba cada motor. Después puedes comenzar con un análisis personalizado de una carpeta pequeña.

La distribución es experimental y no está firmada. Mantén Microsoft Defender activo. Sentinel vigila cambios después de que ocurren y puede funcionar con una cuenta estándar. Los motores portátiles, catálogos, resultados y cuarentena se guardan en `%LOCALAPPDATA%\SentinelSecurity`.

## Compilar desde el código

En Windows x64 con el SDK .NET 10:

```powershell
dotnet restore SentinelSecurity.slnx --locked-mode
dotnet build SentinelSecurity.slnx -c Release --no-restore
dotnet test SentinelSecurity.slnx -c Release --no-build
./scripts/publish.ps1
```

Abre `SentinelSecurity.slnx` en una versión de Visual Studio compatible con .NET 10. El script genera un ZIP con ejecutable, dependencias, manual y una suma SHA-256 independiente en `artifacts`. GitHub Actions ejecuta los mismos pasos en Windows.

## Documentación

- [Manual de usuario](docs/manual.md)
- [Configuración de ClamAV, YARA y catálogos SHA-256](docs/motores.md)
- [Arquitectura, límites y validación](docs/arquitectura.md)
- [Extracción, entrenamiento y evaluación con ML.NET](docs/ml.md)
- [Cambios](CHANGELOG.md) y [estado de desarrollo](ROADMAP.md)
