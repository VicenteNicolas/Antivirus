# Arquitectura y compatibilidad

| Proyecto | Responsabilidad |
| --- | --- |
| Core | Contratos y modelos, opciones y control del análisis |
| Engine | Recorrido limitado, hash y tipo de archivo, heurística PE, Authenticode y adaptadores ClamAV/YARA |
| Infrastructure | SQLite, configuración, catálogos, hallazgos y cuarentena cifrada |
| Monitoring | FileSystemWatcher, reconciliación, procesos y auditoría de Windows |
| MachineLearning | Extracción reproducible, entrenamiento y evaluación ML.NET |
| UI | WPF, MVVM, composición de servicios, acciones y recursos visuales en español |
| Tests | Pruebas unitarias y de integración en Windows |

La interfaz construye los servicios por inyección de constructor. Engine depende de Core y consulta firmas a través de `ISignatureLookup`. Los hallazgos conservan el motor y su evidencia. Las reglas heurísticas aportan una puntuación que se puede revisar. Malware identificado requiere coincidencias de un catálogo local autorizado o evidencia de firmas de ClamAV. YARA y los indicadores estáticos pueden generar avisos.

## Datos y seguridad

SQLite usa parámetros y transacciones para cambios de catálogos y configuración. Los archivos grandes, las ubicaciones remotas, enlaces y rutas no accesibles se omiten con contexto. Los archivos se leen sin ejecutarlos. Los detectores externos reciben argumentos por separado y tienen un límite de ejecución. El recorrido y la vigilancia limitan memoria y concurrencia. El inventario usa muestras de CPU y el valor de memoria observado en Windows.

La cuarentena cifra cada archivo con AES-GCM y protege la clave con DPAPI de usuario. Antes de retirar el original, valida el hash y guarda metadatos. Las operaciones de restauración verifican la integridad y evitan sobrescribir destinos. Los datos se crean en el perfil de Windows. Las rutas y registros pueden contener información privada del equipo.

## Límites actuales

- Protección posterior al cambio de archivos mientras se ejecuta la aplicación. Requiere que el usuario configure y valide su cobertura de firmas. Windows y Defender conservan sus responsabilidades.
- Los permisos, archivos abiertos, enlaces, límites de archivos y límites de contenido comprimido pueden dejar objetos sin analizar. Los motores externos pueden faltar o no cargar sus bases.
- El inventario inspecciona la imagen ejecutable en disco. Los procesos protegidos pueden ocultar datos. La auditoría presenta una muestra acotada y el historial local de Windows Update.
- El modelo ML.NET requiere datos con origen y particiones apropiadas, evaluación y revisión. La distribución no incluye modelo ni dataset, y no usa resultados sintéticos como medida de calidad.
- La distribución es x64, depende de .NET Desktop Runtime 10 y no está firmada. La protección de kernel requeriría un proyecto separado con validación aislada, controladores firmados y pruebas exhaustivas.

Microsoft.Data.Sqlite, ProtectedData, ML.NET y .NET se distribuyen como proyectos de código abierto bajo MIT. ClamAV y YARA se instalan por separado con sus licencias GPLv2 y BSD. [SQLite para .NET](https://www.nuget.org/packages/Microsoft.Data.Sqlite/10.0.15), [ProtectedData](https://www.nuget.org/packages/System.Security.Cryptography.ProtectedData/10.0.15), [ML.NET](https://github.com/dotnet/machinelearning) y [ciclo de soporte de .NET](https://dotnet.microsoft.com/platform/support/policy).
