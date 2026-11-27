# Historial de cambios

## 0.2.0

- Asistente WPF para configurar, verificar y activar los motores desde Actualizaciones, con progreso por etapa, cancelación y diagnóstico.
- Instalación portátil de ClamAV y YARA, con descarga desde los repositorios oficiales y comprobación SHA-256 antes de la extracción.
- Actualización de bases oficiales mediante FreshClam e importación de firmas SHA-256 de Cisco Talos. Las firmas importadas manualmente conservan su catálogo separado.
- Descarga de un conjunto inicial de reglas de Windows de ReversingLabs desde una revisión fija y validación de cada archivo antes de activarlo.
- Comprobación de funcionamiento del analizador ClamAV, las reglas YARA y la búsqueda SHA-256 en SQLite. Los motores disponibles se conservan si otro paso falla.

## 0.1.0

- Interfaz WPF en español con tema oscuro y tema claro.
- Análisis personalizado, rápido y completo con SHA-256, heurística y conectores de ClamAV y YARA.
- Persistencia SQLite, configuración y cuarentena cifrada con verificación.
- Vigilancia de carpetas, inventario de procesos y auditoría de Windows.
- Pipeline CLI de extracción de características y evaluación de ML.NET.
- Automatización de compilación, pruebas y publicación en Windows.
