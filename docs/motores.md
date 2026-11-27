# Motores de detección y actualizaciones

## Configuración inicial

En **Inicio**, entra en el asistente cuando aparezca el aviso de motores sin configurar. En **Actualizaciones**, pulsa **Configurar todos los motores** para comenzar. El asistente usa la cuenta de Windows actual y guarda los componentes portátiles y las bases en el perfil local de Sentinel.

| Etapa | Origen y comprobación |
| --- | --- |
| ClamAV | ZIP oficial de Cisco Talos para Windows x64. Sentinel comprueba el SHA-256 publicado y ejecuta las comprobaciones de versión de los componentes portátiles. |
| FreshClam | Bases oficiales de ClamAV. FreshClam comprueba las bases y Sentinel ejecuta ClamAV sobre un archivo inofensivo antes de activar la generación. |
| SHA-256 | Firmas de archivo completo extraídas de las bases firmadas de Cisco Talos. Sentinel actualiza el catálogo oficial en SQLite y comprueba la búsqueda de una firma. Las importaciones manuales conservan su catálogo separado. |
| YARA | Busca una instalación conocida y comprueba que responda. Si hace falta, descarga el ZIP oficial de VirusTotal y verifica su SHA-256. Conserva las reglas activas válidas o incorpora seis archivos de reglas de Windows de ReversingLabs y comprueba que pueden analizar un archivo inofensivo. |

El primer paso de ClamAV puede descargar varios cientos de megabytes de herramientas y firmas. La interfaz muestra cada etapa y permite cancelar. Si alguna falla, revisa su mensaje y vuelve a ejecutar el asistente. Las etapas que ya activaron un motor válido se conservan. Si el servidor de FreshClam impone una espera, los intentos posteriores respetan ese estado.

Las reglas iniciales de ReversingLabs se descargan en código fuente desde la revisión `e0a0be54aa1e11ccfd6854e4f19e9476f328fd84`. Se comprueba el SHA-256 fijado para cada archivo y su licencia MIT. Es una selección inicial de reglas de Windows. [Repositorio oficial de ReversingLabs](https://github.com/reversinglabs/reversinglabs-yara-rules/tree/e0a0be54aa1e11ccfd6854e4f19e9476f328fd84)

La versión 0.2.0 fija las descargas portátiles de ClamAV 1.5.5 y YARA 4.6.0. [ClamAV 1.5.5](https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.5.5) · [YARA 4.6.0](https://github.com/VirusTotal/yara/releases/tag/v4.6.0)

**Actualizar ClamAV** actualiza también el catálogo SHA-256 si usas la instalación del asistente. En **Configuración**, puedes permitir una comprobación diaria mientras Sentinel esté abierto. Las descargas y el análisis funcionan junto a Microsoft Defender.

La prueba de integración con bases firmadas se habilita indicando el directorio de `main.cvd`, `daily.cvd` y `bytecode.cvd` con `SENTINEL_TEST_CLAM_DATABASE`, y la ruta de Sigtool con `SENTINEL_TEST_SIGTOOL`. La prueba verifica la importación y una búsqueda tras reabrir SQLite.

## Configuración manual

Los controles de importación y las rutas manuales siguen disponibles en **Actualizaciones** y **Configuración**.

## ClamAV

1. Instala los binarios de Windows x64 desde [ClamAV](https://www.clamav.net/downloads). Mantén el paquete oficial actualizado. ClamAV es GPLv2 y se distribuye por separado de Sentinel. [Licencia y capacidades](https://docs.clamav.net/Introduction.html)
2. En **Configuración**, selecciona las rutas absolutas de `clamscan.exe` y `freshclam.exe`. Si ya dispones de bases oficiales, puedes indicar también su directorio.
3. Guarda, abre **Actualizaciones** y ejecuta **Actualizar ClamAV**. La operación escribe en un directorio nuevo bajo los datos de Sentinel y usa el espejo oficial. Sentinel publica la ruta únicamente después de verificar que la nueva base oficial puede cargarse. En caso de fallo, la ruta activa anterior sigue disponible. [Actualización oficial de firmas](https://docs.clamav.net/manual/Usage/SignatureManagement.html)

ClamAV usa límites de tiempo, número de archivos, recursión y tamaño expandido. Las alertas de límites y heurísticas de ClamAV se presentan como advertencias. El uso de `clamscan` puede ser más lento porque el programa carga bases al iniciar cada análisis. Aplica la configuración automática solo cuando FreshClam esté disponible.

## YARA

1. Instala YARA para Windows desde el [proyecto oficial y su licencia BSD](https://github.com/VirusTotal/yara). Configura la ruta absoluta de `yara.exe`.
2. Consigue las reglas en código fuente y el SHA-256 de la misma versión por un canal confiable. Prepara un archivo con el digest de 64 caracteres hexadecimales al comienzo de la primera línea.
3. En **Actualizaciones**, indica las reglas y el digest. Sentinel comprueba el hash, valida las reglas con YARA y activa una copia local en caso de éxito. Se aceptan fuentes UTF-8 autocontenidas. Las coincidencias YARA generan avisos de revisión. [Uso de YARA por línea de comandos](https://yara.readthedocs.io/en/latest/commandline.html)

## Catálogo SHA-256

Importa un archivo TSV UTF-8 sin encabezado. Cada fila contiene 64 caracteres hexadecimales, una tabulación y el nombre de la firma. Las líneas vacías y las que empiezan por `#` se ignoran. La importación reemplaza el catálogo de forma transaccional y registra el SHA-256 del TSV como su versión. Verifica la procedencia del catálogo antes de confirmarlo, porque sus coincidencias exactas se clasifican como malware. Sentinel empieza con el catálogo vacío.

## EICAR

La suite usa contenido sintético inofensivo. Si ya dispones del archivo de prueba estándar EICAR de 68 bytes en un entorno aislado, puedes indicarlo mediante `SENTINEL_EICAR_PATH` y ejecutar `dotnet test`. La prueba verifica el SHA-256 exacto y su detección por el catálogo. Se omite cuando el archivo no está disponible. El archivo de prueba se mantiene fuera del repositorio. [EICAR Standard Anti-Malware Test File](https://www.eicar.org/download-anti-malware-testfile/)
