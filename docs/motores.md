# Motores de detección y actualizaciones

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
