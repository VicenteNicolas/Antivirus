# Manual de Sentinel Security

## Análisis

- **Rápido** revisa las carpetas locales de Descargas, Escritorio, temporales e Inicio que estén disponibles.
- **Completo** permite seleccionar una o varias raíces de unidades locales. **Carpeta** y **Archivos** permiten revisar ubicaciones concretas.
- Durante el recorrido de una unidad, el total puede ser desconocido. La barra indica actividad mientras se descubren archivos. Pausar detiene el inicio de nuevos análisis. Los análisis de archivos que ya empezaron pueden terminar. Cancelar conserva un resumen parcial.
- **Amenazas** muestra detecciones y omisiones registradas. Selecciona una fila para ver los motores, los indicadores o la causa de omisión. El historial presenta los análisis recientes. «Sin hallazgos» describe el resultado obtenido con la cobertura disponible.

## Protección, procesos y auditoría

- Activa la vigilancia en **Protección en tiempo real**. Configura las carpetas desde **Configuración**, una ruta absoluta por línea. Cuando la lista queda vacía se usa Descargas si está disponible. La aplicación revisa archivos nuevos o modificados mientras esté abierta.
- En **Procesos**, actualiza el inventario, filtra por nombre, ruta, PID, fabricante o firma y ordena mediante los encabezados. Usa **Analizar ejecutable** para obtener el hash y el veredicto de la imagen ejecutable accesible.
- En **Seguridad del sistema**, ejecuta la auditoría para ver las respuestas de Windows. Algunas consultas pueden requerir permisos que no están disponibles para tu cuenta. Los indicadores de firma y procedencia ayudan a revisar los resultados. Una firma ausente, el uso de CPU o una ruta de tareas por sí solos no prueban que un elemento sea malware.

## Cuarentena

Selecciona un hallazgo con hash y confirma el aislamiento. Sentinel compara el hash actual con el de la detección, guarda una copia cifrada y retira el archivo original si es seguro hacerlo. Desde **Cuarentena**, puedes verificar la integridad o confirmar una restauración o eliminación. La restauración requiere que la ubicación original esté disponible y sin otro archivo en el mismo lugar. La clave de cifrado depende del usuario de Windows. Para revisar posteriormente un caso, conserva el perfil y sus datos.

## Motores y configuración

**Actualizaciones** muestra el estado de los motores y permite importar firmas, importar reglas YARA o actualizar mediante FreshClam. Para activar motores externos, guarda primero sus rutas en **Configuración**. Mantén las herramientas y las reglas al día desde sus fuentes oficiales.

El inicio con Windows, el monitor, las exclusiones, las notificaciones, los límites y el horario se aplican al guardar. El horario mide las horas desde el último análisis rápido completado y se ejecuta cuando la aplicación está abierta. Usa 0 para desactivarlo. El modo gaming reduce a un trabajador por análisis, reduce avisos del monitor y pospone análisis programados y actualizaciones automáticas. El monitor que ya estaba activo sigue funcionando.
