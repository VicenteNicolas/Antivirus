# Estado de desarrollo

| Fase | Estado de 0.1.0 |
| --- | --- |
| Inicialización | Solución .NET 10, main, GitHub y CI de Windows |
| Interfaz | Diez secciones WPF, tema oscuro inicial, tema claro y navegación por teclado |
| Análisis | SHA-256, tipos, reglas explicables y adaptadores externos con límites de recursos |
| Persistencia | SQLite, catálogos, historial, exclusiones, configuración y cuarentena cifrada |
| Monitorización | Cambios con reconciliación, procesos y auditoría de Windows |
| Detección inteligente | Heurística local, extracción y entrenamiento reproducible con evaluación retenida |
| Rendimiento | Paralelismo limitado, deduplicación, caché de vigilancia, horarios y modo gaming |
| Validación | Compilación Release y pruebas de Windows. Distribución x64 mediante ZIP y digest SHA-256 |

## Trabajo posterior

- Incorporar un modelo entrenado con datos de procedencia verificada y validar la calidad antes de activarlo.
- Ampliar la matriz de pruebas con versiones de Windows, resoluciones y casos de escalado físico adicionales.
- Evaluar `clamd` como opción de alto rendimiento y mantener pruebas de compatibilidad con los motores externos.
- Evaluar protección preventiva en un entorno aislado, requisitos de firma de controladores y pruebas de recuperación.
- Firmar el paquete y evaluar un instalador cuando exista un certificado de distribución.
