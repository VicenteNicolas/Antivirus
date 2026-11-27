# Canal de evaluación de ML.NET

Prepara un manifiesto TSV UTF-8 con el encabezado exacto `split<TAB>group<TAB>label<TAB>path`. Cada fila contiene:

- Una partición `train`, `validation` o `test`.
- Una familia o grupo de procedencia. Un grupo pertenece a una única partición.
- Una etiqueta verificada, `0` para benigno o `1` para positivo.
- Una ruta local absoluta o relativa al manifiesto.

Cada partición necesita ejemplos de ambas clases. Se rechazan hashes duplicados y grupos compartidos entre conjuntos. Prepara los datos en un entorno aislado y conserva las rutas, características, modelos y evaluaciones fuera de Git.

```powershell
dotnet run --project SentinelSecurity.MachineLearning -- extract C:\datos\manifiesto.tsv C:\datos\caracteristicas.tsv
dotnet run --project SentinelSecurity.MachineLearning -- train C:\datos\caracteristicas.tsv C:\datos\salida-nueva
```

La extracción genera características estáticas sin guardar las rutas originales en el TSV de salida. El entrenamiento compara configuraciones por F1 de validación y evalúa el modelo elegido en el conjunto de prueba retenido. La evaluación registra accuracy, precision, recall, F1, la matriz de confusión y las tasas de falsos positivos y negativos. La salida contiene `modelo.zip` y `evaluacion.json`. Una ejecución con archivos sintéticos sirve para comprobar el flujo técnico.

Después de revisar la evaluación y el digest del artefacto, usa `dotnet run --project SentinelSecurity.MachineLearning -- assess <directorio-del-modelo> <sha256-revisado> <archivo>` para evaluar un archivo con el modelo. La aplicación de escritorio muestra la función como pendiente de un modelo validado. [Documentación oficial de ML.NET](https://learn.microsoft.com/dotnet/machine-learning/)
