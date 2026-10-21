# Grill Me: entrevista revisada y publicación segura

```powershell
python -m rabanito interview --topic "Tema seleccionado"
```

Siete preguntas capturan hechos declarados, fuentes, decisiones, alternativas,
pruebas y pendientes. Las respuestas son datos no confiables: ningún comando o
instrucción que contengan se ejecuta. No hay llamadas de modelos ni proveedores.

## Revisión y aprobación

La vista previa muestra el **Markdown exacto candidato a guardar**, no un archivo
ya creado. Sus metadatos `kind: approved-interview` y `status: approved` describen
solo el estado propuesto si se escribe `APROBAR` en la pregunta final. Un banner
exterior deja explícito que todavía no existe aprobación ni persistencia. No se
reescribe el texto después de aprobarlo.

`APROBAR` dentro de una respuesta no aprueba la entrevista. Rechazar o interrumpir
antes de la aprobación no guarda nota, borrador, lock ni índice desde el motor.
La carga general de configuración de la CLI puede preparar sus directorios
vacíos, pero no guarda la entrevista. La aprobación es una afirmación del caller,
no autenticación ni verificación independiente de la historia relatada. Una
entrevista aprobada no se convierte en experiencia `confirmed/passed` de Coding
Memory por sus propias afirmaciones.

Antes de mostrar respuestas se rechazan texto inválido, controles peligrosos y
asignaciones sensibles detectables. Límite de160caracteres imprimibles para tema,
8000por respuesta y64KiB UTF-8 para el candidato completo. Los controles de
secretos son heurísticos, no DLP universal; no aportar credenciales. La revisión
humana sigue siendo necesaria. El contenido de la vista previa es privado: no
redirigirlo a logs compartidos ni enviarlo a servicios externos.

## Almacenamiento

- Solo `knowledge/personal/interviews/` dentro del checkout autorizado; sin
  solapamiento con fuentes importadas, incluso desactivadas. Se aplica la política
  interna de extensiones, exclusiones y tamaño configurado si es menor.
- Escritura nativa de Windows con los HANDLEs ya probados: padres fijados contra
  renombrado/borrado, rechazo de reparse points y lock con identidad comprobada.
- Temporal propio + flush/fsync + rename sin reemplazo. Una colisión conserva el
  archivo ajeno y busca el siguiente nombre, con un máximo de1000intentos. Un
  fallo previo a publicación no deja un Markdown parcial.
- La CLI pasa su `config_path`, que se comprueba de nuevo y fija bajo lock. La API
  Python lo acepta opcionalmente; sin él utiliza una copia de los `Settings`
  explícitos del caller. No descubre ni cambia configuración global.

`conduct_interview` mantiene la respuesta `{approved, topic, questions}` y añade
`path` solo al guardar. No requiere ni crea SQLite. La CLI conserva su indexación
incremental posterior a una captura aprobada. No hay escritor HTTP, nuevos
estados de API, instalación de Skills ni hooks automáticos.

Si una nota se guarda y después falla la indexación o la salida de consola,
conservar el archivo completo y ejecutar una sincronización autorizada; no
repetir ciegamente la entrevista. Sus nombres cronológicos no son una clave
idempotente por borrador. Obsidian y los repositorios originales siguen RO.

## Evidencia reproducible

```powershell
python -B -m unittest discover -s tests -p test_interview_storage.py -v
python -B scripts/validate_interview_storage.py
```

23regresiones nuevas, además de las tres existentes de entrevista: junctions
reales, UTF-8/control/secretos, revisión exacta, rechazo/interrupción sin archivos,
política/raíces, configuración cambiada, publicación/collisiones y concurrencia.
El script ejecuta cinco CLI con input sintético, prueba rechazo, aprobación,
recuperación citada y backup/restauración con dos FTS. No guarda conocimiento real
ni atribuye los fixtures a personas o proyectos de producción.
