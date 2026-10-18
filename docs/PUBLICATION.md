# Publicación segura del software

Git versiona software y documentación publicable, no conocimiento del usuario. `.gitignore` usa una allowlist raíz y exclusiones adicionales. `config/settings.example.json` es portable; la configuración real y los checkpoints operativos originales permanecen localmente sin rastrear, no se borran.

## Procedimiento

1. Revisa `git status`, `git ls-files` e historial. Ignore no elimina archivos rastreados. Si hay un secreto real en historia, detener el push y coordinar remediación sin reescritura destructiva.
2. Revisa código, fixtures, archivos ocultos y documentación. No publiques fuentes originales aunque el remoto sea privado.
3. Ejecuta `python -B scripts/publication_audit.py`. Solo informa archivo/regla/línea, nunca valores. Es un detector acotado, **no garantiza detectar todo secreto**; revisar manualmente.
4. Prepara archivos revisados; ejecuta `python -B scripts/publication_audit.py --staged`, `git diff --cached --check`, `git diff --cached --stat` y revisa el diff real. La segunda pasada lee blobs preparados, no confía en el filesystem.
5. Ejecuta pruebas y un smoke desde un checkout limpio, sin configuración privada; comprueba Skills, catálogo y ejemplo.
6. Verifica destino/rama y cambios remotos. No uses force push. Tras publicar, compara `HEAD` con `refs/heads/main` y verifica el árbol recibido.

El respaldo inicial y cada publicación posterior requieren autorización humana
específica. La solicitud de publicar el estado actual autoriza un commit y push
adicionales a main, no una cadencia de publicaciones ni un merge de Frontend-Design.
Después de verificar ese push, los avances siguientes vuelven a quedar locales
hasta una nueva autorización. No usar force push ni alterar otras ramas.

La visibilidad real debe comprobarse, no deducirse de una descripción histórica.
La publicación del estado acumulado fue autorizada expresamente en repositorio
público tras advertir esa condición. Esto no autoriza distribuir memoria privada,
relajar exclusiones ni añadir una licencia al código. El repositorio no requiere
notas ni bases operativas para ejecutar sus pruebas.

## Límites y recuperación

Bases, FTS, cachés HTTP, copias SQLite, fichas derivadas y registros privados quedan excluidos, igual que rutas personales e históricos de misión/continuidad. GitHub no reconstruye notas o decisiones privadas: respáldalas por separado.

La identidad del commit usa correo GitHub noreply configurado únicamente en este repositorio, sin alterar identidad global. El contenido remoto debe verificarse tras el push; la salida de un comando no basta por sí sola.
