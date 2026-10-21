# Validación local del cargador de Skills de Hermes

Esta prueba opcional importa el módulo real `tools.skills_tool` de un checkout
local inspeccionado. No usa Hermes CLI, bootstrap, activación de entornos ni
instaladores. No es una conversación de agente ni una instalación en un perfil.

## Ejecutar

Desde este repositorio, con el Python de Windows que coincida exactamente con la
versión del entorno de dependencias seleccionado por el PM local de Hermes:

```powershell
& '<python.exe existente y compatible>' -B scripts/validate_hermes_skill.py --hermes-repo '<checkout local inspeccionado de Hermes>'
```

Los marcadores deben sustituirse por rutas autorizadas. El script falla si no
existe una selección PM compatible; no instala dependencias ni cambia `PATH`.
No ejecutar contra un checkout desconocido: importa código local y dependencias
nativas. La suite habitual no importa Hermes ni necesita esas dependencias.

## Qué comprueba

- Lee `installs/<install-key>/facts.json` y `pyvenv.cfg` para localizar el entorno
  comprometido por PM. Exige que esté dentro de esa instalación y que la versión
  de Python coincida. No ejecuta archivos `.pth`.
- Copia únicamente la Skill Hermes de este proyecto a un home temporal dentro de
  `tests/.test-temp/`. La configuración temporal no desactiva el descubrimiento
  predeterminado de proyectos, pero no agrega confianza ni fuentes externas.
- Invoca `skill_view` real, sin y con preprocesado. Exige éxito, cuerpo idéntico,
  parser YAML nativo, disponibilidad declarada y ausencia de setup pendiente.
- Exige el rechazo de tres rutas inválidas y que no se importen los módulos de
  bootstrap/CLI. Comprueba limpieza del temporal y selección PM sin cambios.
- Devuelve JSON de metadatos y exit `0` solo si todos los controles pasan; exit
  `1` para un resultado incompleto. No imprime Skill, credenciales ni logs.

El proceso hijo recibe solo variables de entorno básicas de Windows y un
`HERMES_HOME` temporal. Un audit hook bloquea las escrituras Python fuera del
temporal, lecturas sensibles, conexiones de red y subprocesos; se comprueba un
rechazo de escritura contra una ruta sintética del propio repositorio. Algunas
sondas opcionales de Hermes pueden ser rechazadas y aparecer como contadores.
El hook es defensa adicional para código inspeccionado, **no un sandbox del SO**
ni una garantía frente a código nativo arbitrario.

## Evidencia y límites

Probado en Windows con Python3.14.7 y Hermes fuente
`63d0b94120027d487c9a5235b9ec64b696af1b26`, utilizando sus dependencias ya presentes.
El módulo completo aceptó la Skill y rechazó las tres rutas inválidas. Las pruebas
reproducibles del contrato están en `tests/test_hermes_native_probe.py`.

Esto mejora la evidencia anterior de parser aislado, pero `available` es un
estado declarado de requisitos, no prueba del intérprete que selecciona
`terminal`, de permisos del perfil Rabanito, de convivencia con Jev/OAuth ni de
acceso desde Opus/Luna/Claude. La recuperación CLI del Second Brain se prueba por
separado; este validador no la presenta como transporte terminal de Hermes.

No instala la Skill, modifica perfiles reales, repara ACL, llama a modelos ni
confirma memorias. La activación y las sesiones de cliente requieren su propia
etapa autorizada. No reejecutar Hermes CLI para intentar forzar esa validación.
