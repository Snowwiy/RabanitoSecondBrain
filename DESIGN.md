---
version: alpha
name: Rabanito Second Brain
description: Consola local de conocimiento citado y evidencia de seguridad.
colors:
  background: "#0b0f14"
  surface: "#111821"
  elevated: "#18222d"
  text: "#e8eef5"
  muted: "#8ea0b5"
  primary: "#63e6be"
  warning: "#ffcc66"
  danger: "#ff7b8b"
  border: "#587086"
typography:
  sans:
    fontFamily: "system-ui, Segoe UI, sans-serif"
    fontSize: "14px"
    lineHeight: "1.45"
  mono:
    fontFamily: "ui-monospace, monospace"
rounded:
  DEFAULT: "8px"
  panel: "12px"
spacing:
  page: "16px"
  gap: "16px"
components:
  panel:
    borderRadius: "12px"
  control:
    borderRadius: "8px"
---

# Rabanito — Neural Knowledge Command Center

## Overview

Consola de trabajo local para consultar memoria técnica, proyectos, documentos y evidencia pública de seguridad. Idioma es-MX, Windows, objetivos de escritorio 1920×1080 y 2560×1440 con adaptación hasta ventanas estrechas. No existe alcance de mercado japonés ni interfaz japonesa. La referencia visual entregada es una sala de conocimiento radial y hexagonal: explorador denso a la izquierda, visualización central y ficha a la derecha, adaptada a la identidad de Rabanito. Cada dato conserva procedencia y estado; no se usan métricas ficticias.

Se conserva el dashboard y las operaciones existentes; no se reconstruyen. El centro de mando añade Neural Orbit, Hex Knowledge y Knowledge Tree sobre el grafo local; Knowledge Galaxy reutiliza el canvas 3D y sus filtros actuales. El banco de herramientas anterior permanece plegable. El catálogo de seguridad y Coding Memory conservan sus endpoints existentes. El selector de tema ofrece Raven Neon, Cyber Ocean, Violet Intelligence, Security Amber y Minimal Dark, sin fuentes externas ni CDNs.

## Colors

Modelo B: las variables de `web/index.html` son canónicas. Este archivo documenta los valores, no genera CSS. Mapa semántico: background→`--bg`, surface→`--panel`, elevated→`--panel2`, text→`--text`, muted→`--muted`, primary→`--accent`, warning→`--warn`, danger→`--bad`, border→`--line`. Los controles usan `--control-border`, botones `--button-border`; las categorías se asignan determinísticamente a una paleta cian, turquesa, violeta, naranja y verde. Los temas alteran variables semánticas sin repintar nodos manualmente. Pruebas Node comprueban contraste de roles base.

## Typography

Se reutiliza system-ui/Segoe UI o ui-monospace/Consolas, elegidas por el operador, sin descargar fuentes. El tamaño base es 14px y su escala es localmente configurable. Identificadores CVE, fechas, rutas relativas y citas permanecen como texto seleccionable. Los documentos importados se crean con `textContent`, nunca como HTML ejecutable.

## Layout

Cabecera compacta más una disposición de tres paneles redimensionables: explorador 258px, visualización flexible, inspector 306px; los anchos se limitan y se guardan localmente. Las vistas centrales son tabs mutuamente excluyentes, con estado visible/ARIA y controles compartidos. A 840px o menos se apilan y se usan los botones de colapso. El documento conserva scroll natural; las listas internas tienen presupuestos. El banco anterior se abre bajo demanda y mantiene sus módulos y controles.

## Elevation & Depth

Capas tonales, bordes visibles y sombra moderada ya existente en paneles. No incorporar fondos o efectos que confundan severidad con decoración. Foco de2px con `--accent`.

## Shapes

Paneles12px y controles8px, tabla sin contorno individual por celda. La forma y el texto acompañan al estado; color nunca es el único indicador.

## Components

El panel colapsable Security Architecture/Coding Memory comparte toolbar, inputs/select nativos, paginación y detalle de Cyber. No aplica otra navegación global, framework o paleta. Cards informativas sin cursor de acción; botones explícitos para abrir fichas. Las experiencias muestran sus fragmentos/citas y no inventan una acción de apertura. Se mantienen layouts responsive y presupuestos por biblioteca.

Panel, toolbar, button, input/select, metadata y error reutilizan el CSS existente. Selects y datalist son nativos: se acepta el popup del sistema operativo. No hay calendario ni componente de selección múltiple en Cyber. Scrollbar global tokenizada, visible y compatible con forced-colors.

Los paneles de datos muestran carga, cero coincidencias y error sin ocultar estados. Las consultas se envían por POST JSON local; no guardan query ni filtros en localStorage o URLs. Generaciones independientes descartan respuestas obsoletas. Las preferencias visuales (tema, escala, grosor/brillo de enlaces, densidad, calidad, zoom, tipografía, transparencia y paneles) se guardan solo en localStorage del navegador. No hay animación continua nueva; el canvas redibuja por interacción y respeta `prefers-reduced-motion`.

## Visual truth and graph semantics

El grafo dibuja solo nodos y relaciones recibidos de `/api/graph`. Los enlaces sugeridos son opcionales, discontinuos y naranjas; nunca se mezclan con enlaces explícitos confirmados. Los componentes conectados se calculan solo desde relaciones explícitas presentes y se etiquetan como conectividad. Orbit/HEX también pueden mostrar una estimación topológica multi-nivel de comunidades basada únicamente en los enlaces explícitos cargados; usa el mismo mapa de color determinista por grupo y nunca se presenta como semántica tipada o confirmada. Las etiquetas advierten que la estimación puede cubrir solo el subconjunto actualmente cargado. HEX también agrupa por metadatos reales. Tree agrupa documentos por `project_name`; informa explícitamente que no inventa subcomponentes ni jerarquía arquitectónica. La vista de documento combina metadatos y fragmentos citados con una lectura Markdown voluntaria y limitada por ID; cualquier contenido externo se renderiza como texto seguro.

## Do's and Don'ts

- Conservar citas y fechas exactas del proveedor, diferenciando publicación, modificación y consulta.
- Mostrar datos faltantes como “Sin puntuación” o “No informado”.
- No representar EPSS como explotación observada ni un producto coincidente como proyecto vulnerable.
- No añadir CDN, fuentes remotas, telemetría ni parámetros de búsqueda privados en URLs.
- No convertir similitud, componentes conectados ni metadatos de proyecto en hechos arquitectónicos.
- No mostrar resultados del servidor de fixtures como datos reales; el banner de prueba es obligatorio cuando `fixture: true`.
- La vista Markdown es de solo lectura, limitada a 65,536 bytes y puede ocultar patrones detectables de credenciales/rutas; no presentarla como copia exacta ni como detector universal.
- No convertir HTML ni instrucciones de notas importadas en comportamiento de la interfaz.

Auditoría visual/renderizada y lint oficial se registran en TEST_RESULTS; la existencia de este archivo no los da por aprobados.
