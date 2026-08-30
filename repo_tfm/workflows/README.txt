# Workflows de n8n
 
Esta carpeta contiene los seis flujos de trabajo del sistema, exportados desde n8n en formato JSON.
 
Para usarlos: en n8n, cada archivo se importa con **Import from File** (menú "…" → Import).
 
| Archivo | Fase | Función |
|---------|------|---------|
| `01-ingesta-nvd.json` | Ingesta | Recoge las vulnerabilidades recientes de la NVD |
| `02-ingesta-cisa-kev.json` | Ingesta | Recoge las explotadas activamente de CISA KEV |
| `03-enriquecimiento-epss.json` | Enriquecimiento | Añade la probabilidad de explotación (EPSS) |
| `04-priorizacion-ia.json` | Priorización | Prioriza según el contexto con IA local |
| `05-notificaciones-email.json` | Notificación | Avisa a cada grupo de lo que le corresponde |
| `06-informes.json` | Informe | Genera el informe ejecutivo en PDF |
