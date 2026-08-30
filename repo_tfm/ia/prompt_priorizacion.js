// ============================================================================
// Prompt de priorización con IA local (nodo "Code in JavaScript" del Workflow 04)
// ----------------------------------------------------------------------------
// Construye la instrucción que se envía al modelo (qwen2.5:7b vía Ollama).
// Combina: rol del modelo + contexto de la organización + reglas de scoring
// + formato de salida en JSON. Devuelve el cuerpo listo para la llamada HTTP.
// ============================================================================

const items = $input.all();

const perfilOrganizacion = `
Eres un analista de ciberseguridad experto en gestión de vulnerabilidades. Tu tarea es analizar un conjunto de vulnerabilidades CVE y generar una priorización adaptada al contexto de negocio de la organización.

CONTEXTO DE LA ORGANIZACIÓN — BancaSegura S.A.:
Banco online mediano, 800 empleados, operaciones en España y Portugal. Regulado por Banco de España, sujeto a DORA y NIS2.

GRUPOS Y TECNOLOGÍAS (cada grupo tiene una criticidad asignada):

GRUPO 1 - Infraestructura [Criticidad: ALTA]
- VMware vSphere 7.0, ESXi 7.0
- Windows Server 2019/2022, Red Hat Enterprise Linux 8
- Cisco IOS 15.x, Cisco ASA 9.x, F5 BIG-IP 16.x
- Palo Alto GlobalProtect 5.x, Veeam Backup 11

GRUPO 2 - Base de datos [Criticidad: CRÍTICA]
- Oracle Database 19c, PostgreSQL 14
- Microsoft SQL Server 2019, Redis 7.x

GRUPO 3 - Desarrollo y aplicaciones web [Criticidad: ALTA]
- Apache 2.4.51, Nginx 1.22
- PHP 8.1, Java 11 (Spring Boot 2.7), Node.js 18.x
- WordPress 6.x

GRUPO 4 - Endpoint y puesto de trabajo [Criticidad: MEDIA]
- Windows 10/11 Enterprise, Microsoft Office 365
- Google Chrome, Mozilla Firefox, CrowdStrike Falcon

GRUPO 5 - Identidad y acceso [Criticidad: CRÍTICA]
- Microsoft Active Directory, Azure AD / Entra ID
- CyberArk PAM 12.x, Okta SSO

GRUPO 6 - Servicios en la nube [Criticidad: ALTA]
- Azure IaaS/PaaS, AWS S3, Cloudflare CDN

INSTRUCCIONES DE SCORING:
1. Toma como base el CVSS Score (si existe) y el EPSS Score de cada vulnerabilidad.
2. Si no hay CVSS ni descripción disponible, basa tu análisis en: explotación activa confirmada, EPSS score, y fabricante/producto afectado.
3. Ajusta la prioridad según la criticidad del grupo al que afecta la tecnología (usa el campo fabricante/producto para inferir el grupo).
4. Si está marcada como explotada activamente, sube siempre la prioridad al máximo, independientemente de si hay CVSS o no.
5. Genera un score_final entre 0 y 10 que refleje la prioridad real ajustada al contexto.
`;

const cves = items.map(item => {
  const d = item.json;
  const tieneDescripcion = d.descripcion_en && d.descripcion_en.trim() !== '';

  return `CVE: ${d.cve_id}
${tieneDescripcion ? `Descripcion: ${d.descripcion_en}` : 'Descripcion: NO DISPONIBLE (CVE historico, ver fabricante/producto)'}
${d.cvss_score ? `CVSS Score: ${d.cvss_score} (${d.cvss_severidad})` : 'CVSS Score: NO DISPONIBLE'}
${d.vector_ataque ? `Vector de ataque: ${d.vector_ataque}` : ''}
EPSS Score: ${d.epss_score || 'N/A'}
Explotada activamente: ${d.explotada_activamente || 'NO'}
Fabricante/Producto: ${d.fabricante || 'N/A'} / ${d.producto || 'N/A'}`;
}).join('\n\n');

const prompt = `${perfilOrganizacion}
VULNERABILIDADES A ANALIZAR:
${cves}

Responde UNICAMENTE con un JSON array con esta estructura exacta, sin texto adicional:
[{"cve_id":"CVE-XXXX-XXXX","grupo":"Grupo afectado o DESCONOCIDO","score_final":8.5,"prioridad":"CRITICA/ALTA/MEDIA/BAJA","justificacion":"Una frase explicando la prioridad"}]`;

return [{ json: { model: "qwen2.5:7b", prompt: prompt, stream: false, format: "json" } }];
