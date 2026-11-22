import re
from datetime import datetime, timezone
from urllib.parse import urlparse
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="AegisMesh API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class LinkScanRequest(BaseModel):
    url: str


class FileScanRequest(BaseModel):
    filename: str
    size_bytes: int
    sha256: str
    mime_type: str = "application/octet-stream"


SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "rb.gy"
}

SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".click", ".zip", ".work"}

PHISHING_TOKENS = [
    "login", "signin", "verify", "update", "secure", "account",
    "banking", "wallet", "confirm", "suspend", "free", "bonus", "password"
]

HIGH_RISK_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".apk", ".jar", ".msi", ".reg"
}

MEDIUM_RISK_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img", ".docm", ".xlsm", ".pptm"
}


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "aegismesh-backend"}


@app.post("/api/scan/link")
def scan_link(payload: LinkScanRequest):
    raw_url = payload.url.strip()
    has_scheme = raw_url.startswith(("http://", "https://"))
    normalized = raw_url if has_scheme else f"http://{raw_url}"
    parsed = urlparse(normalized)
    host = parsed.hostname.lower() if parsed.hostname else ""
    port = parsed.port

    score = 10
    findings: list[dict[str, str]] = []

    if not host:
        return {
            "url": raw_url,
            "domain": "desconocido",
            "protocol": "inválido",
            "riskScore": 90,
            "riskLevel": "Crítico",
            "scannedAt": datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
            "findings": [
                {
                    "severity": "Crítico",
                    "title": "URL malformada",
                    "detail": "No se pudo extraer un dominio válido de la cadena ingresada.",
                }
            ],
        }

    # 1. Protocolo inseguro
    if parsed.scheme != "https":
        score += 20
        findings.append({
            "severity": "Medio",
            "title": "Tráfico sin cifrado TLS (HTTP)",
            "detail": "La URL no utiliza HTTPS; los datos enviados pueden ser interceptados.",
        })

    # 2. Dirección IP directa en lugar de dominio
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        score += 35
        findings.append({
            "severity": "Alto",
            "title": "Host basado en dirección IP literal",
            "detail": f"El enlace apunta directamente a la IP {host}, patrón habitual en infraestructura C2 o phishing.",
        })

    # 3. Punycode / homógrafos IDN
    if "xn--" in host:
        score += 35
        findings.append({
            "severity": "Alto",
            "title": "Posible ataque homógrafo (Punycode)",
            "detail": "El dominio contiene codificación IDN (xn--), usada para suplantar marcas legítimas.",
        })

    # 4. Acortadores de URL
    if host in SHORTENERS:
        score += 25
        findings.append({
            "severity": "Medio",
            "title": "Acortador de enlaces detectado",
            "detail": f"El dominio {host} oculta el destino final de redirección.",
        })

    # 5. TLD frecuentemente abusado
    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 20
        findings.append({
            "severity": "Medio",
            "title": "Extensión de dominio (TLD) de alto riesgo",
            "detail": "El TLD utilizado presenta alta incidencia en campañas automatizadas de spam y phishing.",
        })

    # 6. Subdominios excesivos o @ en la URL
    if "@" in normalized:
        score += 35
        findings.append({
            "severity": "Crítico",
            "title": "Ofuscación de credenciales/destino con '@'",
            "detail": "El símbolo '@' puede engañar al usuario sobre el host real al que se conecta el navegador.",
        })

    if host.count(".") >= 3:
        score += 18
        findings.append({
            "severity": "Medio",
            "title": "Múltiples niveles de subdominio",
            "detail": f"Se detectaron {host.count('.')} niveles en '{host}', técnica común para simular sitios oficiales.",
        })

    # 7. Palabras clave de ingeniería social
    matched_tokens = [tok for tok in PHISHING_TOKENS if tok in normalized.lower()]
    if matched_tokens:
        score += min(30, 10 * len(matched_tokens))
        findings.append({
            "severity": "Alto",
            "title": "Patrones léxicos de ingeniería social",
            "detail": f"Palabras sospechosas detectadas: {', '.join(matched_tokens)}.",
        })

    # 8. Puerto no estándar
    if port and port not in (80, 443):
        score += 15
        findings.append({
            "severity": "Medio",
            "title": f"Puerto no estándar ({port})",
            "detail": "El servicio responde en un puerto inusual para navegación web convencional.",
        })

    score = min(score, 99)
    if score >= 75:
        risk_level = "Crítico"
    elif score >= 50:
        risk_level = "Alto"
    elif score >= 25:
        risk_level = "Medio"
    else:
        risk_level = "Bajo"

    if not findings:
        findings.append({
            "severity": "Bajo",
            "title": "Sin indicadores heurísticos anómalos",
            "detail": "El dominio usa HTTPS y no presenta patrones comunes de ofuscación o phishing.",
        })

    return {
        "url": raw_url,
        "domain": host,
        "protocol": parsed.scheme.upper(),
        "riskScore": score,
        "riskLevel": risk_level,
        "scannedAt": datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
        "findings": findings,
    }


@app.post("/api/scan/file")
def scan_file(payload: FileScanRequest):
    clean_name = payload.filename.strip() or "archivo_sin_nombre"
    lower_name = clean_name.lower()
    size_bytes = max(0, payload.size_bytes)
    sha256 = payload.sha256.strip().lower() or "no-disponible"

    score = 10
    findings: list[dict[str, str]] = []

    parts = [p for p in lower_name.split(".") if p]
    if len(parts) >= 3:
        last_ext = f".{parts[-1]}"
        prev_ext = f".{parts[-2]}"
        if last_ext in HIGH_RISK_EXTENSIONS and prev_ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"}:
            score += 38
            findings.append({
                "severity": "Crítico",
                "title": "Técnica de doble extensión detectada",
                "detail": f"El archivo '{clean_name}' disfraza un ejecutable ({last_ext}) tras una extensión común ({prev_ext}).",
            })

    ext = f".{parts[-1]}" if len(parts) >= 2 else ""
    if ext in HIGH_RISK_EXTENSIONS:
        score += 32
        findings.append({
            "severity": "Alto",
            "title": f"Tipo de archivo ejecutable o script ({ext})",
            "detail": "Los binarios, scripts o instaladores requieren inspección adicional antes de ejecutarse.",
        })
    elif ext in MEDIUM_RISK_EXTENSIONS:
        score += 18
        findings.append({
            "severity": "Medio",
            "title": f"Contenedor comprimido o imagen ({ext})",
            "detail": "Puede ocultar cargas útiles o archivos maliciosos en su interior.",
        })

    if size_bytes == 0:
        score += 15
        findings.append({
            "severity": "Medio",
            "title": "Archivo vacío (0 bytes)",
            "detail": "Un archivo sin contenido puede ser un marcador o un artefacto incompleto.",
        })
    elif size_bytes > 100 * 1024 * 1024:
        score += 12
        findings.append({
            "severity": "Medio",
            "title": "Tamaño de archivo elevado (> 100 MB)",
            "detail": "Los archivos muy pesados suelen requerir análisis por lotes o en sandbox.",
        })

    if len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256):
        score += 10
        findings.append({
            "severity": "Medio",
            "title": "Hash SHA-256 no estándar o incompleto",
            "detail": "No se pudo validar un digest hexadecimal de 64 caracteres.",
        })

    score = min(score, 99)
    if score >= 75:
        risk_level = "Crítico"
    elif score >= 50:
        risk_level = "Alto"
    elif score >= 25:
        risk_level = "Medio"
    else:
        risk_level = "Bajo"

    if not findings:
        findings.append({
            "severity": "Bajo",
            "title": "Sin indicadores sospechosos en metadatos",
            "detail": "La extensión y estructura del archivo no muestran patrones heurísticos de riesgo.",
        })

    return {
        "filename": clean_name,
        "extension": ext or "sin extensión",
        "sizeBytes": size_bytes,
        "sha256": sha256,
        "mimeType": payload.mime_type or "application/octet-stream",
        "riskScore": score,
        "riskLevel": risk_level,
        "scannedAt": datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
        "findings": findings,
    }
