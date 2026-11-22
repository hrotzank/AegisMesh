import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import urlparse
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

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


class ApkScanRequest(BaseModel):
    filename: str
    size_bytes: int
    sha256: str
    entries: list[str] = []
    selected_permissions: list[str] = []


class NetworkScanRequest(BaseModel):
    target: str
    ports: list[int] = Field(default_factory=lambda: [22, 80, 443, 3389, 8080])


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

SENSITIVE_PERMISSIONS = {
    "BIND_ACCESSIBILITY_SERVICE": {
        "severity": "Crítico",
        "score": 35,
        "desc": "Permite interceptar eventos del sistema, teclado y contenido en pantalla (abuso común en troyanos bancarios).",
    },
    "SYSTEM_ALERT_WINDOW": {
        "severity": "Crítico",
        "score": 28,
        "desc": "Capacidad de dibujar sobre otras apps para ataques de overlay y suplantación de credenciales.",
    },
    "REQUEST_INSTALL_PACKAGES": {
        "severity": "Alto",
        "score": 25,
        "desc": "Permite descargar e instalar paquetes APK secundarios eludiendo tiendas oficiales (dropper).",
    },
    "READ_SMS": {
        "severity": "Alto",
        "score": 24,
        "desc": "Acceso de lectura a mensajes SMS para interceptar códigos 2FA y transacciones bancarias.",
    },
    "SEND_SMS": {
        "severity": "Alto",
        "score": 24,
        "desc": "Envío de SMS silenciosos a números de tarificación adicional o exfiltración C2.",
    },
    "RECEIVE_SMS": {
        "severity": "Alto",
        "score": 22,
        "desc": "Interceptación pasiva de SMS entrantes en tiempo real.",
    },
    "RECORD_AUDIO": {
        "severity": "Alto",
        "score": 20,
        "desc": "Grabación de audio ambiental desde el micrófono sin confirmación visual activa.",
    },
    "READ_CONTACTS": {
        "severity": "Medio",
        "score": 14,
        "desc": "Lectura de la agenda de contactos con fines de propagación o perfilamiento.",
    },
    "ACCESS_FINE_LOCATION": {
        "severity": "Medio",
        "score": 14,
        "desc": "Geolocalización satelital precisa del dispositivo.",
    },
    "INTERNET": {
        "severity": "Bajo",
        "score": 5,
        "desc": "Conectividad de red estándar requerida para comunicaciones salientes.",
    },
}

PORT_RISK_MAP = {
    21: {
        "service": "FTP",
        "severity": "Alto",
        "score": 25,
        "desc": "Protocolo de transferencia de archivos sin cifrado nativo (credenciales en texto plano).",
    },
    22: {
        "service": "SSH",
        "severity": "Medio",
        "score": 12,
        "desc": "Terminal remota segura. Expuesto a ataques de fuerza bruta si no cuenta con fail2ban/claves.",
    },
    23: {
        "service": "Telnet",
        "severity": "Crítico",
        "score": 35,
        "desc": "Protocolo obsoleto sin cifrado; interceptación directa de sesiones y contraseñas.",
    },
    25: {
        "service": "SMTP",
        "severity": "Medio",
        "score": 15,
        "desc": "Servicio de correo saliente. Riesgo de relay abierto si no está autenticado.",
    },
    53: {
        "service": "DNS",
        "severity": "Medio",
        "score": 14,
        "desc": "Servicio de resolución de nombres. Vector potencial de amplificación DDoS o envenenamiento de caché.",
    },
    80: {
        "service": "HTTP",
        "severity": "Medio",
        "score": 15,
        "desc": "Servicio web sin cifrado TLS/SSL. Tráfico vulnerable a inspección y modificación en tránsito.",
    },
    110: {
        "service": "POP3",
        "severity": "Medio",
        "score": 16,
        "desc": "Acceso a buzón de correo sin cifrado por defecto.",
    },
    143: {
        "service": "IMAP",
        "severity": "Medio",
        "score": 16,
        "desc": "Sincronización de correo electrónico sin TLS por defecto.",
    },
    443: {
        "service": "HTTPS",
        "severity": "Bajo",
        "score": 5,
        "desc": "Canal web cifrado estándar. Buenas prácticas de confidencialidad e integridad.",
    },
    445: {
        "service": "SMB",
        "severity": "Crítico",
        "score": 38,
        "desc": "Compartición de archivos Windows/Samba. Vector crítico de propagación lateral y exploits (EternalBlue).",
    },
    1433: {
        "service": "MSSQL",
        "severity": "Alto",
        "score": 28,
        "desc": "Base de datos Microsoft SQL Server expuesta a la red.",
    },
    3306: {
        "service": "MySQL/MariaDB",
        "severity": "Alto",
        "score": 28,
        "desc": "Base de datos relacional expuesta sin aislamiento de capa de aplicación.",
    },
    3389: {
        "service": "RDP",
        "severity": "Alto",
        "score": 30,
        "desc": "Escritorio remoto de Windows. Objetivo primario de ataques de fuerza bruta y ransomware.",
    },
    5432: {
        "service": "PostgreSQL",
        "severity": "Alto",
        "score": 28,
        "desc": "Base de datos PostgreSQL expuesta directamente.",
    },
    6379: {
        "service": "Redis",
        "severity": "Crítico",
        "score": 36,
        "desc": "Almacén en memoria habitualmente configurado sin contraseña o con permisos root.",
    },
    8080: {
        "service": "HTTP-Proxy/Alt",
        "severity": "Medio",
        "score": 16,
        "desc": "Servicio web alternativo, interfaces de administración o proxys sin TLS.",
    },
    8443: {
        "service": "HTTPS-Alt",
        "severity": "Bajo",
        "score": 6,
        "desc": "Servicio web seguro alternativo.",
    },
    27017: {
        "service": "MongoDB",
        "severity": "Crítico",
        "score": 36,
        "desc": "Base de datos NoSQL con riesgo histórico de exposición no autenticada.",
    },
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


@app.post("/api/scan/apk")
def scan_apk(payload: ApkScanRequest):
    clean_name = payload.filename.strip() or "paquete.apk"
    lower_name = clean_name.lower()
    size_bytes = max(0, payload.size_bytes)
    sha256 = payload.sha256.strip().lower() or "no-disponible"
    entries = payload.entries or []
    selected_perms = [p.strip().upper() for p in payload.selected_permissions if p.strip()]

    score = 10
    findings: list[dict[str, str]] = []

    # 1. Extensión del archivo
    if not lower_name.endswith(".apk"):
        score += 25
        findings.append({
            "severity": "Alto",
            "title": "Extensión no estándar para paquete Android",
            "detail": f"El archivo '{clean_name}' no finaliza con la extensión '.apk'.",
        })

    # 2. Análisis estructural de entradas internas
    lower_entries = [e.lower() for e in entries]
    total_entries = len(entries)
    has_manifest = any(e.endswith("androidmanifest.xml") for e in lower_entries)
    dex_files = [e for e in lower_entries if e.endswith(".dex")]
    dex_count = len(dex_files)
    native_libs = [e for e in lower_entries if e.startswith("lib/") and e.endswith(".so")]
    native_lib_count = len(native_libs)

    if entries:
        if not has_manifest:
            score += 30
            findings.append({
                "severity": "Alto",
                "title": "Ausencia de AndroidManifest.xml",
                "detail": "El archivo ZIP/APK analizado no contiene el manifiesto principal de Android.",
            })

        if dex_count == 0:
            score += 25
            findings.append({
                "severity": "Alto",
                "title": "Sin bytecode Dalvik ejecutable (.dex)",
                "detail": "No se encontraron archivos classes.dex en la raíz del paquete.",
            })
        elif dex_count > 4:
            score += 15
            findings.append({
                "severity": "Medio",
                "title": f"Múltiples archivos DEX detectados ({dex_count})",
                "detail": "Estructura multi-DEX amplia, habitual en apps complejas o con módulos ofuscados.",
            })

        if native_lib_count > 0:
            findings.append({
                "severity": "Medio",
                "title": f"Binarios nativos compilados ({native_lib_count} archivos .so)",
                "detail": "La aplicación incluye código binario nativo (C/C++), potencialmente capaz de evadir inspecciones basadas solo en Dalvik.",
            })
            score += 10

    # 3. Tamaño anómalo
    if size_bytes == 0:
        score += 25
        findings.append({
            "severity": "Medio",
            "title": "Paquete APK vacío (0 bytes)",
            "detail": "El archivo carece de contenido para análisis de firma o estructura.",
        })
    elif size_bytes > 120 * 1024 * 1024:
        score += 10
        findings.append({
            "severity": "Medio",
            "title": "Tamaño de paquete considerable (> 120 MB)",
            "detail": "El APK posee un volumen elevado, habitual en empaquetadores con assets pesados o código embebido.",
        })

    # 4. Análisis de permisos sensibles
    perm_score_accum = 0
    for perm in selected_perms:
        clean_perm = perm.replace("ANDROID.PERMISSION.", "")
        meta = SENSITIVE_PERMISSIONS.get(clean_perm)
        if meta:
            perm_score_accum += meta["score"]
            findings.append({
                "severity": meta["severity"],
                "title": f"Permiso de riesgo: {clean_perm}",
                "detail": meta["desc"],
            })

    # Combinación de alto riesgo: Accesibilidad + Overlay o SMS
    perm_names = [p.replace("ANDROID.PERMISSION.", "") for p in selected_perms]
    if "BIND_ACCESSIBILITY_SERVICE" in perm_names:
        has_overlay = "SYSTEM_ALERT_WINDOW" in perm_names
        has_sms = any(s in perm_names for s in ("READ_SMS", "RECEIVE_SMS", "SEND_SMS"))
        if has_overlay or has_sms:
            perm_score_accum += 20
            findings.append({
                "severity": "Crítico",
                "title": "Vector de ataque combinado (Accessibility + Overlay/SMS)",
                "detail": "Patrón de comportamiento característico de troyanos bancarios y keyloggers en Android.",
            })

    score += min(perm_score_accum, 55)

    # 5. Verificación de hash SHA-256
    if len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256):
        score += 8
        findings.append({
            "severity": "Medio",
            "title": "Hash SHA-256 no estándar",
            "detail": "No se validó un digest SHA-256 estándar de 64 caracteres.",
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
            "title": "Sin indicadores de riesgo elevados",
            "detail": "La configuración de permisos y estructura básica del APK no presentan anomalías severas.",
        })

    return {
        "filename": clean_name,
        "sizeBytes": size_bytes,
        "sha256": sha256,
        "totalEntries": total_entries,
        "dexCount": dex_count,
        "nativeLibCount": native_lib_count,
        "hasManifest": has_manifest,
        "permissionsAnalyzed": selected_perms,
        "riskScore": score,
        "riskLevel": risk_level,
        "scannedAt": datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
        "findings": findings,
    }


@app.post("/api/scan/network")
def scan_network(payload: NetworkScanRequest):
    raw_target = payload.target.strip()
    ports = sorted(list(set(payload.ports if payload.ports else [22, 80, 443, 3389, 8080])))
    valid_ports = [p for p in ports if 1 <= p <= 65535]

    score = 10
    findings: list[dict[str, str]] = []

    # Quitar posibles prefijos de protocolo http:// o https://
    cleaned_target = re.sub(r"^https?://", "", raw_target)
    if "/" in cleaned_target and not re.search(r"/\d{1,2}$", cleaned_target):
        cleaned_target = cleaned_target.split("/")[0]

    # Quitar puerto si viene en el host ej 192.168.1.1:80
    if ":" in cleaned_target and not (cleaned_target.startswith("[") or cleaned_target.count(":") > 1):
        cleaned_target = cleaned_target.split(":")[0]

    target_type = "Dominio / Hostname"
    network_scope = "Internet Pública"
    resolved_host = cleaned_target

    # 1. Validación de IPv4 / CIDR / Loopback / LAN
    is_cidr = "/" in cleaned_target
    try:
        if is_cidr:
            net = ipaddress.ip_network(cleaned_target, strict=False)
            target_type = f"Subred CIDR IPv4 (/{net.prefixlen})"
            resolved_host = str(net.network_address)
            if net.is_loopback:
                network_scope = "Loopback / Localhost"
            elif net.is_private:
                network_scope = "Red Privada / LAN"
            elif net.is_link_local:
                network_scope = "Link-Local"
            else:
                network_scope = "Internet Pública"
        else:
            ip_obj = ipaddress.ip_address(cleaned_target)
            target_type = "Dirección IPv4" if ip_obj.version == 4 else "Dirección IPv6"
            resolved_host = str(ip_obj)
            if ip_obj.is_loopback or cleaned_target in ("127.0.0.1", "localhost", "::1"):
                network_scope = "Loopback / Localhost"
            elif ip_obj.is_private:
                network_scope = "Red Privada / LAN"
            elif ip_obj.is_link_local:
                network_scope = "Link-Local"
            else:
                network_scope = "Internet Pública"
    except ValueError:
        target_type = "Dominio / FQDN"
        if cleaned_target.lower() in ("localhost", "localhost.localdomain"):
            network_scope = "Loopback / Localhost"
        elif cleaned_target.endswith((".local", ".internal", ".lan", ".home")):
            network_scope = "Red Privada / LAN"
        else:
            network_scope = "Internet Pública"

    # Hallazgo de ámbito de red
    if network_scope == "Red Privada / LAN":
        findings.append({
            "severity": "Bajo",
            "title": f"Objetivo en ámbito privado ({network_scope})",
            "detail": f"El objetivo '{cleaned_target}' pertenece a un segmento no enrutable en Internet (RFC1918). Protegido tras NAT o cortafuegos perimetral.",
        })
    elif network_scope == "Loopback / Localhost":
        findings.append({
            "severity": "Bajo",
            "title": "Interfaz local de bucle (Loopback)",
            "detail": "El escaneo apunta a la propia máquina local. Los puertos analizados no están expuestos externamente.",
        })
    else:
        score += 15
        findings.append({
            "severity": "Medio",
            "title": "Exposición en Internet Pública",
            "detail": f"El objetivo '{cleaned_target}' se encuentra en direccionamiento público global. La superficie de ataque es accesible para escaneos indiscriminados.",
        })

    # Hallazgo si es subred CIDR amplia
    if is_cidr and target_type.startswith("Subred"):
        prefix = int(cleaned_target.split("/")[1])
        if prefix < 24:
            score += 12
            findings.append({
                "severity": "Medio",
                "title": f"Máscara de subred amplia (/{prefix})",
                "detail": "El rango abarca un volumen elevado de direcciones IP consecutivas, incrementando la superficie de barrido.",
            })

    # 2. Análisis de superficie por puertos
    ports_detail: list[dict[str, object]] = []
    port_risk_accum = 0

    for port in valid_ports:
        meta = PORT_RISK_MAP.get(port, {
            "service": "Servicio Desconocido / Personalizado",
            "severity": "Medio" if port < 1024 else "Bajo",
            "score": 10 if port < 1024 else 5,
            "desc": f"Puerto TCP {port} registrado en la verificación de superficie.",
        })

        port_score = meta["score"]
        # En Internet pública, servicios sensibles o sin cifrar son más críticos
        if network_scope == "Internet Pública" and port in (21, 23, 445, 1433, 3306, 3389, 5432, 6379, 27017):
            port_score = int(port_score * 1.25)
            findings.append({
                "severity": "Crítico",
                "title": f"Servicio crítico {meta['service']} (:{port}) expuesto en Internet Pública",
                "detail": f"El servicio {meta['service']} (puerto {port}) no debe exponerse a Internet sin VPN ni túnel autenticado.",
            })
        else:
            findings.append({
                "severity": meta["severity"],
                "title": f"Puerto {port}/TCP ({meta['service']}) evaluado",
                "detail": meta["desc"],
            })

        port_risk_accum += port_score
        ports_detail.append({
            "port": port,
            "service": meta["service"],
            "severity": meta["severity"],
        })

    # Detección de protocolos legacy / alta vulnerabilidad
    if 23 in valid_ports or 445 in valid_ports:
        port_risk_accum += 15
        findings.append({
            "severity": "Crítico",
            "title": "Detección de protocolos legacy / alta vulnerabilidad (Telnet/SMB)",
            "detail": "La presencia de puertos 23 o 445 representa un riesgo mayor de compromiso o propagación de malware.",
        })

    if len(valid_ports) >= 8:
        score += 10
        findings.append({
            "severity": "Medio",
            "title": "Superficie de puertos amplia",
            "detail": f"Se especificaron {len(valid_ports)} puertos objetivo simultáneos.",
        })

    score += min(port_risk_accum, 55)
    score = min(score, 99)

    if score >= 75:
        risk_level = "Crítico"
    elif score >= 50:
        risk_level = "Alto"
    elif score >= 25:
        risk_level = "Medio"
    else:
        risk_level = "Bajo"

    return {
        "target": raw_target,
        "resolvedHost": resolved_host,
        "targetType": target_type,
        "networkScope": network_scope,
        "openOrCheckedPorts": ports_detail,
        "riskScore": score,
        "riskLevel": risk_level,
        "scannedAt": datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
        "findings": findings,
    }
