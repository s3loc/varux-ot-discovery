

# **VARUX OT Discovery Framework**

**Author:** s3loc (Selman Vural)
**License:** GPL-3.0
**Organization:** VARUX Dynamic Research Labs
**Repository:** `varux-ot-discovery`

---

## 🧠 Overview

**VARUX OT Discovery Framework**, endüstriyel (OT) ağlarda **pasif, hız sınırlı ve güvenli keşif** gerçekleştiren modüler bir siber güvenlik altyapısıdır.
Sistem; topoloji haritalama, protokol analizleri, SQL güvenlik testleri ve merkezi kontrol bileşenlerini tek çatı altında toplar.

---

## ⚙️ Core Frameworks

### **VARUX OT Discovery Core**

Endüstriyel ağ topolojisini pasif ve salt okunur modda keşfeder.

* SNMPv3 authPriv, Modbus, LLDP, ICMP desteği
* JSON + Graphviz/SVG çıktısı
* AES-GCM şifreleme, HMAC doğrulama

```bash
python3 "VARUX OT Discovery Framework.py" --config config.yaml --range 192.168.10.0/24
```

---

### **NOXIM — Pentest Orchestrator**

Tüm modülleri tek merkezden yöneten otomasyon çekirdeği.

* ML tabanlı rate limiter
* SLA takibi, oturum yönetimi, health monitor

```bash
python3 NOXIM.py --scope scope.json --sla sla.yaml
```

---

## 🧩 Modules  (Located in `/moduler/`)

### `industrial_recon.py`

Pasif + sınırlı aktif ICS/OT keşif modülü.

* Modbus, S7comm, DNP3, Profinet, BACnet, MQTT tespiti
* MAC-OUI vendor tanımlama, SNMP enrichment

```bash
python3 moduler/industrial_recon.py --interface eth0 --duration 300 --deep-analysis
```

---

### `sqlmap_wrapper.py`

VARUX ve sqlmap arasında köprü görevi gören entegrasyon katmanı.

* Otomatik sqlmap algılama
* Proxy / TOR / tamper desteği
* Çıktı izolasyonu

```bash
python3 moduler/sqlmap_wrapper.py -u "https://target.tld/page?id=1"
```

---

### `varuxctl.py`

Framework’ün merkezi komut satırı kontrolcüsü.

* Modül başlatma, yapılandırma, log yönetimi
* Rapor oluşturma ve izleme

```bash
python3 moduler/varuxctl.py --module industrial_recon --run --config config.yaml
```

---

## 🧠 Tech Stack

* **Python 3.11+**
* asyncio · aiohttp · scapy · pysnmp · cryptography · yaml · graphviz

---

## 📂 Project Structure

```
varux-ot-discovery/
├── VARUX OT Discovery Framework.py
├── NOXIM.py
├── moduler/
│   ├── industrial_recon.py
│   ├── sqlmap_wrapper.py
│   └── varuxctl.py
├── LICENSE
├── .gitignore
└── README.md
```

---

## ⚠️ Legal Notice

Bu yazılım yalnızca **yetkili güvenlik testleri ve araştırma ortamları** için kullanılabilir.
İzinsiz ağlarda çalıştırılması **yasal ihlal** oluşturur.
Yazar (s3loc) kötüye kullanımdan doğacak sonuçlardan sorumlu değildir.

---


⠀⠀⠀⠀⠀⠀⠀⣀⣤⣶⡶⠿⠿⠿⠿⠿⠿⣶⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣴⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠿⣦⣄⠀⠀⠀⠀⠀
⠀⠀⢀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⣤⣀⣀⠀⠀⠈⠻⣦⡀⠀⠀⠀
⠀⢀⣾⠋⢀⣴⡄⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⠻⠿⠂⠀⠀⠙⣷⡄⠀⠀
⠀⣾⠇⣠⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠆⠀⠀⠀⠀⠀⠸⣷⡀⠀
⢸⡟⠘⠛⠁⣰⣿⣿⡆⠀⠀⠀⠀⠀⠀⠈⠉⠉⠀⠀⠀⠀⠀⠀⠀⢻⣧⠀
⢸⡇⠀⠀⠀⠸⠿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⡀
⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇
⢸⣧⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⣤⠀⠀⣾⡆⠀⠀⠀⠀⠀⠀⢠⣿⠃
⠀⣿⡄⠀⠀⠀⠀⠀⠀⢾⡇⠀⠀⢀⣿⣦⣤⡿⠁⠀⠀⠀⠀⠀⠀⣼⡟⠀
⠀⠸⣧⠀⠀⠀⠀⠀⠀⠈⠛⠛⠛⠛⠁⠈⠉⠀⠀⠀⠀⠀⠀⢀⣼⡟⠁⠀
⠀⠀⠙⣷⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⢀⣴⣿⠋⠀⠀⠀
⠀⠀⠀⠈⠙⢿⣦⣄⣀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣾⣿⠿⠋⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠉⠛⠛⠻⠿⠿⠿⠿⠛⠛⠛⠛⠉⠁⠀⠀⠀



