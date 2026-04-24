![Lab Topology](topology.svg)

# detection-lab

ELK Stack, Honeypots, Threat Simulation, Detection Rules. 
Built from scratch, documented in real time.

---

Professionally I make artisan sandwiches. On my own time 
I build detection engineering labs from scratch because 
apparently that is what I do for fun.

This lab is where I go deeper on the infrastructure side 
of detection engineering. Building everything from the 
ground up so I actually understand what is happening under 
the hood, not just on the screen.

Everything here is documented as I build it. That includes 
the parts that break, the walls I hit, and how I got through 
them. This is not a finished product. It is a live build.

---

## The Stack

| Component | Technology | Status |
|---|---|---|
| SIEM | Elastic Stack 8.19 | Live |
| Log Collection | Elastic Agent | Up Next |
| Honeypot Network | T-Pot | Planned |
| Threat Simulation | Atomic Red Team | Planned |
| Detection Rules | Sigma | Planned |
| CI/CD Pipeline | GitHub Actions | Planned |
| Threat Intelligence | MISP | Planned |

---

## Progress

## Progress

- **April 24 2026** — Repository created. ELK stack deployed and secured. Firewall configured. SSL certificate installed. Kibana live.

- **April 24 2026** — Elasticsearch verified. Cluster and node confirmed healthy.

- **April 24 2026** — First logs flowing into Kibana. Elastic Agent enrolled and healthy in Fleet.

- **April 24 2026**
  - Full ELK stack deployed and secured on DigitalOcean
  - Ubuntu server patched and firewall configured
  - Kibana live with SSL via NGINX
  - Fleet Server running and healthy
  - Elastic Agent enrolled and shipping live telemetry
  - 1,616 prebuilt detection rules installed with zero gaps
  - GitHub repository live and documented

- **April 24 2026**
  - VPN tunnel configured — Kibana no longer publicly accessible
  - Brute force protection active — first ban triggered within minutes
  - Real attacker traffic observed and logged
  - Infrastructure hardened — ready for Phase 4
      
## Lab Access

Live Kibana dashboard: https://1xlozec.com

---

*Built by 1xLoZec. Work in progress. Check back often.*
