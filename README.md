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

- April 24 2026 — Repository created. ELK stack deployed, 
secured, and accessible at https://1xlozec.com. Firewall 
configured. SSL certificate installed. Kibana is live.
- April 24 2026 — Elasticsearch verified responding correctly. 
  Cluster name 1xlozec-lab confirmed. Node elk-node-01 confirmed.
<img width="1076" height="873" alt="elastic" src="https://github.com/user-attachments/assets/65e011c9-47b2-4088-a3f0-cd9c70e389b1" />
- April 24 2026 — First logs flowing into Kibana. 704 documents ingested from server telemetry. Elastic Agent enrolled and healthy in Fleet.
<img width="1076" height="873" alt="elastid" src="https://github.com/user-attachments/assets/4f297393-48c5-4416-97bf-e804358a2aaa" />
- April 24 2026
    - Full ELK stack deployed and secured on DigitalOcean
    - Ubuntu server patched and firewall configured
    - Elasticsearch 8.19 running and verified
    - Kibana live at https://1xlozec.com with SSL via NGINX
    - Fleet Server running and healthy
    - Elastic Agent enrolled and shipping live telemetry
    - 1,616 Elastic prebuilt detection rules installed with zero gaps
    - GitHub repository live and documented

## Lab Access

Live Kibana dashboard: https://1xlozec.com

---

*Built by 1xLoZec. Work in progress. Check back often.*
