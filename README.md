![Lab Topology](topology.svg)

# detection-lab

ELK Stack, Honeypots, Threat Simulation, Detection Rules. 
Built from scratch, documented in real time.

[![CI/CD](https://img.shields.io/github/actions/workflow/status/1xLoZec/detection-lab/deploy-detections.yml?label=CI%2FCD&style=flat-square)](https://github.com/1xLoZec/detection-lab/actions)
[![Techniques](https://img.shields.io/badge/Techniques%20Deployed-31-blue?style=flat-square)](https://github.com/1xLoZec/detection-lab/tree/main/detections/sigma)
[![ATT&CK Coverage](https://img.shields.io/badge/ATT%26CK%20Coverage-57%25-blue?style=flat-square)](https://attack.mitre.org/)
[![SIEM](https://img.shields.io/badge/SIEM-Elastic%208.19-005571?style=flat-square&logo=elastic)](https://www.elastic.co/)

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

## The Stack

| Component | Technology | Status |
|---|---|---|
| SIEM | Elastic Stack 8.19 | ✅ Live |
| Endpoint | Windows 11 Pro 25H2 · Sysmon | ✅ Live |
| Log Collection | Elastic Agent 8.19 + Fleet | ✅ Live |
| Hypervisor | Proxmox VE 9.1 | ✅ Live |
| Network | UniFi · VLANs (Default/Home/Mgmt/Lab/RedLab) | ✅ Live |
| VPN | WireGuard | ✅ Live |
| Threat Simulation | Atomic Red Team | ✅ Live |
| Detection Pipeline | tallkitchen_water (Claude + Gemini + Ollama) | ✅ Live |
| Detection Rules | Sigma → pySigma → Elastic DSL | ✅ Live |
| CI/CD | GitHub Actions (self-hosted, 3-AI gate) | ✅ Live |
| Alerting | HTML email · Rich terminal | ✅ Live |
| Honeypot Network | T-Pot | 🔜 Planned |
| Threat Intelligence | MISP | 🔜 Planned |

## tallkitchen_water

The center of the lab is a custom autonomous detection engineering pipeline I wrote called **tallkitchen_water**. It runs continuously, because detection engineering never stops.

One command runs the entire workflow:

```
tallkitchen_water
```
<img width="696" height="406" alt="image" src="https://github.com/user-attachments/assets/7685c5f7-b7a0-42fa-8b57-0dac7395a310" />

What happens next, without any human input:

1. Queries Elasticsearch for Sysmon events across the configured lookback window
2. Preprocesses and extracts behavioural indicators across process, network, file, registry, and DNS categories
3. Claude AI identifies the ATT&CK technique, severity, confidence, false positive risk, and writes a plain-English summary
4. Claude generates a production-ready Sigma rule with ECS field names
5. Rule is pushed to GitHub and triggers the CI/CD pipeline
6. Three AI models (Claude + Gemini + Ollama) independently validate the rule — requires 2/3 approval and average score ≥ 6
7. pySigma converts the Sigma YAML to Elasticsearch DSL and deploys via API to Kibana
8. A formatted HTML email lands in my inbox with technique stats, strongest signals, and the recommended next simulation


## Slowly building ATT&CK Coverage
## 🗺️ [View Live ATT&CK Coverage Heatmap →](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/1xLoZec/detection-lab/main/docs/coverage_layer.json)

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

- April 24 2026 — WireGuard VPN fully configured with split DNS. Kibana accessible only through encrypted VPN tunnel. Domain resolves correctly through VPN. Blocked on public internet. Infrastructure hardened and ready for Phase 4.

- April 24 2026 — Windows 11 ARM VM deployed in VMware Fusion. Sysmon installed with SwiftOnSecurity config using the ARM64 native binary (Sysmon64a). Elastic Agent enrolled and healthy. Windows VM shipping telemetry to ELK stack. Network isolated to private only. Snapshots taken at clean install and post-enrollment. Phase 4 complete. Atomic Red Team next.

- April 25 2026 — Hit a wall with VMware. Dug into it, found out Broadcom is shipping incomplete installers. Not a config issue, the files are literally missing. Fixed a DNS issue while I was in there and kept moving.

- April 28 2026 — Decided to do it right. Replaced the ISP router and mesh WiFi with enterprise grade gear. Bought a dedicated machine for Proxmox. Proper network segmentation is in place. Attack environment is locked down. Waiting on hardware to finish the build.

- May 7 2026 — Long sessions. Got Proxmox running on the dedicated lab machine and the Windows VM stood up inside it. Built a jump host for secure access to the lab environment. SSH from my PC to the jump host is working with full clipboard support. Still working through network segmentation. Getting closer.

- May 8 2026 — The pipeline is live. Windows VM telemetry flowing into Kibana. Sysmon operational, Windows event logs, PowerShell logs & security events all showing up from VM. Took some work to get here but it's running clean now.

- May 8 2026 — First Atomic Red Team simulation ran today. T1003 credential dumping. Completely isolated, nowhere to go. Telemetry showed up in Kibana immediately. Sysmon caught everything — process creation, registry modifications, logon events. The whole pipeline worked exactly as designed. Writing the first detection rule next.

<img width="558" height="269" alt="image" src="https://github.com/user-attachments/assets/2a654b1a-2d26-4604-ae85-a65a5f95fb2a" />
<img width="558" height="269" alt="image" src="https://github.com/user-attachments/assets/c20186bc-723b-47cb-aef3-f4cd0dee7068" />\

- May 10 2026 — Full Detection as Code pipeline is live. Push a Sigma rule to GitHub and it automatically gets validated by three AI models, converted to Elastic query language, and deployed to Kibana. No manual steps. First rule deployed successfully — PowerShell Spawning Reconnaissance Commands. Running every 5 minutes.

<img width="510" height="74" alt="image" src="https://github.com/user-attachments/assets/2951a146-6d4c-4349-99db-834555e4c09e" />
<img width="752" height="140" alt="image" src="https://github.com/user-attachments/assets/dc67a15d-2a6e-44c8-9300-38d44620ef04" />

- May 10 2026 — Built the full tallkitchen_water automation pipeline. One command triggers the entire detection engineering workflow: query Elasticsearch, extract ATT&CK technique with Claude AI, generate a Sigma rule, push to GitHub, validate with three AI models (Claude + Gemini + Ollama), convert to Elastic DSL with pySigma, deploy to Kibana, send a formatted HTML alert to my inbox. 31 rules deployed. 57% ATT&CK tactic coverage. Runs 24/7 with adaptive lookback, weekly digest, and a kill switch. The pipeline is fully operational.

<img width="862" height="754" alt="image" src="https://github.com/user-attachments/assets/4e82b198-a59d-4191-aa6a-6a5759ae9c79" />

- May 11 2026 — Two big things today.

  First, `demo.1xlozec.com` is live. Public read-only Kibana dashboard. SSL, rate limiting, dedicated viewer account. Anyone can see the lab without VPN.

  Second, the CI/CD pipeline is now self-healing. Every Sigma rule runs through four automated stages before it touches Kibana:

  1. YAML lint — catches malformed rules before wasting API calls
  2. Conversion — pySigma translates Sigma to Elastic DSL
  3. Backtest — query runs against live Elasticsearch to confirm it matches real data
  4. Three-AI gate — Claude, Gemini, and Ollama each score the rule independently
  
  If it fails, Claude rewrites it using each validator's feedback and tries again. Three attempts max. If it still fails, a circuit breaker emails me and stops. Nothing broken makes it to Kibana.

- May 11 2026 — 31 custom detection rules deployed to Kibana and firing live alerts. Full pipeline confirmed end to end: simulation → telemetry → AI analysis → rule generation → CI/CD validation → deployment → alert. Three high severity alerts generated from T1059.001, T1082, and T1016 simulations.

## Roadmap

- [ ] Public read-only Kibana at `training.1xlozec.com`
- [ ] MITRE ATT&CK coverage heatmap (auto-generated)
- [ ] Kibana email alerts when deployed rules fire
- [ ] Active Directory domain controller in Proxmox
- [ ] T-Pot honeypot on dedicated DigitalOcean droplet
- [ ] MISP threat intelligence integration
- [ ] Incident response playbooks per technique
- [ ] Documentation site at `docs.1xlozec.com`
- [ ] False positive feedback loop

## Lab Access

Live Kibana dashboard: `demo.1xlozec.com`

---

*Built by 1xLoZec. Work in progress. Check back often.*
