![Lab Topology](topology.svg)
*Network topology: VLAN-segmented home lab feeding a cloud SIEM through a WireGuard tunnel.*

# 1xLoZec Detection Lab

**Tall Kitchen detection lab. Built from scratch, documented in real time.**

[![CI/CD](https://img.shields.io/github/actions/workflow/status/1xLoZec/detection-lab/deploy-detections.yml?label=CI%2FCD&style=flat-square)](https://github.com/1xLoZec/detection-lab/actions)
[![Detection as Code](https://img.shields.io/badge/Detection-as--Code-success?style=flat-square)](https://github.com/1xLoZec/detection-lab/tree/main/detections/sigma)
[![Self-Healing CI/CD](https://img.shields.io/badge/CI%2FCD-Self--Healing-orange?style=flat-square)](#tallkitchen_water)
[![T-Pot Integrated](https://img.shields.io/badge/T--Pot-Integrated-red?style=flat-square)](#t-pot-integration)
[![SIEM](https://img.shields.io/badge/SIEM-Elastic%208.19-005571?style=flat-square&logo=elastic)](https://www.elastic.co/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)

**[🖥️ Live Dashboard](https://demo.1xlozec.com) · [🗺️ ATT&CK Coverage Heatmap](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/1xLoZec/detection-lab/main/docs/coverage_layer.json)**

---

**Professionally I make artisan sandwiches.** On my own time I build detection engineering labs from scratch because apparently that is what I do for fun. 
This lab is where I go deeper on the infrastructure side of detection engineering. I'm building everything from the ground up so I actually understand what's happening under the hood, not just on the screen. Every piece is documented as I build it including the parts that break, the walls I hit, and how I got through them. This is not a finished product. It is a live build.

**How this is built.** I leaned on and learned from a stack of AI platforms for this one. Claude was my main collaborator for code and architecture. Cursor was my editor. Gemini and Ollama sit inside Water as two of the three validators that grade every rule before it goes live. The design, the decisions, and the way everything fits together is mine. The typing speed is theirs.
*(And yes — I'm actually a cyber security engineer. The sandwich gig is a long-running joke my friends refuse to let die.)*

## Lab Access

**Live dashboard:** [demo.1xlozec.com](https://demo.1xlozec.com)
**Username:** `demo`
**Password:** `DemoUser2026!`

Read-only viewer account. Dark mode is on by default. Time range is locked to the last 3 months. Anyone can view the lab without VPN.

## The Stack

**Live components:**

| Component | Technology | Status |
|---|---|---|
| SIEM | Elastic Stack 8.19 | ✅ Live |
| Endpoint | Windows 11 Pro 25H2 · Sysmon (SwiftOnSecurity config) | ✅ Live |
| Log Collection | Elastic Agent 8.19 + Fleet | ✅ Live |
| Hypervisor | Proxmox VE 9.1 | ✅ Live |
| Network | UniFi · VLANs (Default/Home/Mgmt/Lab/RedLab) | ✅ Live |
| VPN | WireGuard with split DNS | ✅ Live |
| Threat Simulation | Atomic Red Team (on-demand) | ✅ Live |
| Honeypot | T-Pot Hive · 30+ honeypots · WireGuard tunnel to main ELK | ✅ Live |
| Detection Pipeline | tallkitchen_water (Claude + Gemini + Ollama) | ✅ Live |
| Detection Rules | Sigma → pySigma → Elastic DSL | ✅ Live |
| CI/CD | GitHub Actions on self-hosted Mac Mini runner · 3-AI validation gate · self-healing | ✅ Live |
| Real-time Alerting | ElastAlert2 (HTML email on rule firings) | ✅ Live |
| Public Dashboard | Kibana behind NGINX reverse proxy · SSL · rate-limited | ✅ Live |
| Threat Intelligence | MISP | 🔜 Planned |

**Planned:** see [Roadmap](#roadmap).

## tallkitchen_water

The center of the lab is a custom autonomous detection engineering pipeline I wrote called **tallkitchen_water**. It runs continuously, because detection engineering never stops.

One command runs the entire workflow:

```
tallkitchen_water
```
<img width="790" height="530" alt="image" src="https://github.com/user-attachments/assets/12746ddf-05a9-4f47-aeef-de38329edc75" />

What happens next, without any human input:

1. Queries Elasticsearch for Sysmon events across the configured lookback window
2. Preprocesses and extracts behavioural indicators across process, network, file, registry, and DNS categories
3. Claude identifies the ATT&CK technique, severity, confidence, false positive risk, and writes a plain-English summary
4. Claude generates a production-ready Sigma rule with ECS field names
5. Rule is pushed to GitHub, triggering the self-hosted CI/CD runner
6. **YAML lint** catches malformed rules before any API calls
7. **Backtest** runs the converted query against live Elasticsearch to confirm it matches real data
8. **Three-AI validation gate** — Claude, Gemini, and Ollama each independently score the rule. Pass requires 2/3 approval and average score ≥ 6
9. **Self-healing:** if validation fails, Claude rewrites the rule using each validator's specific feedback and retries — up to three attempts
10. **Circuit breaker:** if a rule still fails after three rewrites, the pipeline stops and emails me. Nothing broken makes it to Kibana
11. pySigma converts the validated Sigma YAML to Elasticsearch DSL
12. `deploy_rule.py` pushes the rule to Kibana via the detection engine API
13. A formatted HTML email lands in my inbox with technique stats, strongest signals, and the recommended next simulation
14. Heatmap and state files update automatically and push back to GitHub

The only point a human enters the loop is when the circuit breaker fires.

## T-Pot Integration

As of May 14 2026, the T-Pot honeypot ships every event it captures to the main ELK over a WireGuard tunnel.

- **Source:** 30+ honeypots on the T-Pot droplet
- **Transport:** Logstash on T-Pot writes to both its local Elasticsearch (preserving T-Pot's own UI) and to ELK at `10.0.0.1:9200` over the encrypted tunnel
- **Authentication:** Dedicated `tpot_writer` user with role scoped to `tpot-*` indices only — least privilege
- **Volume:** Roughly one attack event every 0.5 seconds during a typical hour

The honeypot data feeds the lab's detection coverage from a complementary angle. Endpoint Sysmon shows what attackers do once they're in; T-Pot shows what they're trying everywhere on the internet right now. Real credentials being brute-forced, real CVEs being scanned for, real malware being delivered.

## ATT&CK Coverage

Live, auto-generated from the deployed rule set.

### [🗺️ View Live ATT&CK Coverage Heatmap →](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/1xLoZec/detection-lab/main/docs/coverage_layer.json)

## Progress

**May 26 — Tall Kitchen progress**
- Built Hunt and Water web pages (plain-English), committed and polished.
- Fixed Hunt scoring so confirmed-malicious results scale past 85 instead of flatlining; rewrote verdicts to lead with a clear action.
- Built a rule efficacy counter that measures which deployed rules actually fire on real alerts.
- Found the big one: 30 rules were silently dead. Traced it to a schema mismatch (the Sigma converter emitted raw Sysmon fields like `EventID` against ECS data). Fixed all 30 live rules, fixed the root cause in the deploy converter, and verified rules firing with live attacks.
- Added an efficacy visual to the Water page, auto-refreshing every 15 minutes.
- Built a human review gate: Water now holds every generated rule for approval (CLI + email) instead of auto-deploying, unified across both rule paths.
- Put it all on a schedule: efficacy every 15 min, Water twice daily (generates and holds, never auto-deploys).
  
<img width="1107" height="811" alt="image" src="https://github.com/user-attachments/assets/af3ae7b2-8d33-4913-a155-bff287a577e0" />
<img width="1107" height="473" alt="image" src="https://github.com/user-attachments/assets/6f5941fd-733c-48b8-a41d-c9a14bd07215" />



- **May 14 2026 (later that day)**
  Cleaned up Elasticsearch. T-Pot now on a 30-day ILM policy, replicas dropped to 0, best_compression on. Real disk hog was Elastic Agent metrics from the Windows VM, 16M perfmon docs and 1.6M process snapshots that nothing was reading. Turned those off, kept Sysmon and the Windows Security logs. Stack Monitoring rules now watching disk and JVM.

  <img width="891" height="124" alt="Elasticsearch disk usage cleanup after ILM policy change" src="https://github.com/user-attachments/assets/4b8d2867-4b99-44f9-8a8e-8ff465f74ddf" />

- **May 14 2026**
  T-Pot integration complete. WireGuard tunnel up between ELK and T-Pot — both directions, low latency, persistent across reboots. Created a dedicated `tpot_writer` Elasticsearch user scoped to `tpot-*` indices only — least privilege. Patched T-Pot's Logstash config to dual-output: it still writes to its own local ES (so T-Pot's UI keeps working) and now also ships every event to main ELK over the encrypted tunnel. Wall hit: Logstash 8 fully removed the old `ssl_certificate_verification` and `ssl` settings — they're not deprecated, they're obsolete and crash the pipeline on load. Had to use the modern `ssl_enabled` / `ssl_verification_mode` names. Another fun one: container healthcheck reported "healthy" while Logstash was actually in a pipeline crash loop, because the healthcheck only verifies the API port responds. 1974 attack events landed in ELK in the first ten minutes. tallkitchen_water can now learn from real attackers.

- **May 13 2026**
  T-Pot is live. Dedicated cloud droplet running 30+ honeypots. Cowrie was logging real Telnet brute force attempts from Colombia within minutes of the install finishing. Management is locked down behind ELK, honeypot ports wide open. The build wasn't clean — port conflict put it in a restart loop on the first reboot, took some journal log digging to sort out. Next: pipe the data into the main ELK so tallkitchen_water can learn from real attackers, not just simulations.

  <img width="1145" height="661" alt="T-Pot honeypot dashboard showing real attack events from Colombia" src="https://github.com/user-attachments/assets/061c7d4e-b2ef-445c-b292-91ea071a9636" />

- **May 12 2026**
  Cleaned up the public demo. Fixed Kibana permissions so the demo user can actually see alert data on the dashboard — the role's Security feature privilege needed to be set via the Kibana role API, not the ES role API. Wrong tool for the job. Locked the time range to last 3 months, turned on dark mode, made the dashboard the default landing page. Rewrote the markdown header in plain language. Demo is ready to show.

- **May 11 2026**
  Two big things today.
  First, `demo.1xlozec.com` is live. Public read-only Kibana dashboard with SSL, rate limiting, and a dedicated viewer account. Anyone can see the lab without VPN. Built a Security Overview dashboard with nine live panels covering total alerts, severity distribution, most active rules, ATT&CK coverage, and a live alerts table.

  Second, the CI/CD pipeline is now self-healing. Every Sigma rule runs through four automated stages before it touches Kibana:

  1. YAML lint — catches malformed rules before wasting API calls
  2. Conversion — pySigma translates Sigma to Elastic DSL
  3. Backtest — query runs against live Elasticsearch to confirm it matches real data
  4. Three-AI gate — Claude, Gemini, and Ollama each score the rule independently

  If it fails, Claude rewrites it using each validator's feedback and tries again. Three attempts max. If it still fails, a circuit breaker emails me and stops. Nothing broken makes it to Kibana. 31 custom detection rules deployed to Kibana and firing live alerts. Full pipeline confirmed end to end: simulation → telemetry → AI analysis → rule generation → CI/CD validation → deployment → alert. Three high severity alerts generated from T1059.001, T1082, and T1016 simulations.

- **May 10 2026**
  Built the full tallkitchen_water automation pipeline. One command triggers the entire detection engineering workflow: query Elasticsearch, extract ATT&CK technique with Claude AI, generate a Sigma rule, push to GitHub, validate with three AI models (Claude + Gemini + Ollama), convert to Elastic DSL with pySigma, deploy to Kibana, send a formatted HTML alert to my inbox. 31 rules deployed. 57% ATT&CK tactic coverage. Runs 24/7 with adaptive lookback, weekly digest, and a kill switch. The pipeline is fully operational.

  <img width="862" height="754" alt="tallkitchen_water email report showing technique analysis and deployment summary" src="https://github.com/user-attachments/assets/4e82b198-a59d-4191-aa6a-6a5759ae9c79" />

- **May 10 2026**
  Full Detection-as-Code pipeline is live. Push a Sigma rule to GitHub and it automatically gets validated by three AI models, converted to Elastic query language, and deployed to Kibana. No manual steps. First rule deployed successfully — PowerShell Spawning Reconnaissance Commands. Running every 5 minutes.

  <img width="510" height="74" alt="GitHub Actions workflow run for first detection rule deployment" src="https://github.com/user-attachments/assets/2951a146-6d4c-4349-99db-834555e4c09e" />
  <img width="752" height="140" alt="First detection rule live in Kibana with enabled status" src="https://github.com/user-attachments/assets/dc67a15d-2a6e-44c8-9300-38d44620ef04" />

- **May 8 2026**
  First Atomic Red Team simulation ran today. T1003 credential dumping. Completely isolated, nowhere to go. Telemetry showed up in Kibana immediately. Sysmon caught everything — process creation, registry modifications, logon events. The whole pipeline worked exactly as designed. Writing the first detection rule next.

  <img width="558" height="269" alt="Atomic Red Team T1003 credential dumping simulation executing on Windows VM" src="https://github.com/user-attachments/assets/2a654b1a-2d26-4604-ae85-a65a5f95fb2a" />
  <img width="558" height="269" alt="T1003 simulation telemetry captured by Sysmon and ingested into Kibana" src="https://github.com/user-attachments/assets/c20186bc-723b-47cb-aef3-f4cd0dee7068" />

- **May 8 2026**
  The endpoint pipeline is live. Windows VM telemetry flowing into Kibana. Sysmon operational. Windows event logs, PowerShell logs, and security events all showing up from the VM. Took some work to get here but it's running clean now.

- **May 7 2026**
  Long sessions. Got Proxmox running on the dedicated lab machine and the Windows VM stood up inside it. Built a jump host for secure access to the lab environment. SSH from my PC to the jump host is working with full clipboard support. Still working through network segmentation. Getting closer.

- **April 28 2026**
  Decided to do it right. Replaced the ISP router and mesh WiFi with enterprise-grade gear. Bought a dedicated machine for Proxmox. Proper network segmentation is in place. Attack environment is locked down. Waiting on hardware to finish the build.

- **April 25 2026**
  Hit a wall with VMware. Dug into it, found out Broadcom is shipping incomplete installers. Not a config issue — the files are literally missing. Fixed a DNS issue while I was in there and kept moving.

- **April 24 2026**
  Full ELK stack deployed and secured on DigitalOcean. Ubuntu server patched, firewall configured, SSL via NGINX. Elasticsearch 8.19 running on cluster `1xlozec-lab`, node `elk-node-01` verified responding. Kibana live at https://1xlozec.com. Fleet Server running and healthy. Elastic Agent enrolled and shipping live telemetry. 1,616 Elastic prebuilt detection rules installed with zero gaps. WireGuard VPN configured with split DNS — Kibana accessible only through the encrypted tunnel, blocked on the public internet. First Windows 11 ARM VM stood up in VMware Fusion, Sysmon installed with SwiftOnSecurity config, Elastic Agent enrolled and healthy, telemetry flowing. 704 documents ingested in the first hour.

  <img width="1076" height="873" alt="Elasticsearch cluster 1xlozec-lab verified responding via Kibana Dev Tools" src="https://github.com/user-attachments/assets/65e011c9-47b2-4088-a3f0-cd9c70e389b1" />
  <img width="1076" height="873" alt="First live telemetry documents flowing into Kibana Discover from Elastic Agent" src="https://github.com/user-attachments/assets/4f297393-48c5-4416-97bf-e804358a2aaa" />


## Roadmap

- [ ] Active Directory domain controller in Proxmox VLAN 40 — unlocks Kerberoasting, Pass-the-Hash, LDAP enumeration detection
- [ ] Dedicated Kali Linux attack platform in Proxmox VLAN 40
- [x] ~~T-Pot honeypot on a dedicated DigitalOcean droplet — real internet attackers~~ *(complete May 14 2026)*
- [ ] MISP threat intelligence integration — real IOCs feeding tallkitchen_water
- [ ] False positive feedback loop — thumbs up/down in the weekly digest feeds back to the pipeline
- [ ] Incident response playbooks per technique
- [ ] Documentation site at `docs.1xlozec.com`

## License

MIT — see [LICENSE](LICENSE). Fork it, learn from it, build your own. If you ship something based on this, I'd love to hear about it.

---

*Built by 1xLoZec. Work in progress. Check back often.*
