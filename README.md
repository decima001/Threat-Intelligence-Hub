Threat Intelligence Hub & Incident Response SandboxAn interactive, enterprise-grade Cyber Threat Intelligence (CTI) appliance built using Python and the Django framework. 

The platform acts as a localized security operations checkpoint parsing raw, unstructured incident responder device logs, cross-referencing extracted indicators against global threat campaign actors via AlienVault OTX, and generating dynamically visualized STIX 2.1 Graph topologies natively in the browser. 

Core Architectural Features:

Log Ingestion Parsing Sandbox: Utilizes prioritized regex compilation mechanics to scan, sanitize, and extract key Indicators of Compromise (IoCs) including IPv4 addresses, domains/FQDNs, MD5, and SHA-256 malware hashes from flat text files while automatically filtering internal infrastructure noise.

Live Community Feed Enrichment: Integrates directly with the AlienVault Open Threat Exchange (OTX) API v2 using official software development kits to track real-world infrastructure footprints, active pulses, threat groups, and active tactical malware tags in real time.

Dynamic Security Evaluation Matrix: Employs an internal multi-variable scoring model that cross-examines indicator hit frequencies against live vendor campaign visibility to dynamically assign granular risk trust metrics and severe final mitigation verdicts.OASIS STIX 2.1 Compilation Engine: Compiles flat relational SQL database rows into strictly compliant, graph-connected STIX 2.1 JSON enterprise data bundles on demand.

Interactive Node-Network Visualizer: Embeds the high-performance Vis.js Network rendering engine onto the frontend UI dashboard, programmatically translating raw STIX graph relationship structures into beautiful, draggable browser-native topology charts. 

The Tech Stack MatrixComponent
Framework / Library / Engine Used Backend Architecture Python 3.14+ / Django Web FrameworkData StoreSQLite3 / Django Object-Relational Mapping (ORM)CTI Integrations AlienVault OTXv2 Python SDKSTIX FrameworkOASIS stix2 Specification Translation LayerFrontend UI LayoutBootstrap 5 / Vanilla JavaScript (ES6)Graph VisualizationVis.js Network Standalone Engine System Operational Pipelines1. 
File Ingestion PipelineWhen an analyst drops a raw system, SIEM, or firewall dump into the Sandbox, the application instantly tracks the exact submission timestamp, isolates raw data components, and kicks off an interactive API handshake stream with the threat exchange grid.

2. Trust Score Calculation MatrixRisk evaluation is computed dynamically across four distinct intelligence metrics to protect analysts from alerting fatigue:
$$Composite\ Trust\ Score = \frac{Relevance + Accuracy + Freshness + Completeness}{4}
$$High Confidence Verdicts ($\ge 8.0$): Flagged instantly as Malicious (Critical) and routed to the automated enterprise containment matrix.

3. Edge-Appliance Rule ExportsThe system exposes two downstream operational pipelines natively for security engineers:Plaintext Firewall Blocklists: Live network edge appliances can poll this plain-text view endpoint directly to capture deduplicated, malicious IPv4 addresses for immediate perimeter dropping.STIX 2.1 JSON Streams: Feeds raw, structural intelligence graphs directly into automated SOAR playbooks or external SIEM systems like Splunk or Sentinel.

Project StructurePlaintextthreat_intel_hub/
│
├── threatintel/               # Core Project Configuration Scope
│   ├── settings.py            # Global setups, Middlewares, and OTX Keys
│   └── urls.py                # Main URL routing dispatch grid
│
├── intelligence/              # Specialized Threat App Container
│   ├── templates/             # Front-End UI Layer 
│   │   └── intelligence/
│   │       └── dashboard.html # Vis.js Canvas Map & Operational Console
│   ├── models.py              # Schema definition for IoCs and Audit Logs
│   ├── views.py               # Operational controllers & endpoint triggers
│   └── aggregator.py          # The core regex extraction & OTX query engine
│
└── manage.py                  # Django administrative orchestration script
