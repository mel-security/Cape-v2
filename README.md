# cape_doctor.py

Script all-in-one de diagnostic, collecte et remédiation pour CAPE Sandbox (compatible Cuckoo).

## Objectif

`cape_doctor.py` automatise le troubleshooting d'une installation CAPE/Cuckoo en un seul passage :

1. Exécute des vérifications de configuration (hôte, hyperviseur, réseau, VM guest).
2. Collecte les logs pertinents (hôte + guest).
3. Corrèle les symptômes connus (crash VM avec navigateur moderne, IE flagge toutes les URLs, etc.).
4. Produit un rapport Markdown (`report.md`) avec diagnostics probables et actions correctives.
5. Crée une archive `cape_triage_<hostname>_<timestamp>.tar.gz` de tous les artefacts.

---

## Prérequis

- **OS hôte** : Debian/Ubuntu (prioritaire) ; Fedora/RHEL supporté.
- **Python** : 3.8+
- **Droits** : `root` ou `sudo` recommandé (accès iptables, journald, dmesg, services).
- **Dépendances Python** : aucune externe requise pour le mode par défaut. `pywinrm` uniquement si `--guest-creds=winrm`.
- **Fonctionne offline** par défaut (pas de réseau requis sauf `--online`).

---

## Installation

Aucune installation. Fichier unique, exécutable directement :

```bash
chmod +x cape_doctor.py
```

---

## Interface CLI

```
cape_doctor.py [OPTIONS]
```

### Options

| Option | Défaut | Description |
|---|---|---|
| `--out-dir <path>` | `./cape_triage_<timestamp>` | Répertoire de sortie pour les artefacts |
| `--vm-name <name>` | *(auto-détection)* | Nom de la VM guest (si non détectable) |
| `--hypervisor auto\|kvm\|virtualbox` | `auto` | Forcer le type d'hyperviseur |
| `--fix` | désactivé | Appliquer les remédiations safe (non destructif) |
| `--online` | désactivé | Autoriser les tests réseau externes (ping, DNS, HTTPS) |
| `--guest-creds none\|winrm\|ssh\|manual` | `none` | Méthode de collecte guest |
| `--guest-host <ip>` | — | IP/hostname du guest pour WinRM/SSH |
| `--guest-user <user>` | — | Utilisateur guest |
| `--guest-password <pwd>` | — | Mot de passe guest (préférer env/secret store) |
| `--verbose` | désactivé | Logging détaillé (DEBUG) |

---

## Exemples d'utilisation

### Collecte simple (mode par défaut)

```bash
sudo python3 cape_doctor.py
```

Exécute tous les checks hôte, collecte les logs, corrèle les symptômes, génère le rapport et l'archive. Aucune modification apportée au système.

### Collecte avec tests réseau en ligne

```bash
sudo python3 cape_doctor.py --online
```

Ajoute des tests DNS (`getent hosts example.com`), ping (`1.1.1.1`) et HTTPS (`curl https://example.com`) pour valider la connectivité sortante.

### Collecte + remédiations automatiques

```bash
sudo python3 cape_doctor.py --fix --vm-name win10-cape
```

En plus de la collecte, applique les correctifs safe (détail complet dans la section Remédiations).

### Collecte avec VM spécifique (VirtualBox)

```bash
sudo python3 cape_doctor.py --hypervisor virtualbox --vm-name win10-analysis
```

### Collecte avec WinRM (guest Windows)

```bash
sudo python3 cape_doctor.py \
  --guest-creds winrm \
  --guest-host 192.168.56.101 \
  --guest-user Administrator \
  --guest-password 'S3cret!'
```

Récupère les Event Logs Windows (System, 200 dernières entrées) via WinRM. Nécessite `pywinrm` installé sur l'hôte et le service WinRM actif sur le guest.

### Collecte complète (online + fix + VM + verbose)

```bash
sudo python3 cape_doctor.py \
  --online --fix --verbose \
  --hypervisor kvm --vm-name win10-cape
```

---

## Détail des vérifications

### A. Checks hôte

#### Environnement

- OS, kernel, CPU (flags de virtualisation `vmx`/`svm`)
- Détection automatique CAPE vs Cuckoo (chemins : `/opt/CAPEv2`, `/opt/CAPE`, `~/.cuckoo`, `/etc/cuckoo`)
- Détection du gestionnaire de services (systemd vs supervisord)
- Détection de l'hyperviseur (KVM/libvirt vs VirtualBox)
- Version Git du dépôt CAPE/Cuckoo

#### Paquets et versions

- Python, pip, tcpdump, libvirt, qemu-kvm, VirtualBox
- Services CAPE/Cuckoo, Redis, MongoDB, PostgreSQL/MySQL, Nginx/Apache

#### Services

- Status de chaque service via `systemctl` ou `supervisorctl`
- Ports en écoute (`ss -ltnup`)

#### Configuration CAPE/Cuckoo

Fichiers parsés automatiquement :

- `cuckoo.conf`, `auxiliary.conf`, `machinery.conf`, `routing.conf`
- `processing.conf`, `reporting.conf`, `web.conf`

Paramètres clés extraits : machinery, interface réseau, route, resultserver ip/port, timeout, browser package, proxy, DNS, suricata, yara.

#### Réseau hôte

- Interfaces (`ip a`), routes, `resolv.conf`, NetworkManager
- `net.ipv4.ip_forward`, `rp_filter`
- Règles iptables/nft (NAT, MASQUERADE, FORWARD policy)
- Table ARP
- Tests de connectivité contrôlée (si `--online`)

#### Hyperviseur

**KVM/libvirt** :
- `virsh list --all`, `dominfo`, `domifaddr`
- Journaux libvirtd / virtqemud

**VirtualBox** :
- `VBoxManage list vms`, `showvminfo`
- Logs VM (`VBox*.log`)

#### Inspection VM approfondie (si `--vm-name` fourni)

**KVM** :
- Dump XML complet (`virsh dumpxml`)
- RAM allouée (seuil minimum : 4096 MiB pour navigateurs modernes)
- Type d'adaptateur vidéo (VGA, virtio, QXL, bochs) et VRAM
- Accélération 3D (accel3d)
- Modèle CPU et mode passthrough
- Hyper-V enlightenments (relaxed, vapic, spinlocks)
- Liste des snapshots
- Ligne de commande du processus QEMU en cours d'exécution
- Blocages AppArmor/SELinux sur le processus QEMU

**VirtualBox** :
- Configuration machine lisible (`--machinereadable`)
- RAM allouée
- Contrôleur graphique (VBoxVGA, VBoxSVGA, VMSVGA)
- VRAM
- Accélération 3D et 2D
- Hardware virtualization (hwvirtex, nested paging)

#### Pression mémoire hôte

- RAM disponible vs seuil critique (2048 MiB minimum libre)
- Transparent Huge Pages (THP)
- KSM (Kernel Same-page Merging)

#### Configuration navigateur CAPE

- Packages CAPE browser/chrome/edge : présence des flags `--disable-gpu`, `--no-sandbox`
- MITM / sniffer activé dans `auxiliary.conf`
- Détection de conflit entre sandbox navigateur et instrumentation CAPE

#### Synchronisation horloge

- Status NTP hôte (`timedatectl`)
- Drift horloge matérielle vs système
- Impact sur validation TLS dans le guest

#### Ressources et runtime

- RAM libre, swap, disque (`df -h`)
- Erreurs I/O, OOM killer (dmesg, journald)
- Logs CAPE/Cuckoo (`/var/log/cape/*`, `/var/log/cuckoo/*`, `~/.cuckoo/log/*`)

#### Analyses CAPE récentes échouées

- Scan des 20 dernières analyses dans le storage
- Détection de signatures de crash navigateur (chrome.exe, msedge.exe, GPU process crash, WerFault, STATUS_ACCESS_VIOLATION)
- Copie des logs des analyses échouées dans le bundle

### B. Checks guest (VM Windows)

#### Collecte passive (sans credentials)

- Logs agent/analyzer si partagés sur le filesystem hôte : `agent.log`, `analyzer.log`, `*browser*.log`
- Crash dumps (`.dmp`) dans les répertoires d'analyses

#### Collecte WinRM (`--guest-creds=winrm`)

- Event Logs System (200 dernières entrées)
- Erreurs applicatives (navigateurs, BSOD, bugcheck)

### C. Corrélation et diagnostics

Le script analyse l'ensemble du corpus collecté (commandes + logs) et détecte automatiquement :

| Symptôme | Causes probables détectées |
|---|---|
| VM crash avec navigateur moderne | OOM kill du process qemu/VirtualBox, accélération 3D instable, RAM VM insuffisante (<4 GB), adaptateur vidéo incompatible (VGA/virtio au lieu de QXL), Hyper-V enlightenments manquants, conflit sandbox navigateur vs CAPE monitor, VC++ runtimes manquants |
| Crash GPU process Chrome/Edge | `STATUS_ACCESS_VIOLATION`, `GpuProcessHost::OnProcessCrashed`, flags `--disable-gpu`/`--no-sandbox` absents du package CAPE, VRAM trop basse |
| KVM internal error | Triple fault, `KVM_EXIT_INTERNAL_ERROR`, CPU non host-passthrough, EPT manquant |
| CAPE monitor injection failure | `inject_dll failed`, `capemon error`, conflit avec architecture multi-process des navigateurs modernes |
| Snapshot corrompu | `snapshot error`, `restore failed`, snapshot pris pendant activité GPU/navigateur |
| IE marque toutes les URLs malveillantes | Erreurs TLS/cert (MITM), DNS sinkhole, proxy renvoyant block page, SmartScreen/Defender actif |
| Agent CAPE non joignable | Timeout agent, `connection refused` sur port 8000/2042, agent.pyw non démarré |
| IP forwarding désactivé | `net.ipv4.ip_forward = 0`, pas de MASQUERADE |
| Resultserver non joignable | IP/port mismatch, FORWARD DROP, firewall |
| AppArmor/SELinux bloque QEMU | Entrées `denied` dans audit log pour processus qemu |
| Pression mémoire hôte | RAM disponible < 2 GB, OOM killer actif |
| NTP non synchronisé | Drift horloge -> échec validation certificats TLS dans le guest |
| Erreurs display QEMU | Erreurs QXL/spice/virtio-gpu/cirrus dans logs libvirt |

### D. Remédiations (`--fix`)

Toutes les actions sont loggées. Seuls les correctifs safe sont appliqués.

#### Fixes réseau

| Action | Condition |
|---|---|
| `sysctl -w net.ipv4.ip_forward=1` | Toujours |
| Ajout règle `MASQUERADE` sur interface par défaut | Si absente |

#### Fixes permissions et services

| Action | Condition |
|---|---|
| `chmod -R u+rwX` sur répertoires de logs | Si existent |
| Activation KSM | Si `/sys/kernel/mm/ksm/run = 0` |
| `systemctl restart` des services CAPE/libvirt | Si systemd détecté (en dernier) |

#### Fixes KVM (si `--vm-name` fourni)

| Action | Condition |
|---|---|
| Changement adaptateur vidéo -> QXL | Si actuellement VGA, virtio, bochs, ou ramfb |
| Augmentation VRAM | Si < 128 MiB |
| Désactivation accélération 3D | Si `accel3d='yes'` |
| Ajout Hyper-V enlightenments | Si `relaxed`, `vapic`, ou `spinlocks` manquants |
| CPU mode `host-passthrough` | Si non configuré |
| Augmentation RAM VM -> 4096 MiB | Si < 4096 MiB |
| `virsh define` du XML corrigé | Si au moins un changement appliqué |

**Important** : après modification du XML KVM, l'ancien snapshot est invalide. Le script signale qu'il faut recréer le snapshot.

#### Fixes VirtualBox (si `--vm-name` fourni)

| Action | Condition |
|---|---|
| `--accelerate3d off` | Si 3D activée |
| `--graphicscontroller vboxvga` | Si VMSVGA ou VBoxSVGA |
| `--vram 128` | Si VRAM < 128 MiB |
| `--memory 4096` | Si RAM < 4096 MiB |
| `--hwvirtex on --nestedpaging on` | Si hwvirtex désactivé |

**Important** : après modification VirtualBox, l'ancien snapshot est invalide. Recréer le snapshot.

#### Fixes NON appliqués (signalés dans le rapport)

Les actions suivantes sont recommandées mais jamais exécutées automatiquement :
- Installation de VC++ Redistributables dans le guest
- Modification des flags de lancement du navigateur dans le guest
- Configuration SmartScreen/Defender dans le guest
- Certificats racine / proxy dans le guest
- Suppression/recréation de snapshot

---

## Sorties

### Écran

Résumé coloré des findings triés par sévérité (HIGH en rouge, MEDIUM en jaune, LOW en vert), avec chemins vers le rapport et l'archive.

### `report.md`

Rapport Markdown structuré :

```
# CAPE/Cuckoo Triage Report
- Generated: <ISO8601>
- Host: <hostname>
- Framework: cape|cuckoo
- Hypervisor: kvm|virtualbox
- Service manager: systemd|supervisord

## Inventory
- hostname, kernel, os_release, virt_flags_count

## VM Configuration
- ram_mib, video_adapter, video_vram_kib, 3d_acceleration
- hyperv_enlightenments, host_ram_available_mib
- qemu_running, browser_crash_failures, ...

## Key Checks
- [PASS|WARN] <commande> (rc=<N>) -> <fichier_json>

## Findings
### 1. <symptôme> (HIGH|MEDIUM|LOW)
**Indices** ...
**Causes probables** ...
**Actions correctives** ...

## Recommended Next Steps
1. ...
```

### Archive `cape_triage_<hostname>_<timestamp>.tar.gz`

```
cape_triage_<timestamp>/
├── cape_doctor.log          # Log du script
├── report.md                # Rapport final
├── fixed_vm.xml             # XML KVM corrigé (si --fix appliqué)
├── commands/                # Sorties JSON de chaque commande exécutée
│   ├── os_release.json
│   ├── uname.json
│   ├── virsh_dumpxml.json
│   ├── vbox_machinereadable.json
│   ├── qemu_process.json
│   ├── svc_cape.json
│   ├── iptables_nat.json
│   └── ...
├── configs/                 # Copies masquées des fichiers de config
│   ├── CAPEv2_conf_cuckoo.conf
│   ├── CAPEv2_conf_routing.conf
│   ├── package_chrome.py    # Packages navigateur CAPE
│   └── ...
├── logs/                    # Tails des logs collectés
│   ├── _var_log_cape_cuckoo.log.tail.log
│   ├── vbox_0_VBox.log
│   └── ...
├── metadata/                # Données structurées
│   ├── environment.json
│   └── parsed_configs.json
├── failed_analyses/         # Analyses CAPE récentes échouées
│   ├── 42/
│   │   ├── task.json
│   │   └── analysis.log
│   └── ...
└── guest/                   # Artefacts guest (si disponibles)
    ├── agent.log
    ├── analyzer.log
    └── winrm_system_events.txt
```

---

## Interprétation rapide du rapport

### Findings HIGH - Crash navigateur

Action immédiate requise. Causes directes du crash.

- **"VM RAM too low for modern browsers (N MiB < 4096 MiB)"** : Chrome/Edge consomment 2-3 GB seuls. La VM a besoin d'au minimum 4 GB RAM. `--fix` augmente automatiquement.
- **"KVM video adapter 'vga' incompatible with modern browsers"** : L'adaptateur VGA/virtio/bochs ne supporte pas le rendu Chrome/Edge. Passer à QXL. `--fix` corrige automatiquement.
- **"KVM 3D acceleration enabled"** / **"VirtualBox 3D acceleration enabled"** : L'accélération 3D est expérimentale et fait crasher le GPU process du navigateur. `--fix` désactive automatiquement.
- **"VirtualBox graphics controller 'VMSVGA' unstable"** : VMSVGA/VBoxSVGA avec 3D = crash garanti. Passer à VBoxVGA. `--fix` corrige automatiquement.
- **"Browser crash detected in N/M recent failed analyses"** : Signatures de crash navigateur confirmées dans les analyses CAPE récentes. Suivre les recommandations détaillées dans le finding.
- **"CAPE browser package missing --disable-gpu / --no-sandbox"** : Le package navigateur CAPE ne passe pas les flags nécessaires. Chrome/Edge essaient d'utiliser le GPU (qui n'existe pas dans la VM) et crashent.
- **"CAPE monitor injection failure"** : L'injection DLL de CAPE dans le processus navigateur échoue. Tester avec `options=free=yes`.
- **"AppArmor/SELinux blocking QEMU"** : Le MAC bloque les opérations mémoire de QEMU, ce qui crash la VM au lancement du navigateur.

### Findings HIGH - Infrastructure

- **"VM process likely killed by OOM"** : Le kernel a tué le processus qemu/VirtualBox. Augmenter la RAM hôte, ajouter du swap, réduire les analyses concurrentes.
- **"Host RAM critically low"** : Moins de 2 GB libres sur l'hôte. OOM imminent.
- **"IP forwarding disabled"** : Le guest n'a aucun accès réseau. `--fix` active `ip_forward`.
- **"Potential routing/NAT breakage"** : FORWARD DROP sans MASQUERADE. `--fix` ajoute la règle.
- **"Resultserver communication issue"** : Vérifier IP/port dans `routing.conf`/`machinery.conf`.
- **"KVM internal error / triple fault"** : Utiliser CPU host-passthrough. `--fix` l'applique.
- **"VM snapshot restore failure"** : Recréer le snapshot depuis un état VM propre (desktop, pas d'applications ouvertes).
- **"CAPE agent not responding"** : Vérifier agent.pyw dans Startup du guest + firewall Windows.
- **"Virtualization flags missing"** : Activer VT-x/AMD-V dans le BIOS/UEFI.

### Findings MEDIUM

Facteurs aggravants ou causes secondaires.

- **"Missing Hyper-V enlightenments"** : Windows guest sans `relaxed`/`vapic`/`spinlocks` = instabilité sous charge. `--fix` les ajoute.
- **"QEMU not using '-cpu host' passthrough"** : Instructions CPU manquantes peuvent faire crasher le JIT/WASM du navigateur.
- **"VM VRAM low"** : VRAM < 128 MiB cause des échecs de rendu. `--fix` augmente.
- **"VirtualBox VRAM too low"** : Idem pour VirtualBox. `--fix` corrige.
- **"Host NTP not synchronized"** : Drift horloge -> échec TLS dans le guest -> toutes les URLs échouent.
- **"QEMU display device errors"** : Erreurs QXL/spice/virtio-gpu. Changer d'adaptateur vidéo.
- **"IE marking all URLs may be policy/TLS/proxy artifact"** : Vérifier certificats racine, SmartScreen, proxy, DNS sinkhole dans le guest.
- **"Hypervisor not auto-detected"** : Forcer `--hypervisor kvm|virtualbox`.

### Findings LOW

- **"KSM disabled"** : Activer KSM peut économiser 10-30% RAM avec plusieurs VMs similaires.
- **"No obvious hard failure signatures"** : Relancer une analyse unitaire avec logging verbeux.

---

## Sécurité et confidentialité

- **Masquage automatique** : les IPs publiques sont remplacées par `x.x.x.x`, les mots de passe/tokens/secrets sont masqués (`***`) dans tous les artefacts de sortie.
- **Clés privées** : détectées et remplacées par `***PRIVATE_KEY_REDACTED***`.
- **IPs privées** : conservées telles quelles (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x).
- **Pas de stockage de secrets en clair** dans les fichiers de sortie.
- **Mode `--fix` non destructif** : chaque action est loggée, les commandes appliquées sont sauvegardées en JSON.

---

## Propriétés du script

| Propriété | Détail |
|---|---|
| Idempotent | Oui (hors `--fix` qui est additif et loggé) |
| Non destructif | Oui par défaut ; `--fix` n'applique que des correctifs safe |
| Offline | Oui par défaut ; `--online` opt-in |
| Interactif | Non ; tout est piloté par arguments CLI et auto-détection |
| Exit codes | `0` = succès, `2` = erreur non gérée |
| Logging | Fichier `cape_doctor.log` + stdout, horodaté |
| Tolérance erreur | Les fichiers/commandes manquants sont marqués SKIP, le script ne crashe pas |

---

## Architecture du script

```
cape_doctor.py
│
├── CmdResult (dataclass)        # Résultat d'exécution de commande
├── Finding (dataclass)          # Diagnostic structuré (sévérité, symptôme, causes, actions)
│
├── CapeDoctor (classe)          # Moteur principal
│   ├── __init__()               # Init dirs, logging, config paths
│   ├── _mask_public_ip()        # Masquage IPs publiques
│   ├── _mask_secrets()          # Masquage passwords/tokens/clés
│   ├── run_cmd()                # Exécution commande avec timeout, logging JSON
│   │
│   ├── detect_environment()     # OS, kernel, CPU virt flags, framework, hyperviseur
│   ├── collect_versions_and_packages()  # Python, pip, paquets système, git rev
│   ├── collect_service_status() # Status systemd/supervisord, ports
│   ├── parse_configs()          # Parse configs CAPE/Cuckoo, extraction params clés
│   ├── collect_network()        # ip, routes, iptables, NAT, forwarding, DNS
│   ├── collect_hypervisor()     # KVM (virsh) ou VirtualBox (VBoxManage) + logs
│   │
│   ├── collect_vm_config()      # Inspection VM approfondie
│   │   ├── _inspect_kvm_vm()    #   KVM: XML, RAM, vidéo, CPU, Hyper-V, AppArmor
│   │   └── _inspect_vbox_vm()   #   VBox: config, RAM, GFX, VRAM, 3D, hwvirtex
│   ├── check_host_memory()      # Pression mémoire hôte, THP, KSM
│   ├── check_cape_browser_config()  # Packages browser, flags --disable-gpu
│   ├── check_clock_drift()      # NTP, drift horloge, impact TLS
│   │
│   ├── collect_resources_and_runtime_logs()  # RAM, disk, OOM, logs runtime
│   ├── collect_failed_analyses()    # Scan analyses CAPE échouées, crash navigateur
│   ├── collect_guest()          # Collecte passive + WinRM optionnel
│   │   └── _collect_winrm()     # Event Logs Windows via pywinrm
│   │
│   ├── correlate()              # Corrélation symptoms -> causes -> actions (étendue)
│   ├── apply_fixes()            # Remédiations safe (si --fix)
│   │   ├── _fix_kvm_browser_crash()   #   KVM: vidéo, 3D, Hyper-V, CPU, RAM, XML
│   │   └── _fix_vbox_browser_crash()  #   VBox: 3D, GFX, VRAM, RAM, hwvirtex
│   ├── write_report()           # Génération report.md
│   ├── create_archive()         # Création tar.gz
│   └── print_summary()         # Résumé coloré terminal
│
├── _python_module_available()   # Test import module
├── shlex_quote()                # Échappement shell safe
├── parse_args()                 # argparse CLI
└── main()                       # Orchestration séquentielle
```

### Flux d'exécution

```
main()
 ├─ detect_environment()
 ├─ collect_versions_and_packages()
 ├─ collect_service_status()
 ├─ parse_configs()
 ├─ collect_network()
 ├─ collect_hypervisor()
 ├─ collect_vm_config()              # NEW: inspection VM profonde
 ├─ check_host_memory()              # NEW: pression mémoire hôte
 ├─ check_cape_browser_config()      # NEW: config navigateur CAPE
 ├─ check_clock_drift()              # NEW: synchronisation horloge
 ├─ collect_resources_and_runtime_logs()
 ├─ collect_failed_analyses()        # NEW: analyses CAPE échouées
 ├─ collect_guest()
 ├─ correlate()                      # ENHANCED: patterns navigateur
 ├─ apply_fixes()                    # ENHANCED: fixes KVM/VBox browser
 ├─ write_report()
 ├─ create_archive()
 └─ print_summary()
```

---

## Guide de résolution : crash navigateur moderne dans la VM

Si la VM crash systématiquement après le lancement de Chrome/Edge, suivre cet ordre :

### 1. Diagnostic rapide

```bash
sudo python3 cape_doctor.py --vm-name <nom-vm> --verbose
```

Examiner le rapport, section "Findings HIGH". Les causes les plus fréquentes sont listées ci-dessous par ordre de probabilité.

### 2. Causes les plus fréquentes (par ordre)

**a) Accélération 3D activée** (cause n°1)
```bash
# KVM - vérifier
virsh dumpxml <vm> | grep accel3d
# VirtualBox - vérifier
VBoxManage showvminfo <vm> | grep -i "3d"
# Fix automatique
sudo python3 cape_doctor.py --fix --vm-name <vm>
```

**b) Adaptateur vidéo incompatible** (KVM)
```bash
# Vérifier - si c'est "vga", "virtio", "bochs" -> problème
virsh dumpxml <vm> | grep -A2 "<video>"
# Fix: passer à QXL
sudo python3 cape_doctor.py --fix --vm-name <vm>
# Puis installer le driver QXL WDDM dans le guest (virtio-win ISO)
```

**c) Contrôleur graphique instable** (VirtualBox)
```bash
# Vérifier - si VMSVGA ou VBoxSVGA -> problème
VBoxManage showvminfo <vm> --machinereadable | grep -i graphic
# Fix: passer à VBoxVGA
sudo python3 cape_doctor.py --fix --vm-name <vm>
```

**d) RAM VM insuffisante** (<4 GB)
```bash
# Fix automatique
sudo python3 cape_doctor.py --fix --vm-name <vm>
```

**e) Flags navigateur manquants dans le package CAPE**

Modifier le package browser dans CAPE pour ajouter aux arguments de lancement :
```
--disable-gpu --disable-software-rasterizer --no-sandbox --disable-dev-shm-usage
```

Ou soumettre l'analyse avec :
```
options=browser_args=--disable-gpu,--no-sandbox
```

**f) Conflit CAPE monitor / sandbox navigateur**

Tester avec :
```
options=free=yes
```
Si le navigateur ne crashe plus, c'est l'injection DLL qui pose problème. Solutions :
- Mettre à jour CAPE vers la dernière version
- Utiliser `options=injection=0` si l'analyse comportementale n'est pas nécessaire

### 3. Après les correctifs

```bash
# Recréer le snapshot (OBLIGATOIRE après modification VM)
# KVM:
virsh start <vm>
# attendre boot complet...
virsh snapshot-create-as <vm> clean --atomic

# VirtualBox:
VBoxManage startvm <vm> --type headless
# attendre boot complet...
VBoxManage snapshot <vm> take clean --live

# Relancer une analyse test
```

### 4. Si le problème persiste

```bash
# Collecte complète avec tests réseau
sudo python3 cape_doctor.py --fix --online --vm-name <vm> --verbose \
  --guest-creds winrm --guest-host <ip-guest> \
  --guest-user Administrator --guest-password '<pwd>'
```

Examiner `failed_analyses/` dans l'archive pour les logs de crash détaillés.

---

## FAQ / Troubleshooting étendu

### Q1 : Chrome/Edge crash immédiatement mais IE fonctionne, pourquoi ?

IE n'utilise pas d'architecture multi-process ni de GPU process séparé. Chrome/Edge lancent un process GPU dédié qui tente d'initialiser l'accélération graphique matérielle. Dans une VM sans GPU réel (ou avec un adaptateur vidéo inadapté), ce process crash au démarrage.

**Diagnostic :**
```bash
sudo python3 cape_doctor.py --vm-name <vm> --verbose
```
Chercher dans le rapport : `KVM video adapter`, `3D acceleration`, `VM RAM too low`.

**Fix rapide :** lancer le navigateur avec `--disable-gpu --no-sandbox` ou appliquer `--fix`.

### Q2 : J'ai désactivé la 3D et changé l'adaptateur vidéo mais ça crash toujours

Causes restantes par ordre de probabilité :

1. **Snapshot non recréé** : après modification de la VM, l'ancien snapshot restaure la config précédente. Recréer impérativement le snapshot (voir Guide de résolution, étape 3).
2. **RAM VM < 4 GB** : Chrome/Edge consomment 2-3 GB seuls. Vérifier `ram_mib` dans le rapport.
3. **CAPE monitor (capemon) injection** : l'injection DLL dans les processus navigateur crash le browser sandbox. Tester avec `options=free=yes`. Si ça marche, le problème vient de l'injection.
4. **VC++ Redistributables manquants** : installer VC++ 2015-2022 x86+x64 dans le guest.
5. **Profil navigateur corrompu** : supprimer le profil Chrome/Edge par défaut dans le guest avant de prendre le snapshot.

### Q3 : IE affiche TOUTES les URLs comme malveillantes, même google.com

Ce n'est pas un vrai positif. L'analyse CAPE classe le comportement réseau comme malveillant à cause d'artefacts d'infrastructure :

1. **Proxy MITM / sniffer actif** : CAPE intercept le trafic TLS. IE détecte le certificat invalide, affiche une page d'erreur. Les signatures CAPE/Suricata classent cette erreur comme indicateur de malveillance.
   - Vérifier `auxiliary.conf` : section `[mitm]` et `[sniffer]`.
   - Le rapport affiche `mitm_enabled: yes` si détecté.

2. **DNS sinkhole** : un DNS qui redirige tout vers une IP interne produit des block pages identiques pour chaque URL, interprétées comme malveillantes.
   - Vérifier `/etc/resolv.conf` sur l'hôte et la config DNS dans le guest.

3. **Certificats racine manquants dans le guest** : le navigateur refuse les connexions TLS, générant des erreurs réseau classées comme suspectes.
   - Installer les certificats racine dans le magasin Windows du guest.

4. **Scoring CAPE/Suricata trop agressif** : certaines règles Suricata ou signatures YARA marquent des patterns légitimes.
   - Vérifier `processing.conf` et `reporting.conf` pour les seuils de scoring.
   - Examiner les règles Suricata actives.

**Diagnostic :**
```bash
sudo python3 cape_doctor.py --vm-name <vm> --online
```
Le flag `--online` teste la connectivité DNS/HTTPS depuis l'hôte pour confirmer si le problème est réseau.

### Q4 : Le script affiche "Hypervisor not auto-detected"

Le script cherche `virsh` (KVM) ou `VBoxManage` (VirtualBox) dans le PATH. Si ces binaires ne sont pas installés ou pas dans le PATH du user root :

```bash
# Vérifier
which virsh
which VBoxManage

# Forcer le type
sudo python3 cape_doctor.py --hypervisor kvm --vm-name <vm>
sudo python3 cape_doctor.py --hypervisor virtualbox --vm-name <vm>
```

### Q5 : Le `--fix` a modifié ma VM mais l'ancienne snapshot ne marche plus

C'est attendu. Le `--fix` modifie la définition de la VM (XML KVM ou config VBox). L'ancien snapshot référence l'ancienne configuration. Il faut :

1. Démarrer la VM manuellement
2. Attendre le boot complet (desktop visible)
3. Si l'adaptateur vidéo a été changé vers QXL (KVM), installer le driver QXL WDDM depuis l'ISO virtio-win
4. Prendre un nouveau snapshot

```bash
# KVM
virsh start <vm>
# ... attendre boot ...
virsh snapshot-create-as <vm> clean --atomic

# VirtualBox
VBoxManage startvm <vm> --type headless
# ... attendre boot ...
VBoxManage snapshot <vm> take clean --live
```

### Q6 : Quelle est la configuration VM optimale pour les navigateurs modernes ?

**KVM :**
```xml
<memory unit='GiB'>4</memory>
<cpu mode='host-passthrough'/>
<features>
  <hyperv>
    <relaxed state='on'/>
    <vapic state='on'/>
    <spinlocks state='on' retries='8191'/>
  </hyperv>
</features>
<video>
  <model type='qxl' vram='131072' heads='1'/>
</video>
```
- Pas de `accel3d='yes'`
- Driver QXL WDDM installé dans le guest

**VirtualBox :**
```
VBoxManage modifyvm <vm> --memory 4096 --vram 128 \
  --graphicscontroller vboxvga --accelerate3d off \
  --hwvirtex on --nestedpaging on
```

**Guest Windows :**
- VC++ Redistributables 2015-2022 (x86 + x64)
- .NET Framework 4.8
- Chrome/Edge lancé avec `--disable-gpu --no-sandbox --disable-dev-shm-usage`
- SmartScreen désactivé (GPO ou registre)
- Windows Defender en mode passif ou désactivé
- Windows Update arrêté (pour stabilité du snapshot)
- NTP synchronisé

### Q7 : Comment savoir si c'est l'injection CAPE qui fait crasher le navigateur ?

Soumettre une analyse avec `options=free=yes`. Ce mode désactive l'injection du monitor CAPE dans les processus. Si le navigateur ne crashe plus :

- Le problème est confirmé comme étant l'injection DLL.
- Solution temporaire : `options=injection=0`
- Solution pérenne : mettre à jour CAPE (les versions récentes gèrent mieux les navigateurs multi-process).

### Q8 : Le script peut-il collecter les logs du guest Windows ?

**Sans credentials (par défaut)** : le script collecte les fichiers `agent.log`, `analyzer.log`, `*browser*.log` et `*.dmp` depuis le filesystem de l'hôte (répertoires de stockage CAPE).

**Avec WinRM** : collecte active des Event Logs Windows.
```bash
sudo python3 cape_doctor.py \
  --guest-creds winrm \
  --guest-host 192.168.122.100 \
  --guest-user Administrator \
  --guest-password 'password'
```
Nécessite : `pip install pywinrm` + WinRM activé dans le guest (`winrm quickconfig`).

### Q9 : Le rapport montre "AppArmor/SELinux blocking QEMU", que faire ?

AppArmor (Ubuntu/Debian) ou SELinux (RHEL/Fedora) peut bloquer les opérations mémoire de QEMU, ce qui crash la VM sous charge (lancement navigateur = pic mémoire).

```bash
# AppArmor : passer le profil en mode permissif
sudo aa-complain /etc/apparmor.d/usr.sbin.libvirtd
sudo aa-complain /etc/apparmor.d/abstractions/libvirt-qemu

# SELinux : passer en permissif temporairement
sudo setenforce 0

# Puis relancer l'analyse pour confirmer
# Si ça marche, ajuster la politique (pas rester en permissif en prod)
```

### Q10 : Comment interpréter la section "VM Configuration" du rapport ?

| Champ | Valeur attendue | Problème si |
|---|---|---|
| `ram_mib` | >= 4096 | < 4096 : RAM insuffisante |
| `video_adapter` | `qxl` | `vga`, `virtio`, `bochs` : crash navigateur |
| `video_vram_kib` | >= 131072 (128 MiB) | < 131072 : échec rendu |
| `3d_acceleration` | absent ou `off` | `on` : crash GPU process |
| `graphics_controller` | `vboxvga` | `vmsvga`, `vboxsvga` : instable |
| `hyperv_enlightenments` | `relaxed,spinlocks,vapic` | `none` : freeze sous charge |
| `host_ram_available_mib` | >= 2048 | < 2048 : OOM imminent |
| `browser_crash_failures` | `0` | > 0 : crashs confirmés |
| `qemu_running` | `yes` (si VM active) | absent : VM non démarrée |
| `mitm_enabled` | `no` | `yes` : peut casser TLS/certs |

---

## Dépannage du script lui-même

| Problème | Cause | Solution |
|---|---|---|
| `Permission denied` sur iptables/dmesg | Script lancé sans `sudo` | Relancer avec `sudo python3 cape_doctor.py` |
| `pywinrm` manquant | Module non installé | `pip install pywinrm` (hors scope offline) |
| Aucun framework détecté | CAPE/Cuckoo installé dans un chemin non standard | Vérifier que `/opt/CAPEv2`, `/opt/CAPE` ou `~/.cuckoo` existe |
| `Hypervisor not auto-detected` | `virsh`/`VBoxManage` absent du PATH | Installer les outils ou forcer `--hypervisor kvm\|virtualbox` |
| Archive vide | Aucun artefact collecté (droits insuffisants) | Vérifier les permissions et relancer avec `sudo` |

---

## Licence

Voir le dépôt pour les conditions de licence.
