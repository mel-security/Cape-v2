# cape_doctor.py

Script all-in-one de diagnostic, collecte et remédiation pour CAPE Sandbox (compatible Cuckoo).

## Objectif

`cape_doctor.py` automatise le troubleshooting d'une installation CAPE/Cuckoo en un seul passage :

1. Exécute des vérifications de configuration (hôte, hyperviseur, réseau, VM guest).
2. Collecte les logs pertinents (hôte + guest).
3. Corrèle les symptômes connus (crash VM avec navigateur moderne, IE flagge toutes les URLs, etc.).
4. **Diagnostique les crashes/arrêts de VM** (libvirt SIGTERM, perte monitor QEMU, devices instables, backing chain profonde).
5. Produit un rapport Markdown (`report.md`) avec diagnostics probables et actions correctives.
6. Crée une archive `cape_triage_<hostname>_<timestamp>.tar.gz` de tous les artefacts.

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
| `--all-vms` | désactivé | Diagnostiquer toutes les VMs (pas uniquement `--vm-name`) |
| `--fix-vm-xml` | désactivé | Supprimer les devices risqués du XML VM (requiert `--fix`) |
| `--fix-spice-to-vnc` | désactivé | Convertir SPICE en VNC et QXL en VGA (requiert `--fix --fix-vm-xml`) |
| `--backing-chain-threshold <N>` | `5` | Seuil d'alerte pour la profondeur de backing chain qcow2 |

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
sudo python3 cape_doctor.py --fix
```

En plus de la collecte, applique les correctifs safe :
- Active `net.ipv4.ip_forward`
- Ajoute la règle `MASQUERADE` si absente
- Corrige les permissions des répertoires de logs CAPE/Cuckoo
- Relance les services CAPE/Cuckoo et libvirtd
- Désactive l'accélération 3D VirtualBox (si hypervisor=virtualbox et `--vm-name` fourni)

### Diagnostic VM complet avec fix XML

```bash
sudo python3 cape_doctor.py --fix --fix-vm-xml --vm-name win10-cape
```

Diagnostique la VM `win10-cape`, supprime les devices risqués (USB redirection, watchdog) et génère un rapport avec inventaire VM.

### Fix complet : SPICE vers VNC + suppression devices inutiles

```bash
sudo python3 cape_doctor.py --fix --fix-vm-xml --fix-spice-to-vnc --vm-name win10-cape
```

En plus des suppressions de base, convertit SPICE en VNC et QXL en VGA pour un profil sandbox headless minimal.

### Diagnostic de toutes les VMs

```bash
sudo python3 cape_doctor.py --all-vms --backing-chain-threshold 3
```

Diagnostique toutes les VMs libvirt, avec un seuil d'alerte de backing chain à 3 niveaux.

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
  --online --fix --fix-vm-xml --fix-spice-to-vnc --verbose \
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

#### Ressources et runtime

- RAM libre, swap, disque (`df -h`)
- Erreurs I/O, OOM killer (dmesg, journald)
- Logs CAPE/Cuckoo (`/var/log/cape/*`, `/var/log/cuckoo/*`, `~/.cuckoo/log/*`)

### B. Diagnostics VM (libvirt/QEMU)

Cette section est automatiquement exécutée lorsque l'hyperviseur détecté est KVM.

#### Inventaire VM

Pour chaque VM (ou la VM spécifiée via `--vm-name`) :
- `virsh list --all` : état de toutes les VMs
- `virsh dominfo <vm>` : vCPU, RAM, état
- `virsh domstate <vm>` : état courant
- `virsh dumpxml <vm>` : configuration XML complète

#### Détection STOPPED_BY_LIBVIRT

Analyse `/var/log/libvirt/qemu/<vm>.log` pour détecter :
- `"terminating on signal 15 from pid … (/usr/sbin/libvirtd)"`
- `"shutting down, reason=destroyed"`

Si trouvé : **"VM arrêtée par libvirtd (SIGTERM), pas un crash guest prouvé"**. Causes possibles : watchdog, OOM cgroup, virsh destroy, redémarrage libvirtd.

#### Détection QEMU_MONITOR_LOST

Analyse `journalctl -u libvirtd` pour détecter :
- `"monitor must not be NULL"`
- `"End of file while reading data: Input/output error"`

Si trouvé : **"Perte du canal monitor QEMU"**. Causes possibles : QEMU tué par OOM, devices SPICE/USB instables, socket fermée.

#### Linting XML (DEVICE_LINT)

Analyse le XML de chaque VM et détecte les devices risqués pour un environnement sandbox :

| Device | Sévérité | Risque |
|---|---|---|
| `<graphics type='spice'>` | MEDIUM | Inutile en sandbox headless |
| `<channel type='spicevmc'>` | MEDIUM | Lié à SPICE |
| `<redirdev type='spicevmc'>` (USB redir) | HIGH | Source connue de crashs QEMU (`usb-redir connection broken`) |
| `<audio type='spice'>` | LOW | Inutile en sandbox |
| `<watchdog action='reset'>` | HIGH | Peut redémarrer la VM pendant l'analyse |
| `<input type='tablet' bus='usb'>` | LOW | Redondant si PS/2 existe |
| `<video model='qxl'>` | MEDIUM | Optimisé SPICE, préférer VGA |

Un **risk score** est calculé et classé en LOW/MEDIUM/HIGH.

#### Profondeur de backing chain (BACKING_CHAIN_DEPTH)

- Identifie le disque principal depuis le XML (`<disk device='disk'><source file='…'>`)
- Exécute `qemu-img info --backing-chain <disk>`
- Calcule la profondeur de la chaîne
- Alerte si > seuil (défaut : 5)
- Propose un plan flatten/commit mais **n'auto-exécute jamais** sans confirmation

### C. Checks guest (VM Windows)

#### Collecte passive (sans credentials)

- Logs agent/analyzer si partagés sur le filesystem hôte : `agent.log`, `analyzer.log`, `*browser*.log`
- Crash dumps (`.dmp`) dans les répertoires d'analyses

#### Collecte WinRM (`--guest-creds=winrm`)

- Event Logs System (200 dernières entrées)
- Erreurs applicatives (navigateurs, BSOD, bugcheck)

### D. Corrélation et diagnostics

Le script analyse l'ensemble du corpus collecté et détecte automatiquement :

| Symptôme | Causes probables détectées |
|---|---|
| VM crash avec navigateur moderne | OOM kill du process qemu/VirtualBox, accélération 3D VirtualBox instable, manque de RAM guest/hôte |
| VM arrêtée par libvirtd (SIGTERM) | Watchdog action=reset, cgroup OOM, virsh destroy, libvirtd restart |
| Perte monitor QEMU | SPICE/USB redirection instable, QEMU tué par OOM, socket error |
| Devices VM risqués pour sandbox | SPICE, USB redir, watchdog, QXL, usb-tablet |
| Backing chain qcow2 profonde | Accumulation de snapshots, latence I/O, timeouts |
| IE marque toutes les URLs malveillantes | Erreurs TLS/cert (MITM), DNS sinkhole, proxy renvoyant block page, SmartScreen/Defender actif, scoring CAPE trop agressif |
| Agent/resultserver non joignable | Mismatch IP resultserver (après changement IP hôte), FORWARD DROP sans MASQUERADE, firewall |
| VM non démarrable | Flags VT-x/AMD-V absents, erreurs hyperviseur, EPT/invalid opcode |

### E. Remédiations (`--fix`)

Toutes les actions sont loggées. Seuls les correctifs safe sont appliqués :

| Action | Condition |
|---|---|
| `sysctl -w net.ipv4.ip_forward=1` | Toujours |
| Ajout règle `MASQUERADE` sur interface par défaut | Si absente |
| `chmod -R u+rwX` sur répertoires de logs | Si existent |
| `systemctl restart` des services CAPE/libvirt | Si systemd détecté |
| `VBoxManage modifyvm --accelerate3d off` | Si hypervisor=virtualbox et `--vm-name` fourni |

#### Remédiations VM XML (`--fix --fix-vm-xml`)

| Action | Condition |
|---|---|
| Sauvegarde XML dans `/tmp/cape_doctor_backup_<vm>.xml` | Toujours avant modification |
| Suppression `<redirdev type='spicevmc'>` | Toujours |
| Suppression `<redirfilter>` | Si présent |
| Suppression `<watchdog>` | Toujours |
| Suppression `<input type='tablet' bus='usb'>` | Si un input PS/2 existe |
| Conversion SPICE -> VNC | Uniquement avec `--fix-spice-to-vnc` |
| Conversion QXL -> VGA | Uniquement avec `--fix-spice-to-vnc` |
| Suppression channels/audio SPICE | Uniquement avec `--fix-spice-to-vnc` |
| Pas de flatten backing chain | Jamais auto (signalé dans le rapport) |

Les correctifs guest (certificats, SmartScreen, proxy) sont signalés dans le rapport mais **jamais appliqués automatiquement** sans credentials.

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

## Key Checks
- [PASS|WARN] <commande> (rc=<N>) -> <fichier_json>

## VM Inventory
| Name | State | ID | vCPU | RAM | Machine | CPU Mode | Graphics | Video | Watchdog | Redirdev | Chain Depth |
|---|---|---|---|---|---|---|---|---|---|---|---|
| win10-cape | shut off | - | 4 | 4194304 | pc-q35-6.2 | host-passthrough | spice | qxl | reset | 2 | 3 |

## VM Device Analysis
### win10-cape: Risk Score 9 (HIGH)
| Device | Severity | Issue | Recommendation |
|---|---|---|---|
| redirdev[type=spicevmc] x2 | HIGH | 2 USB redir devices... | Remove all redirdev |
| watchdog[model=itco, action=reset] | HIGH | Can cause VM resets | Remove or action=none |
...

## Findings
### 1. STOPPED_BY_LIBVIRT: VM 'win10-cape' killed by libvirtd (HIGH)
**Indices** ...
**Causes probables** ...
**Actions correctives** ...

### 2. DEVICE_LINT: VM 'win10-cape' has 7 risky device(s) (HIGH)
...

## Recommended Next Steps
1. ...
```

### Archive `cape_triage_<hostname>_<timestamp>.tar.gz`

```
cape_triage_<timestamp>/
├── cape_doctor.log          # Log du script
├── report.md                # Rapport final
├── commands/                # Sorties JSON de chaque commande exécutée
│   ├── os_release.json
│   ├── uname.json
│   ├── svc_cape.json
│   ├── iptables_nat.json
│   ├── qemu_log_win10.json
│   ├── virsh_dumpxml_win10.json
│   ├── qemu_backing_chain_win10.json
│   └── ...
├── configs/                 # Copies masquées des fichiers de config
│   ├── CAPEv2_conf_cuckoo.conf
│   ├── CAPEv2_conf_routing.conf
│   ├── vm_win10-cape.xml
│   └── ...
├── logs/                    # Tails des logs collectés
│   ├── _var_log_cape_cuckoo.log.tail.log
│   ├── qemu_win10-cape.log
│   ├── vbox_0_VBox.log
│   └── ...
├── metadata/                # Données structurées
│   ├── environment.json
│   └── parsed_configs.json
└── guest/                   # Artefacts guest (si disponibles)
    ├── agent.log
    ├── analyzer.log
    └── winrm_system_events.txt
```

---

## Interprétation rapide du rapport

### Findings HIGH

Action immédiate requise. Bloquants probables.

- **"STOPPED_BY_LIBVIRT"** : La VM a été tuée par libvirtd (SIGTERM signal 15), pas un crash guest. Vérifier watchdog, OOM cgroup, ou libvirtd restart. Utiliser `--fix --fix-vm-xml` pour supprimer le watchdog.
- **"QEMU_MONITOR_LOST"** : libvirtd a perdu la connexion au monitor QEMU. Souvent causé par des devices SPICE/USB instables. Supprimer USB redirection et passer en VNC avec `--fix --fix-vm-xml --fix-spice-to-vnc`.
- **"DEVICE_LINT (HIGH)"** : La VM contient des devices à haut risque (USB redir, watchdog reset). Ces devices causent des instabilités avec les packages lourds (Chrome). Appliquer `--fix --fix-vm-xml`.
- **"VM process likely killed by OOM"** : Le processus qemu/VirtualBox a été tué par le kernel. Augmenter la RAM hôte, réduire la RAM VM, ajouter du swap, ou réduire le nombre d'analyses concurrentes.
- **"Potential routing/NAT breakage"** : La policy FORWARD est DROP sans règle MASQUERADE. Le guest n'a pas d'accès réseau sortant. Relancer avec `--fix` ou ajouter manuellement la règle NAT.
- **"Resultserver communication issue"** : Le resultserver n'est pas joignable depuis le guest. Vérifier que l'IP dans `routing.conf`/`machinery.conf` correspond à l'IP actuelle de l'hôte sur l'interface du réseau guest.
- **"Virtualization flags missing"** : VT-x ou AMD-V désactivé dans le BIOS/UEFI. Activer et redémarrer l'hôte.

### Findings MEDIUM

Facteurs aggravants ou causes secondaires.

- **"BACKING_CHAIN_DEPTH"** : La chaîne de snapshots qcow2 est trop profonde, ce qui dégrade les I/O et peut provoquer des timeouts. Planifier un flatten/commit (ne pas auto-exécuter).
- **"DEVICE_LINT (MEDIUM)"** : Devices SPICE/QXL détectés, inutiles en sandbox headless. Recommandation : passer en VNC/VGA.
- **"Potential browser crash from VirtualBox 3D/GPU acceleration"** : L'accélération 3D cause des crashs avec les navigateurs modernes dans VirtualBox. Désactiver via `--fix` ou manuellement avec `VBoxManage modifyvm <vm> --accelerate3d off`.
- **"IE marking all URLs may be policy/TLS/proxy artifact"** : Vérifier dans le guest : certificats racine (MITM proxy), paramètres SmartScreen/Defender, config proxy, zones de sécurité IE. Un DNS sinkhole ou proxy transparent peut renvoyer des block pages interprétées comme contenu malveillant par les signatures CAPE.
- **"Hypervisor not auto-detected"** : Installer les outils CLI (`virsh` ou `VBoxManage`) ou forcer avec `--hypervisor kvm|virtualbox`.
- **"WinRM collection requested but missing credentials"** : Fournir `--guest-host`, `--guest-user`, `--guest-password`.

### Findings LOW

- **"No obvious hard failure signatures"** : Aucune erreur bloquante détectée automatiquement. Le problème peut être intermittent ou spécifique au guest. Relancer une analyse unitaire avec le logging CAPE verbeux activé et collecter les Event Logs guest manuellement.

---

## Sécurité et confidentialité

- **Masquage automatique** : les IPs publiques sont remplacées par `x.x.x.x`, les mots de passe/tokens/secrets sont masqués (`***`) dans tous les artefacts de sortie.
- **Clés privées** : détectées et remplacées par `***PRIVATE_KEY_REDACTED***`.
- **IPs privées** : conservées telles quelles (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x).
- **Pas de stockage de secrets en clair** dans les fichiers de sortie.
- **Mode `--fix` non destructif** : chaque action est loggée, les commandes appliquées sont sauvegardées en JSON.
- **Backup XML avant modification** : le XML original est sauvegardé dans `/tmp/cape_doctor_backup_<vm>.xml` avant toute modification.

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
├── VMInfo (dataclass)           # Métadonnées VM (nom, état, vCPU, RAM, devices, disk)
├── DeviceIssue (dataclass)      # Problème device détecté (device, sévérité, message, score)
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
│   ├── # --- VM Diagnostics (libvirt/QEMU) ---
│   ├── _parse_virsh_list()             # Parse sortie virsh list --all
│   ├── _collect_qemu_log()             # Tail log QEMU par VM
│   ├── _check_stopped_by_libvirt()     # Détection STOPPED_BY_LIBVIRT
│   ├── _check_qemu_monitor_lost()      # Détection QEMU_MONITOR_LOST
│   ├── _parse_vm_xml()                 # Parse XML virsh dumpxml
│   ├── _lint_vm_xml()                  # Linting devices XML (risk score)
│   ├── _get_disk_path_from_xml()       # Extraction chemin disque principal
│   ├── _extract_vm_info_from_xml()     # Extraction métadonnées VM
│   ├── _check_backing_chain()          # Profondeur backing chain qcow2
│   ├── _fix_vm_xml()                   # Patch XML sandbox minimal
│   ├── diagnose_vms()                  # Orchestration diagnostic VM
│   │
│   ├── collect_resources_and_runtime_logs()  # RAM, disk, OOM, logs runtime
│   ├── collect_guest()          # Collecte passive + WinRM optionnel
│   │   └── _collect_winrm()     # Event Logs Windows via pywinrm
│   ├── correlate()              # Corrélation symptoms -> causes -> actions
│   ├── apply_fixes()            # Remédiations safe (si --fix)
│   ├── write_report()           # Génération report.md (+ VM inventory + device analysis)
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
 ├─ diagnose_vms()            # VM diagnostics (KVM uniquement)
 ├─ collect_resources_and_runtime_logs()
 ├─ collect_guest()
 ├─ correlate()
 ├─ apply_fixes()             # seulement si --fix
 ├─ write_report()            # -> report.md (avec VM Inventory + Device Analysis)
 ├─ create_archive()          # -> .tar.gz
 └─ print_summary()           # -> stdout
```

---

## Tests unitaires

Les tests couvrent toutes les fonctions de diagnostic VM :

```bash
pip install pytest
python3 -m pytest tests/test_vm_diagnostics.py -v
```

### Couverture des tests (31 tests)

| Module | Tests |
|---|---|
| `_parse_virsh_list` | Sortie normale, sortie vide, header seul |
| `_check_stopped_by_libvirt` | Signal 15 détecté, reason=destroyed, log propre, log vide |
| `_check_qemu_monitor_lost` | Monitor NULL, EOF error, journal propre, chaîne vide |
| `_lint_vm_xml` | VM SPICE complète, VM minimale, risk score, comptage redirdev, watchdog reset/none |
| `_get_disk_path_from_xml` | Disque trouvé, pas de disque, ignore cdrom |
| `_extract_vm_info_from_xml` | Tous les champs extraits |
| `_parse_vm_xml` | XML valide, XML invalide, chaîne vide |
| `_fix_vm_xml` | Suppression redirdev/watchdog, SPICE->VNC, VM minimale inchangée |
| `_check_backing_chain` | Chaîne profonde (5 images), image unique |
| Dataclasses | Valeurs par défaut VMInfo, DeviceIssue |

---

## Dépannage du script lui-même

| Problème | Cause | Solution |
|---|---|---|
| `Permission denied` sur iptables/dmesg | Script lancé sans `sudo` | Relancer avec `sudo python3 cape_doctor.py` |
| `pywinrm` manquant | Module non installé | `pip install pywinrm` (hors scope offline) |
| Aucun framework détecté | CAPE/Cuckoo installé dans un chemin non standard | Vérifier que `/opt/CAPEv2`, `/opt/CAPE` ou `~/.cuckoo` existe |
| `Hypervisor not auto-detected` | `virsh`/`VBoxManage` absent du PATH | Installer les outils ou forcer `--hypervisor kvm\|virtualbox` |
| Archive vide | Aucun artefact collecté (droits insuffisants) | Vérifier les permissions et relancer avec `sudo` |
| VM non diagnostiquée | `--vm-name` incorrect ou absent | Utiliser `--all-vms` ou vérifier le nom avec `virsh list --all` |
| Fix XML échoue | VM en cours d'exécution | Arrêter la VM avant le fix : `virsh shutdown <vm>` |

---

## Licence

Voir le dépôt pour les conditions de licence.
