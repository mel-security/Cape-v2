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
sudo python3 cape_doctor.py --fix
```

En plus de la collecte, applique les correctifs safe :
- Active `net.ipv4.ip_forward`
- Ajoute la règle `MASQUERADE` si absente
- Corrige les permissions des répertoires de logs CAPE/Cuckoo
- Relance les services CAPE/Cuckoo et libvirtd
- Désactive l'accélération 3D VirtualBox (si hypervisor=virtualbox et `--vm-name` fourni)

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

#### Ressources et runtime

- RAM libre, swap, disque (`df -h`)
- Erreurs I/O, OOM killer (dmesg, journald)
- Logs CAPE/Cuckoo (`/var/log/cape/*`, `/var/log/cuckoo/*`, `~/.cuckoo/log/*`)

### B. Checks guest (VM Windows)

#### Collecte passive (sans credentials)

- Logs agent/analyzer si partagés sur le filesystem hôte : `agent.log`, `analyzer.log`, `*browser*.log`
- Crash dumps (`.dmp`) dans les répertoires d'analyses

#### Collecte WinRM (`--guest-creds=winrm`)

- Event Logs System (200 dernières entrées)
- Erreurs applicatives (navigateurs, BSOD, bugcheck)

### C. Corrélation et diagnostics

Le script analyse l'ensemble du corpus collecté et détecte automatiquement :

| Symptôme | Causes probables détectées |
|---|---|
| VM crash avec navigateur moderne | OOM kill du process qemu/VirtualBox, accélération 3D VirtualBox instable, manque de RAM guest/hôte |
| IE marque toutes les URLs malveillantes | Erreurs TLS/cert (MITM), DNS sinkhole, proxy renvoyant block page, SmartScreen/Defender actif, scoring CAPE trop agressif |
| Agent/resultserver non joignable | Mismatch IP resultserver (après changement IP hôte), FORWARD DROP sans MASQUERADE, firewall |
| VM non démarrable | Flags VT-x/AMD-V absents, erreurs hyperviseur, EPT/invalid opcode |

### D. Remédiations (`--fix`)

Toutes les actions sont loggées. Seuls les correctifs safe sont appliqués :

| Action | Condition |
|---|---|
| `sysctl -w net.ipv4.ip_forward=1` | Toujours |
| Ajout règle `MASQUERADE` sur interface par défaut | Si absente |
| `chmod -R u+rwX` sur répertoires de logs | Si existent |
| `systemctl restart` des services CAPE/libvirt | Si systemd détecté |
| `VBoxManage modifyvm --accelerate3d off` | Si hypervisor=virtualbox et `--vm-name` fourni |

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
├── commands/                # Sorties JSON de chaque commande exécutée
│   ├── os_release.json
│   ├── uname.json
│   ├── svc_cape.json
│   ├── iptables_nat.json
│   └── ...
├── configs/                 # Copies masquées des fichiers de config
│   ├── CAPEv2_conf_cuckoo.conf
│   ├── CAPEv2_conf_routing.conf
│   └── ...
├── logs/                    # Tails des logs collectés
│   ├── _var_log_cape_cuckoo.log.tail.log
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

- **"VM process likely killed by OOM"** : Le processus qemu/VirtualBox a été tué par le kernel. Augmenter la RAM hôte, réduire la RAM VM, ajouter du swap, ou réduire le nombre d'analyses concurrentes.
- **"Potential routing/NAT breakage"** : La policy FORWARD est DROP sans règle MASQUERADE. Le guest n'a pas d'accès réseau sortant. Relancer avec `--fix` ou ajouter manuellement la règle NAT.
- **"Resultserver communication issue"** : Le resultserver n'est pas joignable depuis le guest. Vérifier que l'IP dans `routing.conf`/`machinery.conf` correspond à l'IP actuelle de l'hôte sur l'interface du réseau guest.
- **"Virtualization flags missing"** : VT-x ou AMD-V désactivé dans le BIOS/UEFI. Activer et redémarrer l'hôte.

### Findings MEDIUM

Facteurs aggravants ou causes secondaires.

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
│   ├── collect_resources_and_runtime_logs()  # RAM, disk, OOM, logs runtime
│   ├── collect_guest()          # Collecte passive + WinRM optionnel
│   │   └── _collect_winrm()     # Event Logs Windows via pywinrm
│   ├── correlate()              # Corrélation symptoms -> causes -> actions
│   ├── apply_fixes()            # Remédiations safe (si --fix)
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
 ├─ collect_resources_and_runtime_logs()
 ├─ collect_guest()
 ├─ correlate()
 ├─ apply_fixes()          # seulement si --fix
 ├─ write_report()         # -> report.md
 ├─ create_archive()       # -> .tar.gz
 └─ print_summary()        # -> stdout
```

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

## deploy_minimal.py

Script all-in-one pour déployer une VM "windows-minimal" sur QEMU/KVM + libvirt, destinée à CAPEv2, à partir d'une installation existante.

### Principe

Le script clone la VM existante (`window`) en une nouvelle VM `windows-minimal` avec un profil libvirt nettoyé (sans watchdog, sans redirdev USB, sans tablet input), crée deux overlays qcow2 (base + chrome), et met à jour `kvm.conf` pour que CAPE utilise la nouvelle VM.

**Zéro impact** : la VM source, ses snapshots, et le réseau libvirt ne sont jamais modifiés.

### Prérequis

- **Root / sudo** requis
- QEMU/KVM + libvirt installés et fonctionnels
- Au moins une VM Windows existante définie dans libvirt (par défaut `window`)
- Espace disque suffisant dans `/var/lib/libvirt/images/` (taille de la VM source x1.5 environ)

### Usage

```bash
# Déploiement normal
sudo python3 deploy_minimal.py

# Prévisualisation (aucune modification)
sudo python3 deploy_minimal.py --dry-run

# Si "windows-minimal" existe déjà, suffixer automatiquement
sudo python3 deploy_minimal.py --force

# Déployer la VM sans modifier kvm.conf
sudo python3 deploy_minimal.py --no-kvmconf
```

### Options

| Option | Description |
|---|---|
| `--dry-run` | Affiche toutes les opérations sans rien exécuter |
| `--force` | Si le domaine `windows-minimal` existe, utilise un suffixe horodaté |
| `--no-kvmconf` | Ne pas modifier `/opt/CAPEv2/conf/kvm.conf` |

### Ce que fait le script

1. **Détection** : identifie la VM source (préfère `window`) et son disque principal
2. **Base image** : `qemu-img convert` du disque source -> `windows-minimal.base.qcow2` (clone complet, pas de backing chain)
3. **Chrome overlay** : `qemu-img create` overlay `windows-minimal.chrome.qcow2` <- `windows-minimal.base.qcow2`
4. **Domaine libvirt** : génère un XML nettoyé (sans watchdog, redirdev, tablet USB) et `virsh define`
5. **Snapshot libvirt** : crée un snapshot `windows-minimal_chrome` pour le revert CAPE
6. **kvm.conf** : remplace `window` -> `windows-minimal`, `snapshot11` -> `windows-minimal_chrome`
7. **Vérification** : contrôle l'intégrité de la VM source, la propreté du XML, la profondeur de chain

### Modifications kvm.conf

Le script modifie le fichier en place avec backup atomique :

- `machines = window` -> `machines = windows-minimal`
- `[window]` -> `[windows-minimal]`
- `label = window` -> `label = windows-minimal`
- `snapshot = snapshot11` -> `snapshot = windows-minimal_chrome`
- Backup : `/opt/CAPEv2/conf/kvm.conf.bak.<timestamp>`

Les autres valeurs (platform, arch, interface, ip, tags) sont préservées telles quelles.

### Rollback

Pour revenir à l'état initial :

```bash
# 1. Restaurer kvm.conf
sudo cp /opt/CAPEv2/conf/kvm.conf.bak.<TIMESTAMP> /opt/CAPEv2/conf/kvm.conf

# 2. Supprimer le domaine
sudo virsh undefine windows-minimal

# 3. (Optionnel) Supprimer les images créées
sudo rm -f /var/lib/libvirt/images/windows-minimal.base.qcow2
sudo rm -f /var/lib/libvirt/images/windows-minimal.chrome.qcow2
```

### Log

Le script produit un rapport complet dans `/tmp/windows-minimal-deploy.<timestamp>.log` et sur stdout.

---

## Licence

Voir le dépôt pour les conditions de licence.
