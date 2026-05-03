# StingBee

# Build

Pour compiler le projet, depuis la racine du dépôt :

```bash
mkdir -p build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Le binaire est ensuite disponible dans `build/stingbee`.

---

### Lancer les tests

On passe simplement `-DBUILD_TESTS=ON` au moment de la configuration, ce qui inclut automatiquement le dossier `tests/` dans la compilation :

```bash
mkdir -p build
cmake -S . -B build -DBUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Si un test échoue, `--output-on-failure` affiche directement le message d'erreur sans avoir à relancer quoi que ce soit.

---

### Utiliser clang à la place de gcc

Par défaut CMake choisit le compilateur disponible sur le système. Pour forcer clang, deux options :

Via les variables d'environnement :

```bash
export CC=clang
export CXX=clang++
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Ou directement dans la commande cmake :

```bash
cmake -S . -B build \
    -DCMAKE_C_COMPILER=/usr/bin/clang \
    -DCMAKE_CXX_COMPILER=/usr/bin/clang++ \
    -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Pour vérifier quel compilateur CMake a retenu :

```bash
cmake -S . -B build -LA -N | grep CMAKE_CXX_COMPILER
```

Si clang n'est pas encore installé :

```bash
sudo apt update && sudo apt install clang
```

---

### Dépendances optionnelles

CMake détecte automatiquement les bibliothèques présentes sur le système et les lie si elles sont disponibles : `libpcap`, `libyara`, `yaml-cpp`, `libaudit`, `libseccomp`. Il n'y a rien à faire manuellement si elles sont installées.

# Structure du projet

```
StingBee/
├── src/
│   ├── static_memory/
│   │   ├── yara_engine.cpp             # Scanning YARA (fichiers + mémoire)
│   │   ├── inotify_watcher.cpp         # Hooks inotify sur les accès fichiers
│   │   ├── procfs_reader.cpp           # Lecture /proc/PID/maps et /proc/PID/mem
│   │   ├── auditd_raw_collector.cpp    # Écoute des événements auditd
│   │   └── mem_scanner.cpp             # Scan mémoire des processus
│   │
│   ├── network_dpi/
│   │   ├── pcap_capture.cpp            # Capture paquets via libpcap
│   │   ├── ndpi_inspector.cpp          # Deep Packet Inspection via nDPI
│   │   ├── suricata_bridge.cpp         # Intégration Suricata / libhtp
│   │   ├── ioc_checker.cpp             # Appels VirusTotal / abuse.ch API
│   │   └── hash_utils.cpp              # MD5 / SHA256 via OpenSSL
│   │
│   ├── behavioral/
│   │   ├── ptrace_tracer.cpp           # Trace syscalls via ptrace
│   │   ├── ebpf_loader.cpp             # Chargement et gestion des programmes eBPF
│   │   ├── auditd_event_analyzer.cpp   # Monitoring événements via libaudit
│   │   ├── seccomp_filter.cpp          # Filtrage syscalls suspects via seccomp
│   │   └── syscall_analyzer.cpp        # Analyse comportementale des syscalls
│   │
│   ├── core/
│   │   ├── main.cpp                    # Point d'entrée, initialisation des modules
│   │   ├── event_bus.cpp/h             # Bus d'événements central (pub/sub)
│   │   ├── config_loader.cpp/h         # Chargement de la config
│   │   ├── logger.cpp/h                # Logger centralisé
│   │   └── thread_pool.cpp/h           # Pool de threads pour les modules
│   │
│   └── alerts/
│       ├── alert_manager.cpp/h         # Agrégation et déduplication des alertes
│       ├── alert_types.h               # Définition des types d'alertes
│       ├── severity.h                  # Niveaux de sévérité
│       ├── syslog_sink.cpp             # Export vers syslog
│       └── json_sink.cpp               # Export JSON (SIEM, API)
│
├── include/                            # Headers publics, miroir de src/
│   ├── static_memory/
│   ├── network_dpi/
│   └── behavioral/
│
├── tests/
│   ├── unit/                           # Tests unitaires (Google Test)
│   ├── integration/                    # Tests de bout en bout
│   └── mocks/                          # Faux pcap, faux /proc, etc.
│
├── rules/
│   ├── malware.yar
│   ├── ransomware.yar
│   ├── suricata.rules
│   └── ioc_lists/                      # IPs, domaines, hashs malveillants
│
├── ebpf/
│   ├── syscall_hook.bpf.c              # Programme BPF pour les syscalls
│   └── net_monitor.bpf.c               # Programme BPF réseau
│
├── config/
│   ├── edr.conf                        # Config principale
│   ├── thresholds.yaml                 # Seuils de détection
│   └── api_keys.env                    # Clés API (gitignorées)
│
├── scripts/
│   ├── build.sh
│   └── install_deps.sh
│
├── CMakeLists.txt
├── .clang-format
└── README.md
```