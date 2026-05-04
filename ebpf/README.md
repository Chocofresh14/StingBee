# eBPF build & runtime

Ce dossier contient les programmes eBPF pour StingBee.

## Prérequis

- **clang/clang++** (pour compiler le C BPF en objet) : clang avec support de la cible BPF
- **libbpf** (optionnel à la compilation/exécution) pour les APIs libbpf en espace utilisateur
- **Noyau** : de préférence >= 5.8 pour le support du ring buffer ; le fallback perf map fonctionne sur les noyaux plus anciens (>= 4.9)

## Build rapide (CMake)

Le CMake racine tentera de compiler `ebpf/syscall_hook.bpf.c` en un fichier `.o` lors du build si `clang` est trouvé dans le PATH. Pour activer la liaison avec libbpf, installez `libbpf-dev` (headers) et le build ajoutera automatiquement une définition de compilation là où c'est pris en charge.

Paquets courants (Debian/Ubuntu) :

```bash
sudo apt install clang libbpf-dev llvm libelf-dev pkg-config bpftool
```

## Notes

- L'exécution du loader entièrement intégré nécessite des privilèges élevés (`CAP_SYS_ADMIN`) ou les permissions appropriées pour le chargement de programmes BPF.
- La CI peut nécessiter une image Docker avec la chaîne d'outils BPF.