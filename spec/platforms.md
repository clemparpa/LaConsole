# Plateformes — plan macOS / Windows (brouillon v2)

> Statut : **brouillon soumis à revue**. Objectif : sortir du « Linux-only »
> implicite du code v1 et définir le **backend de confinement OS par
> plateforme** : **macOS = Seatbelt**, **Windows = WSL2**, **Linux = landlock
> par spawn** — tous couverts par la crate **`nono`** (décision actée
> 2026-11-24, §3). La cage userns+chroot du mode serveur a été **supprimée**
> (décision 2026-11-24).
> Principes inchangés : fail-closed, aucun privilège requis,
> `#![forbid(unsafe_code)]` intact, la console applique elle-même validation,
> limites et kill (jamais délégué au harnais), et chaque plateforme ajoutée =
> nouvelle surface d'attaque à auditer.

## 1. Pourquoi un backend OS par plateforme

La couche applicative (`resolve()` + sensibles + sinks + bornes) reste la
barrière principale, portable. Le backend OS ajoute la **defense in depth** :
même un bug dans `resolve()` ou le parser reste bloqué par l'OS.

| Plateforme | Mode user (poste dev) | Déploiement serveur |
|---|---|---|
| Linux | pur Rust + landlock par spawn (via nono) | idem (landlock par spawn, noyau ≥ 5.13) |
| macOS | pur Rust + **seatbelt** sur la console et/ou par spawn (`sandbox-exec`, via nono) | idem (pas de userns sur macOS ; seatbelt est l'équivalent) |
| Windows | la console tourne **dans WSL2** (VM utilitaire, via nono) | idem (la WSL2 *est* la cage) |

## 2. Couche d'abstraction plateforme (`platform.rs`, prévu)

> La spécification détaillée de la **phase 1** (inventaire par OS, API de
> `platform.rs`, mapping du code existant, stratégie de tests, CI Windows,
> fail-closed sur Windows natif) est dans [platform.md](platform.md).

Un seul module connaît l'OS ; le reste du code passe par des traits :

- `fs_primitives` : canonicalize (std), détection des hardlinks hors root
  (`st_dev`/`st_ino` via `std::os::unix` aujourd'hui → équivalent Windows :
  index de fichier), symlinks dans les tests (`#[cfg(any(target_os = "macos", target_os = "linux"))]` aujourd'hui) ;
- `process` : spawn du shell + application des limites = backend (section 3) ;
- `exit_code` : `128+signal` via `std::os::unix` aujourd'hui → version
  Windows (code de sortie natif, pas de signaux).

Inventaire du code unix (macOS/Linux) spécifique à abstraire :

- `resolve.rs` : `std::os::unix::fs::MetadataExt` (`st_dev`/`st_ino`) ;
- `trusted.rs` : `SHELL = /bin/sh`, script `ulimit` (retiré), `ExitStatusExt` ;
- tests : `std::os::unix::fs::symlink`, `PermissionsExt`.

## 3. Backends de confinement par spawn (trusted / plugins)

Chaque sous-processus est spawné via le helper arg0 (déjà prévu dans
[plugins.md](plugins.md)) : `la-console __sandbox_helper <profil.json> -- <cmd…>`
qui applique le confinement **dans l'enfant, juste avant exec**. Le profil est
généré depuis l'entrée TOML (`trusted.toml`) + les `Limits` globaux.

> ✅ **Décision actée (2026-11-24)** : le backend retenu est la crate **`nono`**
> (nolabs-ai, Apache-2.0 — Landlock sur Linux ≥ 5.13, Seatbelt sur macOS, WSL2
> pour Windows), épinglée à une version exacte et auditée avant chaque bump.
> Toute référence à `nono::` vit dans une **couche d'abstraction unique**
> (`src/sandbox_backend.rs` : `apply(profile) -> Result<(), denied>` +
> `support_info()`), de sorte qu'un breaking change de nono (pre-1.0) ne touche
> qu'un seul fichier. Fail-closed : backend non supporté (noyau < 5.13, ABI
> Landlock réseau < v4, pas de Seatbelt) → `denied`. **Reste chez nous** : proxy
> réseau fin (allowlist de domaines + anti-DNS-rebinding), limites
> `mem_bytes`/`cpus`/`max_write_bytes` (rlimits `nix` dans le helper — non
> couvert par nono hors cgroups Linux), lanceur WSL2 (`wsl.exe` ; Windows natif
> fail-closed, nono tourne dans WSL2), timeout + kill du groupe (`platform.rs`,
> inchangé).

- **macOS — Seatbelt** : profil SBPL généré + `sandbox-exec -p "<profil>"`
  (API publique, spawn de binaire, zéro FFI/`unsafe` chez nous). Règles :
  fichiers allow = root + répertoires d'écriture déclarés ; `(deny network*)`
  ou loopback seul vers un proxy à allowlist ; deny devices. Seatbelt est un
  **filtre de syscalls** (même noyau, pas une VM) : il bloque les accès
  applicatifs, pas un 0-day noyau — la couche app reste la barrière fine.
  Hérité par les enfants après exec. Granularité réseau grossière (allow/deny,
  éventuellement restreint à la loopback).
- **Linux — Landlock** : via la crate `nono` dans le helper (Landlock ≥ 5.13,
  ABI réseau ≥ v4 ; sinon `denied` fail-closed). La cage userns+chroot du mode
  serveur a été supprimée (décision 2026-11-24) : landlock par spawn est le
  backend retenu.
- **Windows — WSL2** : la console entière tourne dans la WSL2 (utility VM
  Hyper-V : noyau Linux dédié, disque ext4 en VHD, réseau NAT) — même patron
  que le mode serveur Linux (`wsl.exe` lance la console avec le root monté).
  Ce que la WSL2 ferme : **tout accès direct au host Windows** (processus,
  mémoire, registre, noyau) — s'en échapper demande un exploit de VM-escape.
  **Ponts à désactiver/restreindre sauf déclaration explicite** (chacun est une
  surface d'attaque à auditer) : interop Windows (lancer des `.exe` depuis
  WSL2), montages `/mnt/c` (drvfs vers le disque host), réseau (NAT sortant +
  `localhostForwarding`), socket docker (backend Docker Desktop WSL2 : le
  daemon tourne dans sa propre VM `docker-desktop`, le CLI dans WSL2 y parle
  via un socket proxy).
- **Fail-closed par spawn** : backend inapplicable → `denied`, jamais de mode
  dégradé. Aucun privilège requis (jamais de root).

## 4. Retrait des `ulimit` (décision liée)

Le script shell des commandes trusted (`ulimit -v/-t/-f` dans `trusted.rs`)
est **retiré** ✅ (livré avec le manifeste `trusted.toml`) : le shell exécute
`{command} "$@"` tel quel, et la console applique le timeout wall-clock + le
kill du **groupe de processus** (`process_group(0)` + kill du pgid).

- `ulimit -v` (RLIMIT_AS) **n'existe pas sur macOS/BSD** (best-effort silencieux
  aujourd'hui) ;
- `-v` borne l'**address space virtuel**, pas la RSS réelle — Node/V8 en
  réservent énormément, donc un plafond `-v` de 1 GiO tue `npm test:e2e` bien
  en dessous de sa consommation réelle.

Les limites deviennent :

- **côté console** : timeout wall-clock + kill du fils (déjà en place,
  `run_with_timeout` + `run_child`) ;
- **par entrée TOML** : `timeout_secs`, `max_write_bytes`, `mem_bytes`,
  `cpus`, `network` (voir [plugins.md](plugins.md)) → traduites dans le profil
  du backend (seatbelt / landlock / limites VM WSL2, cgroups délégués si
  disponibles) ;
- **écritures disque des commandes whitelist** : inchangé (`FileSink` +
  `DiskQuota` partagés).

Conséquence honnête : sans `ulimit`, le quota disque d'un sous-processus
arbitraire ne peut pas être borné en pur userspace sur toutes les plateformes —
il est imposé par le backend (FS deny hors root + répertoires d'écriture
déclarés, disque VHD borné en WSL2). Une entrée qui déclare des limites sans
backend disponible = `denied` (fail-closed) — **règle déjà en vigueur** :
`max_write_bytes`/`mem_bytes`/`cpus`/`network` déclarés dans `trusted.toml`
sont refusés à l'exécution tant que ce chapitre (backends) n'est pas livré.

## 5. Phases proposées

1. `platform.rs` + abstraction des primitives (resolve, exit code, tests) ;
2. manifeste `trusted.toml` (voir [plugins.md](plugins.md)) + retrait des
   `ulimit`, limites par entrée appliquées par le backend ;
3. backend macOS seatbelt (helper arg0 + profils SBPL générés) ;
4. backend Windows WSL2 (console lancée dans la VM, ponts désactivés sauf
   déclarés) ;
5. commandes `git` whitelist read-only (voir [commands.md](commands.md)).

Chaque phase = une PR indépendante, testable, CI verte (cf. `ROADMAP.md`).
