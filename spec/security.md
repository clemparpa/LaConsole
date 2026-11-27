# Sécurité de la-console

## Modèle de menaces

La console est exposée à un **agent non fiable** : toute commande reçue peut
être adversariale. Objectifs : empêcher toute lecture/écriture hors du `root`,
empêcher toute exécution non whitelistée, empêcher la persistance de secrets
sur disque, et empêcher qu'une sortie contamine l'interprétation côté appelant.

## Confinement par path root

- Le `root` est résolu en chemin canonique **une seule fois** au démarrage
  (`std::fs::canonicalize`), puis toutes les opérations travaillent
  exclusivement avec des chemins relatifs au root.
- Toute résolution de chemin utilisateur passe par une fonction unique
  `resolve(root, input) -> Result<PathBuf, Denied>` qui :
  - rejette les chemins absolus (sauf s'ils sont sous le root canonique) ;
  - rejette tout segment `..` après normalisation logique (composants
    `ParentDir`) ;
  - **résout les symlinks** (`fs::canonicalize` sur le parent existant le plus
    proche, puis vérification que le résultat reste préfixe du root canonique) ;
  - rejette les hardlinks pointant hors du root (vérification via
    `st_dev`/`st_ino`, ou en refusant la création de liens et en ne suivant les
    liens existants qu'après canonicalisation) ;
  - rejette fail-closed les chemins absolus de style Windows sur **toutes**
    les plateformes (`platform::looks_like_windows_path`, cf.
    `spec/platform.md`) : drive letter `C:…`, préfixe UNC/verbatim `\\…`,
    et sur Windows tout `:` (NTFS ADS `file:stream`) ; sur unix, tout
    backslash est refusé (`\` n'y est jamais un séparateur) — sur Windows les
    chemins relatifs natifs `src\a.rs` restent valides ;
  - identité de fichier cross-OS via `platform.rs` : unix `st_dev`/`st_ino`/`nlink`,
    Windows volume serial + file index + `nNumberOfLinks` (`winapi-util` via
    `GetFileInformationByHandle`) — résiduel Windows : sur ReFS l'index de fichier
    64 bits n'est pas garanti unique.
- Règle d'or : **jamais de `Path::join` direct sur l'input utilisateur** sans
  passer par `resolve`. Aucune exception.

### Niveaux de confinement

- **v1 : logique pur Rust** (`resolve()` + canonicalize + tests d'évasion en CI),
  marche partout sans privilèges. Un bug dans `resolve()` = évasion totale, donc
  tests agressifs obligatoires.
- **v2 par plateforme ✅ livré — voir [platforms.md](platforms.md) et
  [sandbox-backend.md](sandbox-backend.md)** : backend
  de confinement OS par spawn, crate **`nono`** (nolabs-ai, Apache-2.0, épinglée
  `=0.79.0`) via une couche d'abstraction unique `src/sandbox_backend.rs` —
  Linux : **landlock** (noyau ≥ 5.13) ; macOS : **seatbelt** ; Windows : console
  lancée dans **WSL2** (v3 ; Windows natif reste fail-closed). Chaque commande
  trusted est spawnée via le helper arg0 `__sandbox_helper` (re-exec du binaire,
  profil JSON strict, sandbox appliqué juste avant exec, exit 125 → `denied`).
  Fail-closed : backend indisponible = `denied`, jamais de mode dégradé, aucun
  privilège requis. Le mode serveur (user namespace + chroot via `unshare`) a
  été **supprimé** (décision 2026-11-24) au profit de ce backend par spawn.
  **Scope v2 livré (décision 2026-11-27)** : FS (root RW, système RO) + exec
  (shell + PATH, landlock) par spawn et réseau `none` (défaut) ; `loopback`
  marche sur macOS et est refusé `denied` sur Linux (règles landlock par port,
  sans IP — §8 de la spec) ; `proxy`, `mem_bytes`, `max_write_bytes`, `cpus`
  et le lanceur WSL2 sont reportés à une v3 et restent `denied` fail-closed
  entre-temps.
- **✅ Décision v2 livrée : retrait des `ulimit`** du shell des commandes trusted —
  remplacés par les limites **par entrée** du manifeste TOML. En v2,
  `network = "none"` (défaut) est appliqué par le backend OS (`nono`,
  [sandbox-backend.md](sandbox-backend.md)) et `"loopback"` sur macOS ;
  `network = "proxy"`, `max_write_bytes`, `mem_bytes`, `cpus` restent refusés
  `denied` fail-closed (reportés v3, décision 2026-11-27), plus le timeout
  wall-clock + kill appliqués par la console elle-même
  (cf. [platforms.md](platforms.md) §4).
  Raison du retrait des `ulimit` : `ulimit -v` n'existe pas sur
  macOS et borne l'address space virtuel, pas la RSS réelle.

## Fichiers sensibles

- Déclarés par des regex (ex. `.*\.env`, `.*secret.*`, `\.git/config$`), une
  par ligne dans un fichier du dépôt de l'agent. Le matching se fait sur le
  **chemin relatif au root**. Le moteur `regex` est à temps linéaire : pas de
  ReDoS possible.
- Toute commande whitelist vers un chemin matchant est refusée ; toute commande
  trusted qui touche à un fichier matchant est soumise à un scan renforcé.

## Secrets

- La liste des secrets connus est fournie par l'opérateur via `--secrets-file <chemin>` : une ligne par secret, commentaires `#`, UTF-8 strict, fichier borné (1 MiO) et chargé au démarrage (illisible = exit 1, fail-closed).
- Les secrets (ex. token d'app Git) ne transitent **jamais** par l'env du shell
  de la console (une commande trusted pourrait faire `printenv`), ni en argument
  de ligne de commande (visible dans `ps`), ni dans un fichier lisible par
  l'agent.
- Toute occurrence d'un secret connu dans `stdout`/`stderr` est **masquée**
  (`***`) dans deux cas uniquement :
  1. avant l'envoi de la réponse JSON à l'appelant (sortie de la console) ;
  2. **avant toute écriture sur disque** dans le root (redirections `>`/`>>`,
     fichiers écrits par une commande) — un secret ne doit jamais être
     persisté.
- Pas de masquage dans les flux internes entre commandes (pipes), pour ne pas
  casser les chaînages légitimes.

## Vecteurs d'évasion prioritaires à tester

`..`, symlinks (créés avant/après canonicalize — race TOCTOU), chemins
absolus, unicode, trailing slashes, `//`, NUL bytes, hardlinks. Voir
[testing.md](testing.md) pour la stratégie de test associée.

## Bornes (à confirmer au fil du développement)

- profondeur max de `ls`, nb max d'entrées, taille max par fichier ;
- nb max de matchs de glob, quota disque du root ;
- timeout par commande, taille max de sortie (`max_output_bytes`).

## Principes

- **Fail-closed** : au doute, refuser.
- Une seule fonction de résolution de chemins, testée agressivement.
- Aucun `unsafe` en v1.
- Pas de dépendances réseau dans la console (sauf `http` whitelisté vers
  localhost, voir [commands.md](commands.md)).
