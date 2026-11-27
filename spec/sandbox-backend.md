# Backend de confinement OS par spawn — plan d'implémentation (`nono`)

> Statut : **plan soumis à revue** (décisions 2026-11-24 et 2026-11-27, voir
> `docs/etat-des-lieux-2026-11-24.md` décisions 3 et 4). Le backend retenu est
> la crate **`nono`** (nolabs-ai, Apache-2.0 — Landlock Linux ≥ 5.13, Seatbelt
> macOS, WSL2), derrière une **couche d'abstraction unique**
> `src/sandbox_backend.rs`. Principes inchangés : fail-closed, aucun privilège
> requis, `#![forbid(unsafe_code)]` intact, la console applique elle-même
> validation, limites et kill (jamais délégués au harnais), et chaque
> plateforme ajoutée est une surface d'attaque à auditer.

## 1. Scope retenu — et ce qui est reporté (décision 2026-11-27)

| Élément | v2 (cette intégration, une PR) | v3 (reporté) |
|---|---|---|
| Confinement FS + exec par spawn (landlock / seatbelt / WSL2) | ✅ via `nono` | |
| Réseau `none` (défaut) / `loopback` | ✅ via `nono` | |
| `network = "proxy"` (allowlist de domaines + anti-DNS-rebinding) | ❌ reste `denied` | ✅ candidat v3 |
| `mem_bytes` | ❌ reste `denied` | ✅ candidat v3 (rlimits `nix` / cgroups) |
| `max_write_bytes` (quota d'écriture disque) | ❌ reste `denied` | ✅ candidat v3 |
| `cpus` | ❌ reste `denied` | ✅ candidat v3 (RLIMIT_CPU / cgroups) |
| Lanceur WSL2 (`wsl.exe`) | ❌ Windows natif reste fail-closed | ✅ candidat v3 |
| Timeout wall-clock + kill du groupe de processus | ✅ déjà en place, appliqué par la console (`platform.rs`) | inchangé |

**Raisonnement du descoping** (décision PM 2026-11-27) : l'agent est borné par
son nombre de tours max ; un proxy réseau à allowlist de domaines et des
quotas mémoire/CPU/écriture fins coûtent cher (DNS-rebinding, tokio,
rlimits/cgroups) pour un gain faible en v2. Les quatre champs correspondants
restent **parsés** dans `trusted.toml` mais **refusés `denied` fail-closed à
l'exécution** tant qu'ils ne sont pas livrés — aucun mode dégradé, aucun flag
pour désactiver le sandbox.

## 2. Architecture

- **Dépendance** : `nono` épinglée à une version exacte (`=0.79.x`) dans
  `Cargo.toml`, `Cargo.lock` committé, `cargo deny` + `cargo audit` dans la
  CI, revue du diff avant chaque bump (nono est pré-1.0).
- **Couche unique** : `src/sandbox_backend.rs` est le **seul** module qui
  référence `nono::` — API : `apply(profile: &SandboxProfile) -> Result<(), Denied>`
  + `support_info() -> SupportInfo`. Un breaking change de nono ne touche que
  ce fichier.
- **Helper arg0** : chaque sous-processus trusted est spawné via le re-exec de
  notre propre binaire : `la-console __sandbox_helper <profil.json> -- <cmd…>`
  (`std::env::current_exe()`). L'enfant lit le profil, applique le sandbox
  **juste avant exec** (`Sandbox::apply_auto(&CapabilitySet)`), puis exec.
  Le sandbox n'est **jamais** appliqué dans le harness (qui garde l'accès aux
  manifestes et au stdio). Aucun flag CLI ne permet de désactiver le sandbox.
- Le **profil** est un fichier JSON généré par la console depuis l'entrée
  `trusted.toml` + les `Limits` globaux. Il ne contient **aucun secret**
  (chemins et mode réseau uniquement — jamais de secret, jamais d'env).
- Le reste de l'exécution est inchangé : `cwd = root`, env réduit (`HOME` hors
  du root via `tempfile`), stdin `null`, args passés en `"$@"`, timeout +
  kill du groupe par la console.

## 3. Profil JSON (schéma strict, `deny_unknown_fields`, lecture bornée)

```json
{
  "version": 1,
  "root": "/abs/canonique/du/root",
  "network": "none"
}
```

(`"network"`: `"none"` | `"loopback"` — défaut `"none"`.)

Mapping vers `CapabilitySet`, fait **uniquement** dans `sandbox_backend.rs` :

- `allow_path(root, ReadWrite)` — écriture confinée au root ;
- chemins système en lecture seule (`/usr`, `/bin`, `/lib`, `/etc`… plus le
  strict nécessaire au shell et au toolchain ; macOS : `/usr/lib`, cache dyld,
  `/dev/null`, `/private/tmp`…) — liste centralisée dans `sandbox_backend.rs`
  et testée sur la matrice CI ;
- `allow_execute` sur le shell (`platform::shell()`) et les binaires du
  `PATH` réduit ;
- `network = "none"` → `block_network()` ; `"loopback"` → loopback seule
  (Linux : ABI Landlock réseau ≥ v4 requis, sinon `denied` fail-closed).

## 4. Matrice d'application des champs de `trusted.toml`

| Champ | Appliqué par | v2 |
|---|---|---|
| `command`, `flags`, args de chemin (`no_path_check`) | la console (parse + `resolve()` + sensibles) | inchangé |
| `timeout_secs` | la console : wall-clock + kill du groupe de processus | inchangé |
| checksum sha256 du manifeste | la console, re-vérifié avant chaque exécution | inchangé |
| `network = "none"` / `"loopback"` | le backend OS via nono | ✅ v2 |
| `network` non déclaré | défaut **`none`** dès que le backend existe (avant : comportement v1, réseau joignable) | ✅ v2 |
| `network = "proxy"`, `mem_bytes`, `max_write_bytes`, `cpus` | — | ❌ `denied` fail-closed, reportés v3 |

## 5. Fail-closed

- Backend indisponible (noyau < 5.13, ABI Landlock réseau < v4, pas de
  Seatbelt, Windows natif) → `denied`, jamais de mode dégradé, aucun
  privilège requis.
- Entrée `trusted.toml` déclarant `proxy` / `mem_bytes` / `max_write_bytes` /
  `cpus` → `denied` à l'exécution, avec la raison explicite (champ + « reporté
  v3 »).
- Échec du parse du profil ou de `apply` dans l'enfant → exit code dédié →
  le parent rend `denied` (jamais d'exec sans sandbox).

## 6. Tests et CI

- **Unitaires** : parsing strict du profil (champs inconnus refusés, lecture
  bornée), mapping profil → `CapabilitySet`, `support_info()` par plateforme,
  `backend_limit()` ne refuse plus que les 4 champs reportés v3.
- **e2e** (matrice CI ubuntu + macOS ; windows natif fail-closed) :
  `trusted` écrivant hors du root → refusé par l'OS ; `network = "none"` →
  connexion sortante échoue ; `loopback` → localhost OK, externe refusé ;
  commande trusted usuelle (`echo`, `ls`, `cargo --version`) fonctionne
  sandboxée ; backend simulé indisponible → `denied` ; entrée déclarant
  `mem_bytes` → `denied` avec raison explicite.
- **Proptest** : le profil généré ne contient jamais de champ inconnu ni de
  secret.
- **CI** : `cargo test` matrice 3 OS inchangée ; `cargo deny` + `cargo audit`
  couvrent la nouvelle dépendance. Pas de cible fuzz nouvelle (pas de parsing
  `unsafe` complexe).

## 7. Phases (une PR indépendante, testable, CI verte chacune)

1. **PR « backend nono » (toute la v2)** : dépendance épinglée + audit,
   `src/sandbox_backend.rs`, helper `__sandbox_helper`, spawn des commandes
   trusted via le helper (sandbox FS + réseau `none`/`loopback`), levée de la
   dénégation `network` pour `none`/`loopback` uniquement, tests ci-dessus,
   docs à jour (`ROADMAP.md`, `spec/`, `docs/`).
2. **v3 (candidats, hors de cette PR)** : `network = "proxy"` (proxy à
   allowlist de domaines + anti-DNS-rebinding 169.254.0.0/16),
   `mem_bytes` / `max_write_bytes` / `cpus` (rlimits `nix` ou cgroups Linux),
   lanceur WSL2 (`wsl.exe`), manifeste `plugins.json` / `plugins.rs`.
