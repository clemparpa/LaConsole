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
    liens existants qu'après canonicalisation).
- Règle d'or : **jamais de `Path::join` direct sur l'input utilisateur** sans
  passer par `resolve`. Aucune exception.

### Niveaux de confinement

- **v1 : logique pur Rust** (`resolve()` + canonicalize + tests d'évasion en CI),
  marche partout sans privilèges. Un bug dans `resolve()` = évasion totale, donc
  tests agressifs obligatoires.
- **v2 (déploiement serveur) : `--mode server`, Linux uniquement** — user namespace
  non privilégié + chroot par-dessus (defense in depth : le noyau bloque même
  en cas de bug applicatif). Le binaire se re-exec lui-même via
  `unshare --user --map-root-user --mount --root <root> --wd /` (le binaire et
  ses dépendances dynamiques sont d'abord copiés dans la cage, puis nettoyés
  au démarrage ; un binaire statique n'en a pas besoin). L'API reste identique,
  seul le lanceur change : dans la cage, `--root /`. Jamais de root global au
  lancement. Sur macOS/autre, `--mode server` est refusé (exit 2) et `--mode user`
  reste le défaut.
  - **Déploiement** : lancer la console comme l'utilisateur propriétaire du
    `root` (les permissions Unix/DAC s'appliquent toujours dans le user
    namespace : un fichier appartenant à un autre utilisateur reste illisible,
    même dans la cage). Ne jamais lancer en root global.
  - **Mini-image de cage (v2 étape 2)** : l'opérateur peut équiper la cage via
    `--sandbox-busybox <PATH>` (busybox **statique**, vérifié ELF + `ldd`,
    épinglable par `--sandbox-busybox-sha256`) et `--sandbox-tools-dir <DIR>`
    (outillage ex. git + go, copié en `/opt/la-console-tools` avec les deps
    dynamiques de chaque ELF). Le busybox est placé en `/bin/busybox` avec un
    symlink par applet dans `/bin`. Au démarrage dans la cage, `/bin`,
    `/opt/la-console-tools` et le dossier de libs stagées sont remountés
    **read-only** (bind + remount,ro via l'applet `mount` de busybox, possible
    car le processus est root dans son propre user namespace) pour empêcher
    l'agent d'écraser un outil via une écriture whitelist (tout le contenu du
    chroot est sinon accessible en écriture sous le root). **Fail-closed** :
    si un remount échoue, la console refuse de démarrer (exit 2) — une image de
    cage accessible en écriture n'est pas un déploiement acceptable.
  - **Commandes trusted en mode serveur** : avec un busybox stagé, `trusted`
    s'exécute via `<busybox> sh -c` (`PATH` cage, `HOME=/tmp`, `GOROOT` détecté
    si présent, limites `ulimit` identiques au mode user). **Sans busybox
    stagé, `trusted` reste `denied` (fail-closed)** et seules les commandes
    whitelistées tournent en mode serveur.
  - **Réseau** : la cage partage le namespace réseau de l'hôte (pas de
    `--net`) pour garder la commande `http` vers localhost ; une commande
    trusted peut donc joindre le réseau, comme en mode user — le périmètre
    reste le chroot, pas le réseau.

## Fichiers sensibles

- Déclarés par des regex (ex. `.*\.env`, `.*secret.*`, `\.git/config$`), une
  par ligne dans un fichier du dépôt de l'agent. Le matching se fait sur le
  **chemin relatif au root**. Le moteur `regex` est à temps linéaire : pas de
  ReDoS possible.
- Toute commande whitelist vers un chemin matchant est refusée ; toute commande
  trusted qui touche à un fichier matchant est soumise à un scan renforcé.

## Secrets

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
