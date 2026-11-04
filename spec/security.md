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
- **v2 (déploiement serveur) : user namespace non privilégié + chroot** par-dessus
  (defense in depth : le noyau bloque même en cas de bug applicatif).
  L'API reste identique, seul le lanceur change. Jamais de root global au
  lancement.

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
