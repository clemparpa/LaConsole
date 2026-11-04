# Protocole externe de la-console

## Lancement

La console est un **sous-processus dédié** de l'appelant (le processus parent
qui la pilote). L'isolation par processus garantit qu'un crash de la console
(ex. lecture d'un très gros fichier) n'affecte pas l'appelant.

```
la-console --root <chemin> [--max-output-bytes N] [--timeout-secs N] [--trusted-file <chemin>] [--sensitives-file <chemin>]
```

- `--root` : répertoire racine du confinement, résolu en chemin canonique
  **une seule fois** au démarrage (`std::fs::canonicalize`).
- `--max-output-bytes` : borne de troncature des sorties (défaut raisonnable,
  ex. 1 Mo).
- `--timeout-secs` : timeout par commande (défaut ex. 30 s).
- `--trusted-file` : chemin du fichier de commandes trusted (voir
  [commands.md](commands.md)). Optionnel.
- `--sensitives-file` : chemin du fichier de regex de fichiers sensibles.
  Optionnel.

## Protocole de transport : ligne par ligne sur stdin/stdout

- **Entrée** : une ligne JSON par commande, sur l'entrée standard du processus :

  ```json
  {"op": "exec", "cmd": "ls src"}
  ```

- **Sortie** : exactement une ligne JSON en réponse, sur la sortie standard :

  ```json
  {"ok": true, "code": 0, "stdout": "...", "stderr": "", "truncated": false}
  ```

- En cas de refus (validation échouée) :

  ```json
  {"ok": false, "code": 2, "stdout": "", "stderr": "denied: path escapes root", "truncated": false}
  ```

Règles :

- Le format **JSON structuré** est choisi pour séparer explicitement les
  métadonnées (succès/échec, code de retour) du contenu, et réduire le risque
  d'injection dans l'interprétation de la sortie par l'appelant.
- La console est **stateless** : chaque commande repart du `root`, il n'y a pas
  de `cd` persistant en v1.
- Le stdin du processus appartient au protocole et n'est **jamais** lu par une
  commande exécutée.
- Deux canaux de sortie distincts à l'intérieur de la console : le **flux brut**
  uniquement entre commandes chaînées (pipes/redirections internes), le **JSON**
  uniquement vers l'extérieur (stdout du processus, donc vers l'appelant).
