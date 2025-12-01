#!/bin/zsh

# Eingabeparameter: Ordner, der gesichert werden soll
target_folder="$1"

# Überprüfen, ob Ordner angegeben wurde
if [[ -z "$target_folder" ]]; then
  echo "Fehler: Bitte gib einen Ordner an."
  echo "Beispiel: ./remove_exec_rights.sh /pfad/zum/ordner"
  exit 1
fi

# Absoluten Pfad auflösen
target_folder="$(realpath "$target_folder")"

# Suche alle regulären Dateien und entferne Ausführungsrechte
echo "🔍 Entferne Ausführungsrechte für alle Dateien in $target_folder ..."
find "$target_folder" -type f -exec chmod a-x {} \;

echo "Alle Dateien sind jetzt nicht mehr ausführbar."

