#!/bin/zsh

# Prüfen, ob ein Pfad übergeben wurde
if [ -z "$1" ]; then
    echo "Fehler: Bitte gib den Pfad zum Zielordner an."
    echo "Beispiel: $0 /pfad/zum/ordner"
    exit 1
fi

# Eingabe: Basisordner
BASE_PATH="$1"

# Prüfen, ob gültiger Ordner
if [ ! -d "$BASE_PATH" ]; then
    echo "Fehler: '$BASE_PATH' ist kein gültiger Ordner."
    exit 1
fi

echo "Suche nach Dateien, die mit '~' enden (einschließlich versteckter Dateien)..."
echo "Ordner: $BASE_PATH"

# Alle Dateien mit Tilde am Ende löschen (z. B. file~, .file~, .bashrc~, test.txt~, .test.conf~)
find "$BASE_PATH" -type f -name "*~" -print0 | while IFS= read -r -d '' file; do
    echo "Entferne Datei: $file"
    rm -f "$file"
done

echo "Bereinigung abgeschlossen."

