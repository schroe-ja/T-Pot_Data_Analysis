#!/bin/bash

# Prüfen, ob ein Ordner angegeben wurde
if [ -z "$1" ]; then
    echo "Verwendung: $0 <Pfad-zum-Ordner>"
    exit 1
fi

# Ordnerpfad
FOLDER="$1"

# Prüfen, ob Ordner existiert
if [ ! -d "$FOLDER" ]; then
    echo "Fehler: Ordner '$FOLDER' existiert nicht."
    exit 1
fi

echo "Dateitypen im Verzeichnis '$FOLDER':"
echo

# Typen zählen (nicht rekursiv, nur reguläre Dateien)
for file in "$FOLDER"/*; do
    if [ -f "$file" ]; then
        file -b "$file" | cut -d',' -f1
    fi
done | sort | uniq -c | sort -nr

