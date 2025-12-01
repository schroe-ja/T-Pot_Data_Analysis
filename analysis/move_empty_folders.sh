#!/bin/zsh

# Prüfen, ob ein Pfad übergeben wurde
if [ -z "$1" ]; then
    echo "Fehler: Bitte gib den Pfad zu Ordner A als Argument an."
    echo "Beispiel: $0 /pfad/zum/A"
    exit 1
fi

# Eingabe: Ordner A
A_PATH="$1"

# Prüfen, ob A_PATH ein gültiger Ordner ist
if [ ! -d "$A_PATH" ]; then
    echo "Fehler: '$A_PATH' ist kein gültiger Ordner."
    exit 1
fi

# Name von Ordner A extrahieren
A_NAME=$(basename "$A_PATH")

# Zielordner: "empty_<Ordnername>" auf gleicher Ebene wie A
EMPTY_PATH="$(dirname "$A_PATH")/empty_$A_NAME"

# Zielordner anlegen, falls nicht vorhanden
mkdir -p "$EMPTY_PATH"

echo "Suche nach leeren Ordnern in: $A_PATH"

# Leere Ordner rekursiv finden (tiefste zuerst)
find "$A_PATH" -type d -empty -print0 | while IFS= read -r -d '' folder; do
    echo "Leerer Ordner gefunden: $folder"

    # Relativer Pfad von Ordner A
    relative_path="${folder#$A_PATH/}"
    target_path="$EMPTY_PATH/$relative_path"

    # Zielstruktur im 'empty_<Ordner>' Ordner vorbereiten
    mkdir -p "$(dirname "$target_path")"

    # Ordner verschieben
    mv "$folder" "$target_path"
    echo "Verschoben nach: $target_path"
done

echo "Alle leeren Ordner wurden verschoben nach: $EMPTY_PATH"

