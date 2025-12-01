#!/bin/zsh

# Eingabeparameter: Datei oder Verzeichnis
target="$1"

if [[ -z "$target" ]]; then
  echo "Fehler: Bitte gib einen Pfad oder ein Dateimuster an."
  echo "Beispiel: ./safe_unpack_tgz.sh /pfad/zum/ordner"
  echo "Oder: ./safe_unpack_tgz.sh /pfad/zum/*.tgz*"
  exit 1
fi

# Wenn ein Verzeichnis übergeben wurde
if [[ -d "$target" ]]; then
  file_list=("$target"/*.tgz*(N) "$target"/*.gz(N))
else
  file_list=($~target)
fi

for file in $file_list; do
  [[ -e "$file" ]] || continue
  filename="${file##*/}"

  if [[ "$filename" =~ ^(.*)\.tgz\.([0-9]+)$ ]]; then
    base="${match[1]}${match[2]}"
  elif [[ "$filename" =~ ^(.*)\.tgz$ ]]; then
    base="${match[1]}"
  elif [[ "$filename" == *.gz ]]; then
    if [[ "$filename" == *.tar.gz || "$filename" == *.tgz* ]]; then
      continue  # Diese wurden bereits verarbeitet
    fi
    base="${filename%.gz}"
    output_dir="${file:h}/${base}_gz"
    mkdir -p "$output_dir"
    cp "$file" "$output_dir/$filename"
    gunzip -f "$output_dir/$filename"
    echo "Entpackt einfache .gz-Datei ➝ $output_dir/$base"
    continue
  else
    echo "Überspringe ungültige Datei: $filename"
    continue
  fi

  output_dir="${file:h}/$base"
  mkdir -p "$output_dir"

  if ! tar -tzf "$file" > /dev/null 2>&1; then
    echo "Fehler: $file ist kein gültiges Archiv."
    continue
  fi

  tar -xzf "$file" -C "$output_dir" --no-same-owner
  echo "Erfolgreich entpackt: $file ➝ $output_dir"
done

echo "Verarbeitung abgeschlossen."

