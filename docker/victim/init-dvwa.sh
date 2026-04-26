#!/usr/bin/env bash
set -euo pipefail

DVWA_DIR="/var/www/html/dvwa"

if [[ ! -d "$DVWA_DIR" ]]; then
  git clone --depth=1 https://github.com/digininja/DVWA.git "$DVWA_DIR" || true
fi

if [[ -f "$DVWA_DIR/config/config.inc.php.dist" && ! -f "$DVWA_DIR/config/config.inc.php" ]]; then
  cp "$DVWA_DIR/config/config.inc.php.dist" "$DVWA_DIR/config/config.inc.php"
fi

chown -R www-data:www-data /var/www/html || true
