#!/bin/bash
set -e

# Detecta automaticamente onde a pasta v3 e a raiz do projeto estão localizadas
V3_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$V3_DIR")"

# Localiza o Python do venv (seja na raiz do projeto ou dentro de v3)
if [ -f "$ROOT_DIR/venv/bin/python" ]; then
    VENV_PYTHON="$ROOT_DIR/venv/bin/python"
elif [ -f "$V3_DIR/venv/bin/python" ]; then
    VENV_PYTHON="$V3_DIR/venv/bin/python"
else
    echo "[ERRO] Ambiente virtual (venv) não encontrado! Crie o venv antes de instalar o serviço."
    exit 1
fi

echo "[*] Diretório v3 detectado: $V3_DIR"
echo "[*] Python do venv detectado: $VENV_PYTHON"

# Substitui os marcadores pelo caminho real da máquina do usuário e instala no systemd
sed -e "s|__V3_DIR__|$V3_DIR|g" \
    -e "s|__VENV_PYTHON__|$VENV_PYTHON|g" \
    "$V3_DIR/systemd/sentinel.service" | sudo tee /etc/systemd/system/sentinel.service > /dev/null

sudo systemctl daemon-reload
sudo systemctl enable sentinel.service
sudo systemctl restart sentinel.service

echo "[+] Serviço sentinel.service instalado e iniciado com sucesso!"