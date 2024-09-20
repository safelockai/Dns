#!/bin/bash

# Atualiza o Termux e instala pacotes básicos
pkg update
pkg upgrade

# Instala dependências do Python e ferramentas de desenvolvimento
pkg install python python-dev clang libffi libffi-dev git

# Instala scapy diretamente do GitHub para garantir a versão mais recente
pip install git+https://github.com/secdev/scapy

# Instala o dsniff para a ferramenta arpspoof (se disponível)
pkg install dsniff

echo "Instalação concluída. Agora você pode rodar o seu script Python com ARP spoofing."
