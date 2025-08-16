theZoo Pipeline — Extração, Envio ao VirusTotal e Ranking

Pipeline simples (um único script Python) que:

Baixa o repositório ytisf/theZoo via wget

Extrai as famílias em malware/Binaries (7-Zip), com seleção interativa (timeout de 5 min; sem resposta = todas)

Envia todos os arquivos extraídos de cada malware para o VirusTotal (ignora .txt, symlinks e arquivos ocultos)

Gera um ranking em XLSX por antivírus com base nos resultados do VirusTotal

⚠️ Atenção: este projeto lida com amostras de malware. Use apenas em ambientes isolados (VM), sem sincronia de pastas, com thumbnail preview desativado, filesystem com noexec quando possível, e nunca execute as amostras.

✨ Recursos

Fetch & Extract

Download via wget e extração via unzip/zipfile

Localiza malware/Binaries/binaries

Lista famílias e aguarda 5 minutos por opção do usuário (ex.: 0,2,5); se não houver resposta, extrai todas

Extração com 7z (suporte a .zip, .7z, .rar, .tar.*)

Flatten: por padrão, extrai direto para ~/theZoo_simple/extracted/<Família>/

Fase final inline: se ainda restarem zips/7z/rar no diretório da família, extrai ali mesmo

Envio ao VirusTotal (API v3)

Consulta por hash (SHA-256); se não existir, faz upload e opcionalmente aguarda a análise

Salva um JSON por arquivo em ~/theZoo_simple/VirusTotal/<Família>/<Malware>/<arquivo>.json

Ignora .txt, arquivos ocultos (qualquer segmento do caminho começando com .) e symlinks

Respeita rate limit (por padrão ~4 req/min — configurável)

Ranking XLSX

Lê os JSONs e monta ranking por antivírus com colunas Detectado / Não Detectado / Omissos (em % e absoluto)

Ordena por % Detectado desc (e % Omisso asc como critério secundário)

Gera VirusTotal_Ranking.xlsx

🗂️ Estrutura de diretórios
~/theZoo_simple/
├─ theZoo.zip
├─ theZoo-<branch>/           # repositório baixado e extraído
├─ extracted/                 # saída da extração por família
│  ├─ W32.Beagle/
│  │  ├─ <arquivos extraídos / subpastas> …
│  └─ All.ElectroRAT/
│     └─ 0468127a19da.../ …
└─ VirusTotal/                # JSONs por arquivo enviado ao VT
   ├─ W32.Beagle/
   │  └─ <MalwareDir>/
   │     └─ <arquivo>.json
   └─ All.ElectroRAT/
      └─ 0468127a19da.../
         └─ <arquivo>.json

🔧 Pré-requisitos
Sistema

Linux (testado no Kali)

wget, unzip, p7zip-full (7z)

Python 3.9+

sudo apt update
sudo apt install -y wget unzip p7zip-full

Bibliotecas Python

Você tem duas opções (por causa do PEP 668 no Kali):

A) Virtualenv (recomendado)

sudo apt install -y python3-venv
python3 -m venv ~/.venvs/thezoo
source ~/.venvs/thezoo/bin/activate
pip install --upgrade pip
pip install requests pandas openpyxl


B) Pacotes do sistema (apt)

sudo apt install -y python3-requests python3-pandas python3-openpyxl


Evite --break-system-packages a menos que esteja em VM descartável.

VirusTotal API Key

Crie/exporte a variável:

export VT_API_KEY="SUA_CHAVE_DO_VT"


Conta gratuita tem limites (≈4 req/min e cotas diárias).

🚀 Uso

Salve o script unificado como thezoo_pipeline.py.

Rodar tudo (fetch + send + rank)
python3 thezoo_pipeline.py all

Etapas separadas
# 1) Baixar/Extrair famílias
python3 thezoo_pipeline.py fetch_extract

# 2) Enviar ao VirusTotal (ignora .txt/ocultos/symlinks)
python3 thezoo_pipeline.py send

# 3) Gerar ranking XLSX
python3 thezoo_pipeline.py rank

Selecionar famílias

Por índice (exibido no prompt):

python3 thezoo_pipeline.py fetch_extract --choose "0,2,5"


Por nome:

python3 thezoo_pipeline.py fetch_extract --families "Zeus,Emotet"

Ajustar paralelismo da extração
python3 thezoo_pipeline.py fetch_extract --workers 8
python3 thezoo_pipeline.py all --workers 8

⚙️ Parâmetros e comportamento
Extração

Senha padrão para arquivos protegidos: infected

Flatten: arquivos são extraídos diretamente no diretório da família

Fase final inline: qualquer .zip/.7z/.rar remanescente no nível da família é extraído no próprio diretório da família

Timeout do prompt: 5 minutos — sem resposta => extrai todas as famílias

Envio ao VirusTotal

Ignorados: *.txt, arquivos ocultos (ex.: .DS_Store, .cache/...) e symlinks

Fluxo:

Calcula SHA-256 e tenta GET /files/{sha256}

Se 404: faz POST /files (upload)

Opcional: aguarda análise (GET /analyses/{id} até completed ou timeout)

Busca o report e salva JSON por arquivo

Rate limit: SLEEP_BETWEEN_CALLS = 16s (ajuste se tiver plano pago)

Aguardar análise: WAIT_FOR_ANALYSIS = True (pode deixar False para ir mais rápido e rodar depois novamente)

Ranking (.xlsx)

Lê VirusTotal/<Família>/<Malware>/<arquivo>.json (formato API v3)

Converte resultados por engine:

Detectado: category ∈ {malicious, suspicious}

Não Detectado: category ∈ {harmless, undetected}

Omisso: timeout, failure, type-unsupported ou engine ausente

Denominador = total de arquivos

Gera VirusTotal_Ranking.xlsx com abas “Resultados …” e “Resumo”

🧪 Exemplos rápidos
Rodar apenas envio e ranking (sem re-extrair)
python3 thezoo_pipeline.py send
python3 thezoo_pipeline.py rank

Re-executar para consolidar JSONs pendentes

Se alguns ficaram “em análise” (pendentes no VT), rode novamente:

python3 thezoo_pipeline.py send

🧯 Troubleshooting
error: externally-managed-environment

Use venv ou instale via apt:

# venv (recomendado)
sudo apt install -y python3-venv
python3 -m venv ~/.venvs/thezoo
source ~/.venvs/thezoo/bin/activate
pip install requests pandas openpyxl


ou

sudo apt install -y python3-requests python3-pandas python3-openpyxl

NameError: name 'requests' is not defined

Instale requests (veja acima) e importe no topo do script:

import requests

7z não encontrado

Instale:

sudo apt install -y p7zip-full

VT_API_KEY não definida
export VT_API_KEY="SUA_CHAVE_DO_VT"

Rate limit (429) / timeouts

Aumente SLEEP_BETWEEN_CALLS (ex.: 20–30 s)

Desative WAIT_FOR_ANALYSIS para acelerar e consolide em outra execução

🔐 Boas práticas de segurança

Trabalhe em VM isolada; não sincronize ~/theZoo_simple com nuvens (Drive/Dropbox etc.)

Desative pré-visualizações automáticas de arquivos

Monte partição com noexec se possível para o diretório de trabalho

Nunca execute os binários extraídos

Respeite licenças e termos do VirusTotal; os uploads podem ser públicos

⚖️ Licença & Créditos

Este pipeline é um wrapper prático em torno do repositório theZoo (créditos: ytisf e contribuidores).

Integra com a VirusTotal API v3 (© Google / Chronicle). Respeite os Termos de Uso do serviço.

O código deste pipeline pode ser usado sob licença MIT (adapte conforme sua necessidade).

📝 Roadmap (ideias)

Flag --no-wait/--vt-sleep via CLI (expor configs do VT no CLI)

Inventário CSV/JSON das famílias/arquivos extraídos

Cache de hash → pular uploads de arquivos já processados localmente

Logs estruturados (JSON) e opção --quiet/--verbose

🧭 Comandos de referência (cola rápida)
# deps
sudo apt install -y wget unzip p7zip-full python3-venv
python3 -m venv ~/.venvs/thezoo && source ~/.venvs/thezoo/bin/activate
pip install requests pandas openpyxl

# api key
export VT_API_KEY="SUA_CHAVE_DO_VT"

# pipeline
python3 thezoo_pipeline.py all
# ou
python3 thezoo_pipeline.py fetch_extract --choose "0,2,5"
python3 thezoo_pipeline.py send
python3 thezoo_pipeline.py rank