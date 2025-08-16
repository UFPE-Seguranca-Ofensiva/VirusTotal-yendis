# theZoo Pipeline · Extração → VirusTotal → Ranking ⚙️🧪

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](#)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-informational)](#)
[![7z](https://img.shields.io/badge/Needs-7--Zip-important)](#)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](#)
[![Status](https://img.shields.io/badge/Usage-Lab%20%2F%20VM%20only-red)](#)

Pipeline em **um script Python** para:

1. **Baixar** o repositório [`ytisf/theZoo`](https://github.com/ytisf/theZoo) via `wget`
2. **Extrair** famílias de `malware/Binaries` com seleção interativa (timeout **5 min**)
3. **Enviar** os arquivos extraídos ao **VirusTotal** (ignora **.txt**, **ocultos**, **symlinks**)
4. **Gerar** um **ranking** em **XLSX** por antivírus

> \[!WARNING]
> **Malware em ambiente de laboratório**: use **apenas** em VM/host isolado, sem sincronização de pastas, sem *thumbnails*, e **nunca execute** as amostras.

---

## 📑 Sumário

* [Visão Rápida](#-visão-rápida)
* [Fluxo (Mermaid)](#-fluxo-mermaid)
* [Estrutura de Pastas](#-estrutura-de-pastas)
* [Requisitos](#-requisitos)
* [Instalação](#-instalação)

  * [Virtualenv (recomendado)](#virtualenv-recomendado)
  * [APT (sistema)](#apt-sistema)
* [Configuração](#-configuração)
* [Uso](#-uso)

  * [Tudo em uma passada](#tudo-em-uma-passada)
  * [Etapas separadas](#etapas-separadas)
  * [Selecionar famílias](#selecionar-famílias)
  * [Paralelismo](#paralelismo)
* [Parâmetros & Comportamento](#-parâmetros--comportamento)
* [Troubleshooting](#-troubleshooting)
* [Segurança](#-segurança)
* [Licença & Créditos](#-licença--créditos)
* [Roadmap](#-roadmap)

---

## ⚡ Visão Rápida

```bash
# deps de sistema
sudo apt update
sudo apt install -y wget unzip p7zip-full python3-venv

# venv (recomendado)
python3 -m venv ~/.venvs/thezoo
source ~/.venvs/thezoo/bin/activate
pip install --upgrade pip
pip install requests pandas openpyxl

# chave do VirusTotal
export VT_API_KEY="SUA_CHAVE_DO_VT"

# rodar tudo
python3 thezoo_pipeline.py all
```

> \[!TIP]
> Em ambientes com PEP 668 (Kali/Debian), prefira **venv** ou instale libs via **APT**.

---

## 🧭 Fluxo (Mermaid)

```mermaid
flowchart LR
    A[fetch_extract] -->|wget + unzip| B(theZoo extraído)
    B --> C{Selecionar famílias<br/>(input 5 min)}
    C -->|sem resposta| D[Extrair todas]
    C -->|índices/nome| E[Extrair selecionadas]
    D --> F[extracted/<Família>/...]
    E --> F
    F --> G[send → VT API]
    G -->|hash existe| H[Salva JSON]
    G -->|upload| I[aguarda análise?]
    I --> H
    H --> J[rank → XLSX]
```

---

## 📂 Estrutura de Pastas

```
~/theZoo_simple/
├─ theZoo.zip
├─ theZoo-<branch>/
├─ extracted/                      # saída por família
│  ├─ W32.Beagle/
│  └─ All.ElectroRAT/0468127a.../
└─ VirusTotal/                     # JSON por arquivo (VT v3)
   ├─ W32.Beagle/<MalwareDir>/<arquivo>.json
   └─ All.ElectroRAT/0468127a.../<arquivo>.json
```

---

## 🧰 Requisitos

**Sistema**

```bash
sudo apt update
sudo apt install -y wget unzip p7zip-full
```

**Python 3.9+**

* `requests` (envio ao VT)
* `pandas` + `openpyxl` (ranking XLSX)

---

## 🧩 Instalação

### Virtualenv (recomendado)

```bash
sudo apt install -y python3-venv
python3 -m venv ~/.venvs/thezoo
source ~/.venvs/thezoo/bin/activate
pip install --upgrade pip
pip install requests pandas openpyxl
```

> Para sair do venv: `deactivate`.

### APT (sistema)

```bash
sudo apt install -y python3-requests python3-pandas python3-openpyxl
```

---

## 🔧 Configuração

Defina sua **API key** do VirusTotal:

```bash
export VT_API_KEY="SUA_CHAVE_DO_VT"
```

> \[!CAUTION]
> Não faça *commit* da sua chave. Use variáveis de ambiente ou `.env` (fora do controle de versão).

---

## ▶️ Uso

> Salve o script unificado como `thezoo_pipeline.py`.

### Tudo em uma passada

```bash
python3 thezoo_pipeline.py all
```

### Etapas separadas

```bash
python3 thezoo_pipeline.py fetch_extract   # baixar + extrair
python3 thezoo_pipeline.py send            # enviar ao VT (ignora .txt/ocultos/symlinks)
python3 thezoo_pipeline.py rank            # gerar XLSX
```

### Selecionar famílias

Por **índice**:

```bash
python3 thezoo_pipeline.py fetch_extract --choose "0,2,5"
```

Por **nome**:

```bash
python3 thezoo_pipeline.py fetch_extract --families "Zeus,Emotet"
```

### Paralelismo

```bash
python3 thezoo_pipeline.py fetch_extract --workers 8
python3 thezoo_pipeline.py all --workers 8
```

---

## ⚙️ Parâmetros & Comportamento

| Área       | Chave/Comportamento |              Valor padrão | Notas                                   |
| ---------- | ------------------- | ------------------------: | --------------------------------------- |
| Diretórios | Base de trabalho    |         `~/theZoo_simple` | ZIP, extração e resultados              |
| Extração   | Senha               |                `infected` | Padrão do theZoo                        |
| Extração   | Flatten             |                  **True** | Extrai direto em `extracted/<Família>/` |
| Extração   | Timeout prompt      |                 **5 min** | Sem resposta ⇒ todas                    |
| Envio VT   | Ignorados           | `.txt`, ocultos, symlinks | Filtro por caminho/arquivo              |
| Envio VT   | Esperar análise     |                  **True** | Pode desativar no script p/ agilizar    |
| Envio VT   | Ritmo (API pública) | `SLEEP_BETWEEN_CALLS=16s` | Ajuste conforme plano                   |
| Ranking    | Saída               | `VirusTotal_Ranking.xlsx` | Em diretório atual                      |

**Lógica de ranking (VT v3)**

* **Detectado**: `category ∈ {malicious, suspicious}`
* **Não Detectado**: `category ∈ {harmless, undetected}`
* **Omisso**: `timeout`, `failure`, `type-unsupported` ou engine ausente
* Denominador = **total de arquivos**

---

## 🧯 Troubleshooting

<details>
<summary><b>error: externally-managed-environment (PEP 668)</b></summary>

Use **venv** (recomendado) ou instale via APT:

```bash
sudo apt install -y python3-venv
python3 -m venv ~/.venvs/thezoo && source ~/.venvs/thezoo/bin/activate
pip install requests pandas openpyxl
# ou
sudo apt install -y python3-requests python3-pandas python3-openpyxl
```

</details>

<details>
<summary><b>NameError: requests is not defined</b></summary>

Instale `requests` e confirme `import requests` no topo do script.

</details>

<details>
<summary><b>7z não encontrado</b></summary>

```bash
sudo apt install -y p7zip-full
```

</details>

<details>
<summary><b>Muitos 429 / timeouts no VirusTotal</b></summary>

* Aumente `SLEEP_BETWEEN_CALLS` (ex.: 20–30s)
* Desative espera de análise (coloque `WAIT_FOR_ANALYSIS=False`) e rode `send` novamente depois para consolidar

</details>

---

## 🛡️ Segurança

* Rodar em **VM isolada**; **não** sincronize `~/theZoo_simple` (Drive/Dropbox)
* Desativar **pré-visualizações**/thumbnails
* Preferir volume com `noexec` para o diretório de trabalho
* **Nunca** abrir/executar os binários extraídos
* Respeitar **ToS** do VirusTotal (uploads podem ser públicos)

---

## 📜 Licença & Créditos

* Wrapper em torno de **[theZoo](https://github.com/ytisf/theZoo)** — créditos a *ytisf* e contribuidores
* Integração com **VirusTotal API v3** (© Google/Chronicle)
* Código deste pipeline: **MIT**

---

## 🗺️ Roadmap

* Flags CLI para `--no-wait`/`--vt-sleep`
* Inventário CSV/JSON das famílias/artefatos extraídos
* Cache local de hash para pular reenvios
* Logs estruturados (JSON) e `--quiet/--verbose`

---

> Curtiu? Abra um PR/issue com melhorias ou ideias ✨
