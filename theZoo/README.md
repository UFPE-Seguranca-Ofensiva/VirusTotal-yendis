# theZoo Pipeline · Extração → VirusTotal → Ranking

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

## Sumário

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

## Visão Rápida

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
python3 dynamicAnalysisTheZoo.py all
```

> \[!TIP]
> Em ambientes com PEP 668 (Kali/Debian), prefira **venv** ou instale libs via **APT**.

---

## Fluxo (Mermaid)

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

## Estrutura de Pastas

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

## Requisitos

**Sistema**

```bash
sudo apt update
sudo apt install -y wget unzip p7zip-full
```

**Python 3.9+**

* `requests` (envio ao VT)
* `pandas` + `openpyxl` (ranking XLSX)

---

## Instalação

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

## Configuração

Defina sua **API key** do VirusTotal:

```bash
export VT_API_KEY="SUA_CHAVE_DO_VT"
```

> \[!CAUTION]
> Não faça *commit* da sua chave. Use variáveis de ambiente ou `.env` (fora do controle de versão).

---

## Uso

> Considere `dynamicAnalysisTheZoo.py` como o script unificado.

### Tudo em uma passada

```bash
python3 dynamicAnalysisTheZoo.py all
```

### Etapas separadas

```bash
python3 dynamicAnalysisTheZoo.py fetch_extract   # baixar + extrair
python3 dynamicAnalysisTheZoo.py send            # enviar ao VT (ignora .txt/ocultos/symlinks)
python3 dynamicAnalysisTheZoo.py rank            # gerar XLSX
```

### Selecionar famílias

Por **índice**:

```bash
python3 dynamicAnalysisTheZoo.py fetch_extract --choose "0,2,5"
```

Por **nome**:

```bash
python3 dynamicAnalysisTheZoo.py fetch_extract --families "Zeus,Emotet"
```

### Paralelismo

```bash
python3 dynamicAnalysisTheZoo.py fetch_extract --workers 8
python3 dynamicAnalysisTheZoo.py all --workers 8
```

---

## Parâmetros & Comportamento

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

## Troubleshooting

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

## Segurança

* Rodar em **VM isolada**; **não** sincronize `~/theZoo_simple` (Drive/Dropbox)
* Desativar **pré-visualizações**/thumbnails
* Preferir volume com `noexec` para o diretório de trabalho
* **Nunca** abrir/executar os binários extraídos
* Respeitar **ToS** do VirusTotal (uploads podem ser públicos)

---

## Licença & Créditos

* Wrapper em torno de **[theZoo](https://github.com/ytisf/theZoo)** — créditos a *ytisf* e contribuidores
* Integração com **VirusTotal API v3** (© Google/Chronicle)
* Código deste pipeline: **MIT**

---

## Roadmap

* Flags CLI para `--no-wait`/`--vt-sleep`
* Inventário CSV/JSON das famílias/artefatos extraídos
* Cache local de hash para pular reenvios
* Logs estruturados (JSON) e `--quiet/--verbose`

---

> Curtiu? Abra um PR/issue com melhorias ou ideias

---

# English Version

# theZoo Pipeline · Extraction → VirusTotal → Ranking

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](#)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-informational)](#)
[![7z](https://img.shields.io/badge/Needs-7--Zip-important)](#)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](#)
[![Status](https://img.shields.io/badge/Usage-Lab%20%2F%20VM%20only-red)](#)

Pipeline in **one Python script** for:

1. **Downloading** the [`ytisf/theZoo`](https://github.com/ytisf/theZoo) repository via `wget`
2. **Extracting** families from `malware/Binaries` with interactive selection (timeout **5 min**)
3. **Sending** the extracted files to **VirusTotal** (ignores **.txt**, **hidden**, **symlinks**)
4. **Generating** a **ranking** in **XLSX** by antivirus

> [!WARNING]
> **Malware in laboratory environment**: use **only** in isolated VM/host, without folder synchronization, without *thumbnails*, and **never execute** the samples.

---

## Summary

* [Quick Overview](#quick-overview)
* [Flow (Mermaid)](#flow-mermaid)
* [Folder Structure](#folder-structure)
* [Requirements](#requirements)
* [Installation](#installation)

  * [Virtualenv (recommended)](#virtualenv-recommended)
  * [APT (system)](#apt-system)
* [Configuration](#configuration)
* [Usage](#usage)

  * [All in one pass](#all-in-one-pass)
  * [Separate steps](#separate-steps)
  * [Select families](#select-families)
  * [Parallelism](#parallelism)
* [Parameters & Behavior](#parameters--behavior)
* [Troubleshooting](#troubleshooting)
* [Security](#security)
* [License & Credits](#license--credits)
* [Roadmap](#roadmap)

---

## Quick Overview

```bash
# system deps
sudo apt update
sudo apt install -y wget unzip p7zip-full python3-venv

# venv (recommended)
python3 -m venv ~/.venvs/thezoo
source ~/.venvs/thezoo/bin/activate
pip install --upgrade pip
pip install requests pandas openpyxl

# VirusTotal key
export VT_API_KEY="YOUR_VT_KEY"

# run everything
python3 dynamicAnalysisTheZoo.py all
```

> [!TIP]
> In environments with PEP 668 (Kali/Debian), prefer **venv** or install libs via **APT**.

---

## Flow (Mermaid)

```mermaid
flowchart LR
    A[fetch_extract] -->|wget + unzip| B(theZoo extracted)
    B --> C{Select families<br/>(input 5 min)}
    C -->|no response| D[Extract all]
    C -->|indices/name| E[Extract selected]
    D --> F[extracted/<Family>/...]
    E --> F
    F --> G[send → VT API]
    G -->|hash exists| H[Save JSON]
    G -->|upload| I[wait for analysis?]
    I --> H
    H --> J[rank → XLSX]
```

---

## Folder Structure

```
~/theZoo_simple/
├─ theZoo.zip
├─ theZoo-<branch>/
├─ extracted/                      # output by family
│  ├─ W32.Beagle/
│  └─ All.ElectroRAT/0468127a.../
└─ VirusTotal/                     # JSON by file (VT v3)
   ├─ W32.Beagle/<MalwareDir>/<file>.json
   └─ All.ElectroRAT/0468127a.../<file>.json
```

---

## Requirements

**System**

```bash
sudo apt update
sudo apt install -y wget unzip p7zip-full
```

**Python 3.9+**

* `requests` (sending to VT)
* `pandas` + `openpyxl` (XLSX ranking)

---

## Installation

### Virtualenv (recommended)

```bash
sudo apt install -y python3-venv
python3 -m venv ~/.venvs/thezoo
source ~/.venvs/thezoo/bin/activate
pip install --upgrade pip
pip install requests pandas openpyxl
```

> To exit venv: `deactivate`.

### APT (system)

```bash
sudo apt install -y python3-requests python3-pandas python3-openpyxl
```

---

## Configuration

Define your VirusTotal **API key**:

```bash
export VT_API_KEY="YOUR_VT_KEY"
```

> [!CAUTION]
> Don't commit your key. Use environment variables or `.env` (outside version control).

---

## Usage

> Consider `dynamicAnalysisTheZoo.py` as the unified script.

### All in one pass

```bash
python3 dynamicAnalysisTheZoo.py all
```

### Separate steps

```bash
python3 dynamicAnalysisTheZoo.py fetch_extract   # download + extract
python3 dynamicAnalysisTheZoo.py send            # send to VT (ignores .txt/hidden/symlinks)
python3 dynamicAnalysisTheZoo.py rank            # generate XLSX
```

### Select families

By **index**:

```bash
python3 dynamicAnalysisTheZoo.py fetch_extract --choose "0,2,5"
```

By **name**:

```bash
python3 dynamicAnalysisTheZoo.py fetch_extract --families "Zeus,Emotet"
```

### Parallelism

```bash
python3 dynamicAnalysisTheZoo.py fetch_extract --workers 8
python3 dynamicAnalysisTheZoo.py all --workers 8
```

---

## Parameters & Behavior

| Area       | Key/Behavior      |              Default value | Notes                                   |
| ---------- | ----------------- | -------------------------: | --------------------------------------- |
| Directories | Working base      |         `~/theZoo_simple` | ZIP, extraction and results             |
| Extraction | Password          |                `infected` | theZoo default                          |
| Extraction | Flatten           |                  **True** | Extracts directly to `extracted/<Family>/` |
| Extraction | Timeout prompt    |                 **5 min** | No response ⇒ all                       |
| VT Sending | Ignored           | `.txt`, hidden, symlinks  | Filter by path/file                     |
| VT Sending | Wait for analysis |                  **True** | Can be disabled in script to speed up   |
| VT Sending | Rate (public API) | `SLEEP_BETWEEN_CALLS=16s` | Adjust according to plan                |
| Ranking    | Output            | `VirusTotal_Ranking.xlsx` | In current directory                    |

**Ranking logic (VT v3)**

* **Detected**: `category ∈ {malicious, suspicious}`
* **Not Detected**: `category ∈ {harmless, undetected}`
* **Omitted**: `timeout`, `failure`, `type-unsupported` or missing engine
* Denominator = **total files**

---

## Troubleshooting

<details>
<summary><b>error: externally-managed-environment (PEP 668)</b></summary>

Use **venv** (recommended) or install via APT:

```bash
sudo apt install -y python3-venv
python3 -m venv ~/.venvs/thezoo && source ~/.venvs/thezoo/bin/activate
pip install requests pandas openpyxl
# or
sudo apt install -y python3-requests python3-pandas python3-openpyxl
```

</details>

<details>
<summary><b>NameError: requests is not defined</b></summary>

Install `requests` and confirm `import requests` at the top of the script.

</details>

<details>
<summary><b>7z not found</b></summary>

```bash
sudo apt install -y p7zip-full
```

</details>

<details>
<summary><b>Many 429 / timeouts on VirusTotal</b></summary>

* Increase `SLEEP_BETWEEN_CALLS` (e.g., 20–30s)
* Disable waiting for analysis (set `WAIT_FOR_ANALYSIS=False`) and run `send` again later to consolidate

</details>

---

## Security

* Run in an **isolated VM**; **do not** sync `~/theZoo_simple` (Drive/Dropbox)
* Disable **previews**/thumbnails
* Prefer volume with `noexec` for the working directory
* **Never** open/execute the extracted binaries
* Respect VirusTotal's **ToS** (uploads may be public)

---

## License & Credits

* Wrapper around **[theZoo](https://github.com/ytisf/theZoo)** — credits to *ytisf* and contributors
* Integration with **VirusTotal API v3** (© Google/Chronicle)
* Code of this pipeline: **MIT**

---

## Roadmap

* CLI flags for `--no-wait`/`--vt-sleep`
* CSV/JSON inventory of extracted families/artifacts
* Local hash cache to skip re-sending
* Structured logs (JSON) and `--quiet/--verbose`

---

> Like it? Open a PR/issue with improvements or ideas
