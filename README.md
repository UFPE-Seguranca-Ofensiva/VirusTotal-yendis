# Malware Analysis Monorepo — *VirusTotal-yendis*

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](#)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-informational)](#)
[![7z](https://img.shields.io/badge/Needs-7--Zip-important)](#)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](#)

Repositório **monorepo** para automações de análise de malware e integrações com bases públicas (ex.: **theZoo**) e serviços de reputação (ex.: **VirusTotal**).
O primeiro módulo disponível é o **pipeline theZoo → VirusTotal → Ranking** com seleção interativa, extração em massa e geração de planilha.

> **SEGURANÇA**: este projeto lida com **amostras de malware**. Use **apenas** em VM/host isolado, sem sincronização de pastas, sem *thumbnails* e **nunca execute** binários extraídos.

---

## Organização do repositório

A estrutura na imagem enviada e/ou típica deste repo:

```
.
├─ theZoo/                         # (opcional) artefatos auxiliares do módulo theZoo
├─ dynamicAnalysisTheZoo.py        # orquestrador/ferramenta principal (CLI)
├─ findMalwaresThezoo.py           # (legado) varredura/busca
├─ sendToVirusTotal.py             # (legado) envio ao VT
├─ generateXlsx.py                 # (legado) ranking XLSX
├─ .gitignore
└─ README.md                       # este arquivo
```

> À medida que você adicionar **outros módulos** (ex.: outros datasets ou pipelines), crie novas pastas na raiz:
>
> ```
> ./theZoo/
> ./malshare/
> ./vxvault/
> ./sandbox/
> ...
> ```
>
> Cada módulo deve ter seu **README.md** próprio com instruções específicas.

---

## Visão geral do pipeline theZoo

```mermaid
flowchart LR
    A[fetch_extract] -->|wget + unzip| B(theZoo extraído)
    B --> C{Selecionar famílias\n(timeout 5 min)}
    C -->|sem resposta| D[Extrair todas]
    C -->|índices/nomes| E[Extrair selecionadas]
    D --> F[extracted/<Família>/...]
    E --> F
    F --> G[send → VirusTotal API]
    G -->|hash existe| H[Salva JSON]
    G -->|upload| I[opcional: aguarda análise]
    I --> H
    H --> J[rank → XLSX]
```


**Recursos chave**

* Baixa **ytisf/theZoo** via `wget` e extrai com `unzip`/`7z`
* Lista famílias em `malware/Binaries`; **timeout 5 min** → se não escolher, extrai **todas**
* Extração com **7z** (zip/7z/rar/tar.\*), modo *flatten* por família
* Envio **um a um** ao **VirusTotal**: busca por **hash**; se não existir, **upload** e (opcional) aguarda análise
  ↳ **Ignora** `.txt`, **ocultos** e **symlinks**
* Gera **`VirusTotal_Ranking.xlsx`** (Detectado/Não Detectado/Omisso por engine)

---

## Requisitos

**Sistema**

```bash
sudo apt update
sudo apt install -y wget unzip p7zip-full
```

**Python 3.9+**
Bibliotecas:

* `requests` (obrigatório)
* `pandas` e `openpyxl` (para gerar o XLSX)

> Em Kali/Debian (PEP 668), prefira **venv** ou instale via **APT**:
>
> **venv (recomendado)**
>
> ```bash
> sudo apt install -y python3-venv
> python3 -m venv ~/.venvs/thezoo
> source ~/.venvs/thezoo/bin/activate
> pip install --upgrade pip
> pip install requests pandas openpyxl
> ```
>
> **APT**
>
> ```bash
> sudo apt install -y python3-requests python3-pandas python3-openpyxl
> ```

**VirusTotal API**

```bash
export VT_API_KEY="SUA_CHAVE_DO_VT"
```

---

## Uso rápido (módulo theZoo)

> Considere `dynamicAnalysisTheZoo.py` como **orquestrador** (o seu script unificado).
> Ele expõe subcomandos: `fetch_extract`, `send`, `rank`, `all`.

### 1) Executar tudo

```bash
python3 dynamicAnalysisTheZoo.py all
```

### 2) Etapas separadas

```bash
# baixar + extrair (lista famílias e espera 5 min por escolha)
python3 dynamicAnalysisTheZoo.py fetch_extract

# enviar ao VirusTotal (ignora .txt/ocultos/symlinks)
python3 dynamicAnalysisTheZoo.py send

# gerar planilha XLSX com ranking por antivírus
python3 dynamicAnalysisTheZoo.py rank
```

### 3) Selecionar famílias

Por **índice**:

```bash
python3 dynamicAnalysisTheZoo.py fetch_extract --choose "0,2,5"
```

Por **nome**:

```bash
python3 dynamicAnalysisTheZoo.py fetch_extract --families "Zeus,Emotet"
```

### 4) Paralelismo na extração

```bash
python3 dynamicAnalysisTheZoo.py fetch_extract --workers 8
python3 dynamicAnalysisTheZoo.py all --workers 8
```

---

## Parâmetros e comportamento

| Área       | Chave/Comportamento |                    Padrão | Notas                            |
| ---------- | ------------------- | ------------------------: | -------------------------------- |
| Diretórios | Base                |         `~/theZoo_simple` | ZIP, extração e resultados       |
| Extração   | Senha               |                `infected` | Padrão do theZoo                 |
| Extração   | Flatten             |                  **True** | Extrai em `extracted/<Família>/` |
| Extração   | Timeout prompt      |                 **5 min** | Sem resposta ⇒ todas             |
| Envio VT   | Ignorados           | `.txt`, ocultos, symlinks | `rglob` com filtro               |
| Envio VT   | Esperar análise     |                  **True** | Pode desativar no script         |
| Envio VT   | Ritmo (API pública) | `SLEEP_BETWEEN_CALLS=16s` | Ajuste conforme plano            |
| Ranking    | Saída               | `VirusTotal_Ranking.xlsx` | Planilha no diretório atual      |

**Lógica de ranking (VT v3)**

* **Detectado**: `category ∈ {malicious, suspicious}`
* **Não Detectado**: `category ∈ {harmless, undetected}`
* **Omisso**: `timeout`, `failure`, `type-unsupported` ou engine ausente
* Denominador: **total de arquivos**

---

## Troubleshooting

* **`error: externally-managed-environment`** → use **venv** ou **APT** (veja Requisitos).
* **`NameError: requests is not defined`** → instale `requests` e confirme `import requests` no topo.
* **`7z` ausente** → `sudo apt install -y p7zip-full`.
* **429/limites no VirusTotal** → aumente `SLEEP_BETWEEN_CALLS` (20–30s) e/ou desative a espera de análise, rodando `send` novamente depois.

---

## Boas práticas

* Trabalhe em **VM isolada**; **não** sincronize `~/theZoo_simple` com nuvens (Drive/Dropbox).
* Desative **pré-visualizações**/thumbnails no SO.
* Se possível, use volume com `noexec`.
* **Nunca** execute binários extraídos.
* Respeite os **Termos** do VirusTotal (uploads podem ser públicos).

---

## Contribuindo

* Cada módulo (ex.: `theZoo/`, `malshare/`) deve ter seu **README** próprio.
* Siga *commits* claros e *PRs* focados.
* Sugestão de convenções: `feat:`, `fix:`, `docs:`, `refactor:`, `chore:`.

---

## Licença & Créditos

* Wrapper/pipeline sobre **[theZoo](https://github.com/ytisf/theZoo)** — créditos a *ytisf* e contribuidores.
* Integração com **VirusTotal API v3** (© Google/Chronicle).
* Código deste repo: **MIT**.

---

## Roadmap do monorepo

* **Novos módulos**: outros datasets (MalShare, VXVault, etc.)
* **Flags CLI** para `--no-wait` e `--vt-sleep`
* **Inventário** CSV/JSON de amostras extraídas
* **Cache local de hash** para pular reenvios
* **Logs estruturados** (JSON) e `--quiet/--verbose`

---

> Sugestão: mantenha este README na raiz e adicione um `README.md` em cada pasta de módulo (`theZoo/`, etc.) com instruções específicas.

---

# English Version

# Malware Analysis Monorepo — *VirusTotal-yendis*

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](#)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-informational)](#)
[![7z](https://img.shields.io/badge/Needs-7--Zip-important)](#)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](#)

A **monorepo** for malware analysis automation and integration with public databases (e.g., **theZoo**) and reputation services (e.g., **VirusTotal**).
The first available module is the **pipeline theZoo → VirusTotal → Ranking** with interactive selection, mass extraction, and spreadsheet generation.

> **SECURITY**: this project deals with **malware samples**. Use **only** in isolated VM/host, without folder synchronization, without *thumbnails*, and **never execute** extracted binaries.

---

## Repository Organization

The structure in the image sent and/or typical of this repo:

```
.
├─ theZoo/                         # (optional) auxiliary artifacts of the theZoo module
├─ dynamicAnalysisTheZoo.py        # orchestrator/main tool (CLI)
├─ findMalwaresThezoo.py           # (legacy) scanning/search
├─ sendToVirusTotal.py             # (legacy) sending to VT
├─ generateXlsx.py                 # (legacy) XLSX ranking
├─ .gitignore
└─ README.md                       # this file
```

> As you add **other modules** (e.g., other datasets or pipelines), create new folders at the root:
>
> ```
> ./theZoo/
> ./malshare/
> ./vxvault/
> ./sandbox/
> ...
> ```
>
> Each module should have its own **README.md** with specific instructions.

---

## Overview of the theZoo pipeline

```mermaid
flowchart LR
    A[fetch_extract] -->|wget + unzip| B(theZoo extracted)
    B --> C{Select families\n(timeout 5 min)}
    C -->|no response| D[Extract all]
    C -->|indices/names| E[Extract selected]
    D --> F[extracted/<Family>/...]
    E --> F
    F --> G[send → VirusTotal API]
    G -->|hash exists| H[Save JSON]
    G -->|upload| I[optional: wait for analysis]
    I --> H
    H --> J[rank → XLSX]
```


**Key Features**

* Downloads **ytisf/theZoo** via `wget` and extracts with `unzip`/`7z`
* Lists families in `malware/Binaries`; **timeout 5 min** → if not chosen, extracts **all**
* Extraction with **7z** (zip/7z/rar/tar.*), *flatten* mode by family
* Sending **one by one** to **VirusTotal**: search by **hash**; if it doesn't exist, **upload** and (optional) wait for analysis
  ↳ **Ignores** `.txt`, **hidden** and **symlinks**
* Generates **`VirusTotal_Ranking.xlsx`** (Detected/Not Detected/Omitted by engine)

---

## Requirements

**System**

```bash
sudo apt update
sudo apt install -y wget unzip p7zip-full
```

**Python 3.9+**
Libraries:

* `requests` (required)
* `pandas` and `openpyxl` (to generate XLSX)

> In Kali/Debian (PEP 668), prefer **venv** or install via **APT**:
>
> **venv (recommended)**
>
> ```bash
> sudo apt install -y python3-venv
> python3 -m venv ~/.venvs/thezoo
> source ~/.venvs/thezoo/bin/activate
> pip install --upgrade pip
> pip install requests pandas openpyxl
> ```
>
> **APT**
>
> ```bash
> sudo apt install -y python3-requests python3-pandas python3-openpyxl
> ```

**VirusTotal API**

```bash
export VT_API_KEY="YOUR_VT_KEY"
```

---

## Quick Usage (theZoo module)

> Consider `dynamicAnalysisTheZoo.py` as the **orchestrator** (your unified script).
> It exposes subcommands: `fetch_extract`, `send`, `rank`, `all`.

### 1) Run everything

```bash
python3 dynamicAnalysisTheZoo.py all
```

### 2) Separate steps

```bash
# download + extract (lists families and waits 5 min for choice)
python3 dynamicAnalysisTheZoo.py fetch_extract

# send to VirusTotal (ignores .txt/hidden/symlinks)
python3 dynamicAnalysisTheZoo.py send

# generate XLSX spreadsheet with antivirus ranking
python3 dynamicAnalysisTheZoo.py rank
```

### 3) Select families

By **index**:

```bash
python3 dynamicAnalysisTheZoo.py fetch_extract --choose "0,2,5"
```

By **name**:

```bash
python3 dynamicAnalysisTheZoo.py fetch_extract --families "Zeus,Emotet"
```

### 4) Parallelism in extraction

```bash
python3 dynamicAnalysisTheZoo.py fetch_extract --workers 8
python3 dynamicAnalysisTheZoo.py all --workers 8
```

---

## Parameters and behavior

| Area       | Key/Behavior      |                    Default | Notes                            |
| ---------- | ----------------- | -------------------------: | -------------------------------- |
| Directories | Base              |         `~/theZoo_simple` | ZIP, extraction and results      |
| Extraction | Password          |                `infected` | theZoo default                   |
| Extraction | Flatten           |                  **True** | Extracts to `extracted/<Family>/` |
| Extraction | Timeout prompt    |                 **5 min** | No response ⇒ all                |
| VT Sending | Ignored           | `.txt`, hidden, symlinks  | `rglob` with filter              |
| VT Sending | Wait for analysis |                  **True** | Can be disabled in the script    |
| VT Sending | Rate (public API) | `SLEEP_BETWEEN_CALLS=16s` | Adjust according to plan         |
| Ranking    | Output            | `VirusTotal_Ranking.xlsx` | Spreadsheet in current directory |

**Ranking logic (VT v3)**

* **Detected**: `category ∈ {malicious, suspicious}`
* **Not Detected**: `category ∈ {harmless, undetected}`
* **Omitted**: `timeout`, `failure`, `type-unsupported` or missing engine
* Denominator: **total files**

---

## Troubleshooting

* **`error: externally-managed-environment`** → use **venv** or **APT** (see Requirements).
* **`NameError: requests is not defined`** → install `requests` and confirm `import requests` at the top.
* **`7z` missing** → `sudo apt install -y p7zip-full`.
* **429/limits on VirusTotal** → increase `SLEEP_BETWEEN_CALLS` (20–30s) and/or disable waiting for analysis, running `send` again later.

---

## Best Practices

* Work in an **isolated VM**; **do not** sync `~/theZoo_simple` with clouds (Drive/Dropbox).
* Disable **previews**/thumbnails in the OS.
* If possible, use volume with `noexec`.
* **Never** run extracted binaries.
* Respect VirusTotal's **Terms** (uploads may be public).

---

## Contributing

* Each module (e.g., `theZoo/`, `malshare/`) should have its own **README**.
* Follow clear *commits* and focused *PRs*.
* Suggested conventions: `feat:`, `fix:`, `docs:`, `refactor:`, `chore:`.

---

## License & Credits

* Wrapper/pipeline over **[theZoo](https://github.com/ytisf/theZoo)** — credits to *ytisf* and contributors.
* Integration with **VirusTotal API v3** (© Google/Chronicle).
* Code in this repo: **MIT**.

---

## Monorepo Roadmap

* **New modules**: other datasets (MalShare, VXVault, etc.)
* **CLI flags** for `--no-wait` and `--vt-sleep`
* **Inventory** CSV/JSON of extracted samples
* **Local hash cache** to skip re-sending
* **Structured logs** (JSON) and `--quiet/--verbose`

---

> Suggestion: keep this README at the root and add a `README.md` in each module folder (`theZoo/`, etc.) with specific instructions.
