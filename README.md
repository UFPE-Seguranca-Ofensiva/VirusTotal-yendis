# 🧪 Malware Analysis Monorepo — *VirusTotal-yendis*

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](#)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-informational)](#)
[![7z](https://img.shields.io/badge/Needs-7--Zip-important)](#)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](#)

Repositório **monorepo** para automações de análise de malware e integrações com bases públicas (ex.: **theZoo**) e serviços de reputação (ex.: **VirusTotal**).
O primeiro módulo disponível é o **pipeline theZoo → VirusTotal → Ranking** com seleção interativa, extração em massa e geração de planilha.

> ⚠️ **Segurança**: este projeto lida com **amostras de malware**. Use **apenas** em VM/host isolado, sem sincronização de pastas, sem *thumbnails* e **nunca execute** binários extraídos.

---

## 📦 Organização do repositório

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

## 🧭 Visão geral do pipeline theZoo

```mermaid
flowchart LR
    A[fetch_extract] -->|wget + unzip| B(theZoo extraído)
    B --> C{Selecionar famílias<br/>(timeout 5 min)}
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

## 🔧 Requisitos

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

## ▶️ Uso rápido (módulo theZoo)

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

## ⚙️ Parâmetros e comportamento

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

## 🧯 Troubleshooting

* **`error: externally-managed-environment`** → use **venv** ou **APT** (veja Requisitos).
* **`NameError: requests is not defined`** → instale `requests` e confirme `import requests` no topo.
* **`7z` ausente** → `sudo apt install -y p7zip-full`.
* **429/limites no VirusTotal** → aumente `SLEEP_BETWEEN_CALLS` (20–30s) e/ou desative a espera de análise, rodando `send` novamente depois.

---

## 🛡️ Boas práticas

* Trabalhe em **VM isolada**; **não** sincronize `~/theZoo_simple` com nuvens (Drive/Dropbox).
* Desative **pré-visualizações**/thumbnails no SO.
* Se possível, use volume com `noexec`.
* **Nunca** execute binários extraídos.
* Respeite os **Termos** do VirusTotal (uploads podem ser públicos).

---

## 🤝 Contribuindo

* Cada módulo (ex.: `theZoo/`, `malshare/`) deve ter seu **README** próprio.
* Siga *commits* claros e *PRs* focados.
* Sugestão de convenções: `feat:`, `fix:`, `docs:`, `refactor:`, `chore:`.

---

## 📜 Licença & Créditos

* Wrapper/pipeline sobre **[theZoo](https://github.com/ytisf/theZoo)** — créditos a *ytisf* e contribuidores.
* Integração com **VirusTotal API v3** (© Google/Chronicle).
* Código deste repo: **MIT**.

---

## 🗺️ Roadmap do monorepo

* **Novos módulos**: outros datasets (MalShare, VXVault, etc.)
* **Flags CLI** para `--no-wait` e `--vt-sleep`
* **Inventário** CSV/JSON de amostras extraídas
* **Cache local de hash** para pular reenvios
* **Logs estruturados** (JSON) e `--quiet/--verbose`

---

> Sugestão: mantenha este README na raiz e adicione um `README.md` em cada pasta de módulo (`theZoo/`, etc.) com instruções específicas.
