#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import time
import json
import hashlib
import subprocess
import zipfile
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List, Dict
import requests

# ---- Configuração padrão ----
WORKDIR = Path.home() / "theZoo_simple"
OUT_EXTRACT = WORKDIR / "extracted"
OUT_VT = WORKDIR / "VirusTotal"
ZIP_URL = "https://codeload.github.com/ytisf/theZoo/zip/refs/heads/master"
ZIP_FILE = WORKDIR / "theZoo.zip"
PASS = "infected"                # senha padrão theZoo
PROMPT_SECS = 300                # 5 minutos
DEFAULT_WORKERS = max(2, os.cpu_count() or 2)
ARCHIVE_EXTS = (".zip", ".7z", ".rar", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2")
FLATTEN = True                   # extrair direto em OUT_EXTRACT/<Família>/
# VirusTotal
VT_API_KEY = os.getenv("VT_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"
SLEEP_BETWEEN_CALLS = 16         # API pública: ~4 req/min
ANALYSIS_TIMEOUT = 300           # 5 min
WAIT_FOR_ANALYSIS = True         # aguardar término da análise após upload?
# -----------------------------

# ========= utilidades gerais =========
def run_cmd(cmd: List[str], check=True, quiet=False):
    if not quiet:
        print("$ " + " ".join(cmd))
    return subprocess.run(cmd, check=check)

def have(cmd: str) -> bool:
    return shutil_which(cmd) is not None

def shutil_which(cmd: str) -> Optional[str]:
    from shutil import which
    return which(cmd)

def is_hidden(p: Path) -> bool:
    return any(part.startswith(".") for part in p.parts)

def should_skip_upload(p: Path) -> bool:
    # ignora .txt (qualquer caso), ocultos e symlinks
    if p.is_symlink():
        return True
    if p.suffix.lower() == ".txt":
        return True
    if is_hidden(p):
        return True
    return False

def unique_dest(dest_dir: Path, filename: str) -> Path:
    base, ext = os.path.splitext(filename)
    cand = dest_dir / filename
    i = 1
    while cand.exists():
        cand = dest_dir / f"{base} ({i}){ext}"
        i += 1
    return cand

# ========= FETCH + EXTRACT =========
def ensure_repo() -> Path:
    WORKDIR.mkdir(parents=True, exist_ok=True)

    # 1) Baixar ZIP com wget
    if not ZIP_FILE.exists():
        if not have("wget"):
            sys.exit("Erro: 'wget' não encontrado no PATH.")
        print("[1/3] Baixando repositório (wget)…")
        run_cmd(["wget", "-q", "-O", str(ZIP_FILE), ZIP_URL])
    else:
        print("[1/3] ZIP já existe, pulando download.")

    # 2) Extrair se a pasta ainda não existir
    repo_root = None
    for p in WORKDIR.iterdir():
        if p.is_dir() and p.name.lower().startswith("thezoo"):
            repo_root = p
            break
    if repo_root is None:
        if not have("unzip"):
            # fallback básico em zipfile
            print("[2/3] Extraindo (zipfile)…")
            with zipfile.ZipFile(ZIP_FILE, 'r') as zf:
                zf.extractall(WORKDIR)
        else:
            print("[2/3] Extraindo repositório (unzip)…")
            run_cmd(["unzip", "-q", "-o", str(ZIP_FILE), "-d", str(WORKDIR)])
        for p in WORKDIR.iterdir():
            if p.is_dir() and p.name.lower().startswith("thezoo"):
                repo_root = p
                break
    if repo_root is None:
        sys.exit("Erro: não encontrei a pasta do repositório após extrair.")

    print(f"[3/3] Repositório em: {repo_root}")
    return repo_root

def find_binaries(repo_root: Path) -> Path:
    for name in ("binaries", "Binaries"):
        d = repo_root / "malware" / name
        if d.exists():
            return d
    sys.exit("Erro: não encontrei malware/binaries no repositório.")

def list_families(bin_dir: Path) -> List[Path]:
    fams = sorted([p for p in bin_dir.iterdir() if p.is_dir()], key=lambda p: p.name.lower())
    if not fams:
        sys.exit("Nenhuma família encontrada.")
    print(f"\nFamílias em {bin_dir}:\n")
    for i, fam in enumerate(fams):
        print(f"[{i}] {fam.name}")
    return fams

def prompt_choice(fams: List[Path], choose_indices: Optional[str] = None, families_filter: Optional[str] = None) -> List[Path]:
    # permitir seleção via parâmetros (sem prompt)
    if families_filter:
        names = {n.strip().lower() for n in families_filter.split(",") if n.strip()}
        picked = [f for f in fams if f.name.lower() in names]
        if picked:
            return picked
    if choose_indices:
        idxs = []
        for chunk in choose_indices.split(","):
            chunk = chunk.strip()
            if chunk.isdigit():
                i = int(chunk)
                if 0 <= i < len(fams):
                    idxs.append(fams[i])
        if idxs:
            return idxs

    print(f"\nEscolha índices separados por vírgula (ex: 0,2,5).")
    print(f"Se não responder em {PROMPT_SECS//60} minutos, vou extrair TODAS. (timeout: {PROMPT_SECS}s)")

    # input com timeout (Unix) via select
    choice = ""
    try:
        import select
        start = time.time()
        while True:
            r, _, _ = select.select([sys.stdin], [], [], 1)
            if r:
                choice = sys.stdin.readline().strip()
                break
            if time.time() - start > PROMPT_SECS:
                break
    except Exception:
        try:
            choice = input("> ")
        except EOFError:
            choice = ""

    if not choice:
        print("\n⚠️ Sem resposta — extraindo TODAS.")
        return fams

    picked = []
    for chunk in choice.split(","):
        chunk = chunk.strip()
        if chunk.isdigit():
            i = int(chunk)
            if 0 <= i < len(fams):
                picked.append(fams[i])
    if not picked:
        print("Nenhum índice válido — extraindo TODAS.")
        return fams
    return picked

def find_archives(folder: Path) -> List[Path]:
    return [p for p in folder.rglob("*") if p.is_file() and p.name.lower().endswith(ARCHIVE_EXTS)]

def extract_one(src: Path, fam_out: Path) -> tuple[Path, bool, str]:
    if not have("7z"):
        return (src, False, "7z não encontrado (instale p7zip)")

    dest = fam_out if FLATTEN else fam_out / src.stem
    dest.mkdir(parents=True, exist_ok=True)
    cmd = [
        "7z", "x",
        f"-p{PASS}", "-y",
        "-mmt=on",
        "-bso0", "-bsp0",
        f"-o{str(dest)}",
        str(src)
    ]
    try:
        subprocess.run(cmd, check=True)
        return (src, True, "ok")
    except subprocess.CalledProcessError as e:
        return (src, False, f"7z falhou (code {e.returncode})")

def extract_selected(families: List[Path], workers: int = DEFAULT_WORKERS):
    OUT_EXTRACT.mkdir(parents=True, exist_ok=True)
    tasks = []
    for fam in families:
        fam_archives = find_archives(fam)
        fam_out = OUT_EXTRACT / fam.name
        fam_out.mkdir(parents=True, exist_ok=True)
        if not fam_archives:
            print(f"– {fam.name}: nenhum arquivo compactado encontrado.")
            continue
        for a in fam_archives:
            tasks.append((a, fam_out))

    if not tasks:
        print("Nada para extrair.")
        return

    print(f"\nExtraindo {len(tasks)} arquivo(s)…")
    ok, fail = 0, 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(extract_one, a, d) for a, d in tasks]
        for f in as_completed(futs):
            src, success, msg = f.result()
            if success: ok += 1
            else: fail += 1
            print(f"[{('OK' if success else 'ERRO'):>4}] {src.name} -> {msg}")

    print(f"\nPrimeira fase concluída. Sucesso: {ok} | Falhas: {fail}")

def final_inline_extract(selected_fams: List[Path]):
    if not have("7z"):
        print("Pular fase final de extração inline (7z ausente).")
        return

    print("\nFase final: extração inline dentro das pastas selecionadas…")
    total, ok, fail = 0, 0, 0
    for fam in selected_fams:
        fam_out = OUT_EXTRACT / fam.name
        if not fam_out.exists():
            continue
        archives = [p for p in fam_out.iterdir()
                    if p.is_file() and p.suffix.lower() in (".zip", ".7z", ".rar")]
        if not archives:
            continue
        print(f"→ {fam_out} : {len(archives)} arquivo(s) a extrair")
        for src in archives:
            total += 1
            cmd = [
                "7z", "x",
                f"-p{PASS}", "-y",
                "-mmt=on",
                "-bso0", "-bsp0",
                f"-o{str(fam_out)}",
                str(src)
            ]
            try:
                subprocess.run(cmd, check=True)
                ok += 1
                print(f"[ OK ] {src.name}")
            except subprocess.CalledProcessError as e:
                fail += 1
                print(f"[ERRO] {src.name} -> 7z code {e.returncode}")
    print(f"\nFase final: processados {total}, sucesso {ok}, falhas {fail}")
    print(f"Saída: {OUT_EXTRACT}")

# ========= VirusTotal (envio e relatório) =========
def sha256sum(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def vt_get_file_report(sha256: str) -> Optional[dict]:
    url = f"{BASE_URL}/files/{sha256}"
    r = requests.get(url, headers={"x-apikey": VT_API_KEY})
    if r.status_code == 200:
        return r.json().get("data")
    if r.status_code == 404:
        return None
    raise RuntimeError(f"GET {url} -> {r.status_code}: {r.text}")

def vt_upload_file(path: Path) -> str:
    url = f"{BASE_URL}/files"
    with path.open("rb") as f:
        files = {"file": (path.name, f)}
        r = requests.post(url, headers={"x-apikey": VT_API_KEY}, files=files)
    if r.status_code in (200, 201):
        return r.json()["data"]["id"]  # analysis_id
    raise RuntimeError(f"POST /files -> {r.status_code}: {r.text}")

def vt_poll_analysis(analysis_id: str, timeout: int = ANALYSIS_TIMEOUT) -> str:
    url = f"{BASE_URL}/analyses/{analysis_id}"
    start = time.time()
    while True:
        r = requests.get(url, headers={"x-apikey": VT_API_KEY})
        if r.status_code == 200:
            status = r.json()["data"]["attributes"]["status"]
            if status == "completed":
                return "completed"
            if status not in ("queued", "running"):
                return status
        if time.time() - start > timeout:
            return "timeout"
        time.sleep(5)

def save_json(obj: dict, out_dir: Path, rel_parent: Path, file_name: str):
    # Estrutura: VirusTotal/<relative structure>/<arquivo>.json
    dest_dir = out_dir / rel_parent
    dest_dir.mkdir(parents=True, exist_ok=True)
    out = dest_dir / f"{file_name}.json"
    with out.open("w", encoding="utf-8") as fp:
        json.dump(obj, fp, indent=2, ensure_ascii=False)
    return out

def send_to_virustotal():
    if not VT_API_KEY:
        sys.exit("Defina VT_API_KEY no ambiente: export VT_API_KEY='sua_chave'")

    if not OUT_EXTRACT.exists():
        sys.exit(f"Diretório de extração não encontrado: {OUT_EXTRACT}")

    print(f"Entrada: {OUT_EXTRACT}")
    print(f"Saída:   {OUT_VT}")

    # Percorre: <Família>/<PastaDoMalware>/... (arquivos)
    for family_dir in sorted(OUT_EXTRACT.iterdir()):
        if not family_dir.is_dir() or is_hidden(family_dir):
            continue

        malware_dirs = [d for d in sorted(family_dir.iterdir()) if d.is_dir() and not is_hidden(d)]
        if not malware_dirs:
            files = [p for p in family_dir.iterdir() if p.is_file() and not should_skip_upload(p)]
            rel_parent = Path(family_dir.name) / "_root_"
            for f in files:
                process_one_upload(f, rel_parent)
            continue

        for mdir in malware_dirs:
            files = [p for p in mdir.rglob("*") if p.is_file() and not should_skip_upload(p)]
            if not files:
                continue
            print(f"\n=== Família: {family_dir.name} | Malware: {mdir.name} | Arquivos: {len(files)} ===")
            rel_parent = Path(family_dir.name) / mdir.name
            for f in files:
                process_one_upload(f, rel_parent)

    print("\nEnvio ao VirusTotal finalizado. Se alguns ficaram 'em análise', execute novamente depois para consolidar.")

def process_one_upload(file_path: Path, rel_parent: Path):
    json_path = OUT_VT / rel_parent / f"{file_path.name}.json"
    if json_path.exists():
        print(f"↷ Já processado: {json_path}")
        return

    print(f"\nArquivo: {file_path}")
    try:
        sha = sha256sum(file_path)

        data = vt_get_file_report(sha)
        time.sleep(SLEEP_BETWEEN_CALLS)

        if data is not None:
            print("→ Já existe no VT. Salvando JSON…")
            saved = save_json(data, OUT_VT, rel_parent, file_path.name)
            print(f"OK -> {saved}")
            return

        print("→ Não existe no VT. Enviando (upload)…")
        analysis_id = vt_upload_file(file_path)
        time.sleep(SLEEP_BETWEEN_CALLS)

        if WAIT_FOR_ANALYSIS:
            print("   Aguardando conclusão da análise…")
            status = vt_poll_analysis(analysis_id)
            print(f"   Status: {status}")

        data = vt_get_file_report(sha)
        time.sleep(SLEEP_BETWEEN_CALLS)

        if data is not None:
            saved = save_json(data, OUT_VT, rel_parent, file_path.name)
            print(f"Report salvo -> {saved}")
        else:
            print("WARN: análise ainda não disponível — rode novamente depois para consolidar.")

    except requests.exceptions.ConnectionError:
        print("ERRO de conexão — aguardando e seguindo…")
        time.sleep(SLEEP_BETWEEN_CALLS * 2)
    except Exception as e:
        print(f"ERRO ao processar {file_path.name}: {e}")

# ========= Ranking (VT v3) =========
def ler_json(p: Path) -> Optional[dict]:
    try:
        with p.open("r", encoding="utf-8") as fp:
            return json.load(fp)
    except Exception:
        return None

def status_engine(entry: Optional[dict]) -> Optional[bool]:
    if not entry or not isinstance(entry, dict):
        return None
    cat = (entry.get("category") or "").lower()
    if cat in ("malicious", "suspicious"):
        return True
    if cat in ("harmless", "undetected"):
        return False
    return None  # timeout/failure/type-unsupported/ausente

def tabela_files(file_json_path: Path) -> Dict[str, Optional[bool]]:
    data = ler_json(file_json_path)
    if not data:
        return {}

    if "attributes" not in data and "data" in data and isinstance(data["data"], dict):
        data = data["data"]

    results = (data.get("attributes", {}).get("last_analysis_results", {}) if isinstance(data, dict) else {})
    out = {}
    if isinstance(results, dict):
        for eng, entry in results.items():
            out[str(eng)] = status_engine(entry)
    return out

def build_rank_xlsx():
    try:
        import pandas as pd
    except ImportError:
        sys.exit("Instale dependências: pip install pandas openpyxl")

    if not OUT_VT.exists():
        sys.exit(f"Diretório com JSONs do VT não encontrado: {OUT_VT}")

    arquivos = sorted(p for p in OUT_VT.rglob("*.json") if p.is_file())
    if not arquivos:
        sys.exit("Nenhum JSON encontrado para ranquear.")

    resultado = {}
    engines = set()
    for fjson in arquivos:
        per_file = tabela_files(fjson)
        resultado[fjson.name] = per_file
        engines.update(per_file.keys())

    list_antivirus = sorted(engines, key=str.lower)
    ordered_files = [p.name for p in arquivos]
    total_files = len(ordered_files)

    rows = []
    for eng in list_antivirus:
        vals = [resultado.get(fname, {}).get(eng, None) for fname in ordered_files]
        det = sum(1 for v in vals if v is True)
        nd  = sum(1 for v in vals if v is False)
        om  = sum(1 for v in vals if v is None)
        rows.append({
            "Antivírus": eng,
            "Detectado": round(100.0 * det / total_files, 2),
            "Não Detectado": round(100.0 * nd  / total_files, 2),
            "Omisso": round(100.0 * om / total_files, 2),
            "Detectado (abs)": det,
            "Não Detectado (abs)": nd,
            "Omisso (abs)": om,
        })

    import pandas as pd
    df = pd.DataFrame(rows).set_index("Antivírus")
    df.sort_values(by=["Detectado", "Omisso"], ascending=[False, True], inplace=True)

    out_xlsx = f"{OUT_VT.name}_Ranking.xlsx"  # "VirusTotal_Ranking.xlsx"
    with pd.ExcelWriter(out_xlsx, engine="openpyxl") as writer:
        df.to_excel(writer, sheet_name=f"Resultados {OUT_VT.name}")
        meta = pd.DataFrame([{"Total de arquivos": total_files, "Arquivos (JSON)": len(arquivos)}])
        meta.to_excel(writer, sheet_name="Resumo", index=False)
    print(f"Ranking gerado: {Path(out_xlsx).resolve()}")

# ========= Orquestrador =========
def do_fetch_extract(choose=None, families=None, workers=DEFAULT_WORKERS):
    repo_root = ensure_repo()
    bin_dir = find_binaries(repo_root)
    fams = list_families(bin_dir)
    selected = prompt_choice(fams, choose_indices=choose, families_filter=families)
    extract_selected(selected, workers=workers)
    final_inline_extract(selected)

def do_send():
    send_to_virustotal()

def do_rank():
    build_rank_xlsx()

def do_all(choose=None, families=None, workers=DEFAULT_WORKERS):
    do_fetch_extract(choose=choose, families=families, workers=workers)
    do_send()
    do_rank()

# ========= CLI =========
def parse_args():
    import argparse
    p = argparse.ArgumentParser(description="Pipeline theZoo -> Extração -> VirusTotal -> Ranking")
    sub = p.add_subparsers(dest="cmd", required=True)

    # fetch_extract
    se = sub.add_parser("fetch_extract", help="Baixar/Extrair e selecionar famílias")
    se.add_argument("--choose", help="Índices separados por vírgula (ex: 0,2,5)", default=None)
    se.add_argument("--families", help="Nomes de famílias separados por vírgula (ex: Zeus,Emotet)", default=None)
    se.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Threads para extração (padrão: CPUs)")

    # send
    ss = sub.add_parser("send", help="Enviar arquivos extraídos ao VirusTotal (ignora .txt/ocultos)")

    # rank
    sr = sub.add_parser("rank", help="Gerar ranking .xlsx a partir dos JSONs do VT")

    # all
    sa = sub.add_parser("all", help="Executa fetch_extract + send + rank")
    sa.add_argument("--choose", help="Índices separados por vírgula", default=None)
    sa.add_argument("--families", help="Nomes de famílias separados por vírgula", default=None)
    sa.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Threads para extração")

    return p.parse_args()

if __name__ == "__main__":
    import shutil  # para which

    args = parse_args()
    try:
        if args.cmd == "fetch_extract":
            do_fetch_extract(choose=getattr(args, "choose", None),
                             families=getattr(args, "families", None),
                             workers=getattr(args, "workers", DEFAULT_WORKERS))
        elif args.cmd == "send":
            do_send()
        elif args.cmd == "rank":
            do_rank()
        elif args.cmd == "all":
            do_all(choose=getattr(args, "choose", None),
                   families=getattr(args, "families", None),
                   workers=getattr(args, "workers", DEFAULT_WORKERS))
    except KeyboardInterrupt:
        print("\nInterrompido pelo usuário.")
        sys.exit(130)
