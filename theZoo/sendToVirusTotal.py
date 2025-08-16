#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import time
import json
import hashlib
import requests
from pathlib import Path
from typing import Optional

# ===== Config =====
# DICA: prefira usar variável de ambiente em vez de hardcode:
VT_API_KEY = os.getenv("VT_API_KEY")
if not VT_API_KEY:
    raise SystemExit("Defina VT_API_KEY no ambiente:  export VT_API_KEY='sua_chave'")

BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": VT_API_KEY}

EXTRACTED_DIR = Path.home() / "theZoo_simple" / "extracted"
OUT_BASE      = Path.home() / "theZoo_simple" / "VirusTotal"  # onde salvaremos um .json por arquivo

# Limites API pública (~4 req/min). Ajuste se tiver plano pago.
SLEEP_BETWEEN_CALLS = 16
ANALYSIS_TIMEOUT    = 300      # 5 min
WAIT_FOR_ANALYSIS   = True     # se True, aguarda conclusão da análise após upload
# ===================

def is_hidden(p: Path) -> bool:
    """Retorna True se o arquivo ou algum diretório no caminho começar com '.'."""
    return any(part.startswith('.') for part in p.parts)

def should_skip(p: Path) -> bool:
    """Ignora .txt (qualquer caso), ocultos e symlinks."""
    if p.is_symlink():
        return True
    if p.suffix.lower() == ".txt":
        return True
    if is_hidden(p):
        return True
    return False

def sha256sum(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def vt_get_file_report(sha256: str) -> Optional[dict]:
    url = f"{BASE_URL}/files/{sha256}"
    r = requests.get(url, headers=HEADERS)
    if r.status_code == 200:
        return r.json().get("data")
    if r.status_code == 404:
        return None
    raise RuntimeError(f"GET {url} -> {r.status_code}: {r.text}")

def vt_upload_file(path: Path) -> str:
    url = f"{BASE_URL}/files"
    with path.open("rb") as f:
        files = {"file": (path.name, f)}
        r = requests.post(url, headers=HEADERS, files=files)
    if r.status_code in (200, 201):
        return r.json()["data"]["id"]  # analysis_id
    raise RuntimeError(f"POST /files -> {r.status_code}: {r.text}")

def vt_poll_analysis(analysis_id: str, timeout: int = ANALYSIS_TIMEOUT) -> str:
    url = f"{BASE_URL}/analyses/{analysis_id}"
    start = time.time()
    while True:
        r = requests.get(url, headers=HEADERS)
        if r.status_code == 200:
            status = r.json()["data"]["attributes"]["status"]
            if status == "completed":
                return "completed"
            if status not in ("queued", "running"):
                return status
        if time.time() - start > timeout:
            return "timeout"
        time.sleep(5)

def save_json(obj: dict, out_dir: Path, family: str, malware_folder: str, file_name: str):
    # Estrutura: VirusTotal/<Família>/<PastaDoMalware>/<arquivo>.json
    dest_dir = out_dir / family / malware_folder
    dest_dir.mkdir(parents=True, exist_ok=True)
    out = dest_dir / f"{file_name}.json"
    with out.open("w", encoding="utf-8") as fp:
        json.dump(obj, fp, indent=2, ensure_ascii=False)
    return out

def process_one(file_path: Path, family: str, malware_folder: str):
    if should_skip(file_path):
        print(f"↷ Ignorado (oculto/.txt/symlink): {file_path}")
        return

    json_exists = (OUT_BASE / family / malware_folder / f"{file_path.name}.json").exists()
    print(f"\nArquivo: {file_path}  |  JSON existente: {json_exists}")
    if json_exists:
        print("→ Já processado anteriormente. Pulando.")
        return

    try:
        sha = sha256sum(file_path)

        # 1) Tenta buscar por hash (já existente no VT)
        data = vt_get_file_report(sha)
        time.sleep(SLEEP_BETWEEN_CALLS)

        if data is not None:
            print("→ Já existe no VT. Salvando JSON…")
            saved = save_json(data, OUT_BASE, family, malware_folder, file_path.name)
            print(f"OK -> {saved}")
            return

        # 2) Não existe: fazer upload
        print("→ Não existe no VT. Enviando (upload)…")
        analysis_id = vt_upload_file(file_path)
        time.sleep(SLEEP_BETWEEN_CALLS)

        if WAIT_FOR_ANALYSIS:
            print("   Aguardando conclusão da análise…")
            status = vt_poll_analysis(analysis_id)
            print(f"   Status: {status}")

        # 3) Pega o report (pode demorar alguns segundos após 'completed')
        data = vt_get_file_report(sha)
        time.sleep(SLEEP_BETWEEN_CALLS)

        if data is not None:
            saved = save_json(data, OUT_BASE, family, malware_folder, file_path.name)
            print(f"Report salvo -> {saved}")
        else:
            print("WARN: análise ainda não disponível — rode novamente depois para consolidar.")

    except requests.exceptions.ConnectionError:
        print("ERRO de conexão — aguardando e seguindo…")
        time.sleep(SLEEP_BETWEEN_CALLS * 2)

    except Exception as e:
        print(f"ERRO ao processar {file_path.name}: {e}")

def main():
    if not EXTRACTED_DIR.exists():
        raise SystemExit(f"Diretório não encontrado: {EXTRACTED_DIR}")

    print(f"Entrada: {EXTRACTED_DIR}")
    print(f"Saída:   {OUT_BASE}")

    # Percorre: Família -> PastaDoMalware -> arquivos
    for family_dir in sorted(EXTRACTED_DIR.iterdir()):
        if not family_dir.is_dir() or is_hidden(family_dir):
            continue
        family = family_dir.name

        malware_dirs = [d for d in sorted(family_dir.iterdir()) if d.is_dir() and not is_hidden(d)]
        if not malware_dirs:
            files = [p for p in family_dir.iterdir() if p.is_file() and not should_skip(p)]
            for f in files:
                process_one(f, family, "_root_")
            continue

        for mdir in malware_dirs:
            malware_folder = mdir.name
            files = [p for p in mdir.rglob("*") if p.is_file() and not should_skip(p)]
            if not files:
                continue
            print(f"\n=== Família: {family} | Malware: {malware_folder} | Arquivos: {len(files)} ===")
            for f in files:
                process_one(f, family, malware_folder)

    print("\nFim. Se alguns ficaram 'em análise', execute o script novamente mais tarde para gerar os JSONs faltantes.")

if __name__ == "__main__":
    main()
