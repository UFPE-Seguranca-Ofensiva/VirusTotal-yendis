# -*- coding: utf-8 -*-
import json
from pathlib import Path
from typing import Dict, Optional

import pandas as pd

# ===== CONFIG =====
# Pasta onde ficam os JSONs salvos pelo seu pipeline (um por arquivo enviado):
# Estrutura: VirusTotal/<Família>/<Malware>/<arquivo>.json
dir_entrada = Path.home() / "theZoo_simple" / "VirusTotal"
# ==================

def ler_json(p: Path) -> Optional[dict]:
    try:
        with p.open("r", encoding="utf-8") as fp:
            return json.load(fp)
    except Exception:
        return None

def status_engine(entry: Optional[dict]) -> Optional[bool]:
    """
    Converte um resultado de engine do VT v3 em:
      True  -> detectado (malicious/suspicious)
      False -> não detectado (harmless/undetected)
      None  -> omisso/timeout/failure/type-unsupported/ausente
    """
    if not entry or not isinstance(entry, dict):
        return None
    cat = (entry.get("category") or "").lower()
    if cat in ("malicious", "suspicious"):
        return True
    if cat in ("harmless", "undetected"):
        return False
    return None

def tabela_files(file_json_path: Path) -> Dict[str, Optional[bool]]:
    """
    Emula seu `tabela_files(file)`: retorna dict {engine_name: True/False/None}
    Lemos attributes.last_analysis_results do JSON salvo (formato VT v3).
    Seu JSON salvo deve ser o objeto "data" do VT; se for o envelope completo, tentamos ajustar.
    """
    data = ler_json(file_json_path)
    if not data:
        return {}

    if "attributes" not in data and "data" in data and isinstance(data["data"], dict):
        data = data["data"]

    results = (
        data.get("attributes", {}).get("last_analysis_results", {}) if isinstance(data, dict) else {}
    )
    out = {}
    if isinstance(results, dict):
        for eng, entry in results.items():
            out[str(eng)] = status_engine(entry)
    return out

def coletar_arquivos_json(base: Path):
    """
    Coleta todos os .json recursivamente (VirusTotal/<Família>/<Malware>/arquivo.json)
    """
    if not base.exists():
        raise SystemExit(f"Diretório não encontrado: {base}")
    return sorted(p for p in base.rglob("*.json") if p.is_file())

def main():
    # 1) Carrega todos os JSONs e monta "resultado" como no seu script:
    #    resultado = { "<arquivo>.json": {engine: True/False/None, ...}, ... }
    arquivos = coletar_arquivos_json(dir_entrada)
    if not arquivos:
        raise SystemExit("Nenhum JSON encontrado em dir_entrada.")

    resultado = {}
    engine_set = set()

    for fjson in arquivos:
        per_file = tabela_files(fjson)
        resultado[fjson.name] = per_file
        engine_set.update(per_file.keys())

    list_antivirus = sorted(engine_set, key=str.lower)

    # 2) Monta resultado_antivirus = { engine: [status_por_arquivo_na_ordem], ... }
    resultado_antivirus = {}
    ordered_files = [p.name for p in arquivos]  # ordem determinística

    for eng in list_antivirus:
        parcial = []
        for fname in ordered_files:
            val = resultado.get(fname, {}).get(eng, None)
            parcial.append(val)
        resultado_antivirus[eng] = parcial

    # 3) Agrega contagens por engine (detectado/n_detectado/omisso) e calcula % sobre total de arquivos
    total_files = len(ordered_files)
    ranking_rows = []
    for eng in list_antivirus:
        vals = resultado_antivirus[eng]
        det = sum(1 for v in vals if v is True)
        ndet = sum(1 for v in vals if v is False)
        om = sum(1 for v in vals if v is None)

        pct_det = round(100.0 * det / total_files, 2)
        pct_nd  = round(100.0 * ndet / total_files, 2)
        pct_om  = round(100.0 * om / total_files, 2)

        ranking_rows.append({
            "Antivírus": eng,
            "Detectado": pct_det,
            "Não Detectado": pct_nd,
            "Omisso": pct_om,
            "Detectado (abs)": det,
            "Não Detectado (abs)": ndet,
            "Omisso (abs)": om,
        })

    df = pd.DataFrame(ranking_rows).set_index("Antivírus")
    # Ordena como você fazia: por % Detectado desc (e como critério secundário, menos omissos)
    df.sort_values(by=["Detectado", "Omisso"], ascending=[False, True], inplace=True)

    # 4) Salva Excel (como no seu script)
    out_xlsx = f"{dir_entrada.name}_Ranking.xlsx"  # ex.: "VirusTotal_Ranking.xlsx"
    with pd.ExcelWriter(out_xlsx, engine="openpyxl") as writer:
        df.to_excel(writer, sheet_name=f"Resultados {dir_entrada.name}")

        # (Opcional) adiciona uma aba com metadados
        meta = pd.DataFrame(
            [{"Total de arquivos": total_files, "Arquivos (JSON)": len(arquivos)}]
        )
        meta.to_excel(writer, sheet_name="Resumo", index=False)

    print(f"Arquivos processados: {total_files}")
    print(f"Arquivo gerado: {out_xlsx}")

if __name__ == "__main__":
    main()
