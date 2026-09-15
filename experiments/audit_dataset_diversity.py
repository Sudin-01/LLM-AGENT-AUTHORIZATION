"""
Quantify prompt-set diversity for the v1 (template-expansion) and v2
(curated) datasets, so the paper can report effective diversity rather
than a raw string count.

Metrics
-------
unique_strings        distinct prompt strings
unique_patterns       distinct after removing the "(case N)" counter and
                      normalising interchangeable entities (amounts, table
                      names, file names, topics) - i.e. distinct *sentences*
vocabulary            distinct lowercase word types across the tool's prompts
ttr                   type-token ratio (vocabulary / total tokens)
mean_cos / max_cos    mean and maximum pairwise cosine similarity between
                      MiniLM sentence embeddings within a tool; a max near
                      1.0 indicates near-duplicate prompts
near_dupes            pairs with cosine >= 0.95

Usage:  python3 experiments/audit_dataset_diversity.py
"""
import os

# transformers probes TensorFlow on import; the local TF build crashes on
# machines without AVX, so disable the TF backend before importing it.
os.environ.setdefault("USE_TF", "0")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

import re
import sys
import json
import itertools

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
OUT = os.path.join(HERE, "results_dataset_v2")
os.makedirs(OUT, exist_ok=True)

ENTITY = [
    (re.compile(r"\s*\(case \d+\)\s*$"), ""),
    (re.compile(r"\$[\d,]+"), "$AMT"),
    (re.compile(r"\b(users|sessions|orders|transactions|audit_log|customers|logs|"
                r"temp_data|analytics|payments|backups|staging|test_data|archive|"
                r"metrics|cache)\b"), "TBL"),
    (re.compile(r"\b[\w./-]+\.(yaml|yml|json|conf|log|env|txt|csv|sql|sh)\b"), "FILE"),
    (re.compile(r"\b(AI safety|blockchain consensus|quantum computing|climate policy|"
                r"renewable energy|neural networks|cybersecurity threats|drug interactions|"
                r"financial regulation|genomics research|autonomous vehicles|space exploration|"
                r"machine translation|smart contracts|distributed systems|cryptography)\b"),
     "TOPIC"),
]

def pattern(s):
    for rx, rep in ENTITY:
        s = rx.sub(rep, s)
    return re.sub(r"\s+", " ", s).strip().lower()

def tokens(s):
    return re.findall(r"[a-z']+", s.lower())

def load_v1():
    import run_experiments as R
    import random
    random.seed(42)
    recs = R.generate_prompts(n_per_tool=60)
    d = {}
    for r in recs:
        d.setdefault(r.target_tool, []).append(r.prompt_text)
    return d

def load_v2():
    from prompt_dataset import PROMPTS
    return {t: [p for stratum in s.values() for p in stratum] for t, s in PROMPTS.items()}

def analyse(name, data, model):
    rows = []
    print(f"\n{'='*74}\n  {name}\n{'='*74}")
    print(f"  {'tool':18s} {'strings':>8s} {'patterns':>9s} {'vocab':>7s} "
          f"{'TTR':>6s} {'meanCos':>8s} {'maxCos':>7s} {'>=0.95':>7s}")
    tot_p = 0
    for tool, prompts in data.items():
        pats = {pattern(p) for p in prompts}
        toks = [w for p in prompts for w in tokens(p)]
        vocab = len(set(toks))
        ttr = vocab / len(toks) if toks else 0
        emb = model.encode(prompts, normalize_embeddings=True,
                           show_progress_bar=False, batch_size=64)
        sim = emb @ emb.T
        iu = np.triu_indices(len(prompts), k=1)
        pair = sim[iu]
        nd = int((pair >= 0.95).sum())
        rows.append(dict(dataset=name, tool=tool, n_prompts=len(prompts),
                         unique_strings=len(set(prompts)), unique_patterns=len(pats),
                         vocabulary=vocab, ttr=round(ttr, 4),
                         mean_cos=round(float(pair.mean()), 4),
                         max_cos=round(float(pair.max()), 4), near_dupes=nd))
        tot_p += len(pats)
        print(f"  {tool:18s} {len(set(prompts)):>8d} {len(pats):>9d} {vocab:>7d} "
              f"{ttr:>6.3f} {pair.mean():>8.3f} {pair.max():>7.3f} {nd:>7d}")
    allp = [p for v in data.values() for p in v]
    print(f"  {'TOTAL':18s} {len(set(allp)):>8d} {tot_p:>9d}")
    return rows, tot_p

def main():
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    from sentence_transformers import SentenceTransformer
    model = SentenceTransformer("all-MiniLM-L6-v2")

    v1, v2 = load_v1(), load_v2()
    r1, p1 = analyse("v1  template expansion (as published)", v1, model)
    r2, p2 = analyse("v2  curated dataset (this work)", v2, model)

    import csv
    with open(os.path.join(OUT, "diversity_audit.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(r1[0].keys())); w.writeheader()
        w.writerows(r1 + r2)

    lines = [
        "=" * 74,
        "  PROMPT-SET DIVERSITY AUDIT",
        "=" * 74,
        f"  v1 distinct sentence patterns : {p1} / 300",
        f"  v2 distinct sentence patterns : {p2} / 300",
        "",
        f"  v1 near-duplicate pairs (cos >= 0.95): "
        f"{sum(r['near_dupes'] for r in r1)}",
        f"  v2 near-duplicate pairs (cos >= 0.95): "
        f"{sum(r['near_dupes'] for r in r2)}",
        "",
        f"  v1 mean within-tool cosine : "
        f"{np.mean([r['mean_cos'] for r in r1]):.3f}",
        f"  v2 mean within-tool cosine : "
        f"{np.mean([r['mean_cos'] for r in r2]):.3f}",
        "=" * 74,
    ]
    txt = "\n".join(lines)
    open(os.path.join(OUT, "diversity_summary.txt"), "w").write(txt + "\n")
    print("\n" + txt)

if __name__ == "__main__":
    main()
