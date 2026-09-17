# From Cloud to Assembly Line

**Modelling Cyberattack Paths in Automotive Manufacturing as Critical Infrastructure**

This repository contains a complete academic artefact: an attack-path model of
an automotive assembly plant (`capm/`), a curated corpus of 20 publicly
reported incidents in the sector between 2017 and 2025 (`data/incidents.csv`),
a reproducible experiment pipeline (`experiments/`), a test suite (`tests/`)
and the paper itself (`paper/main.tex`).

The premise: vehicle cybersecurity research and regulation (ISO/SAE 21434,
UN R155) govern the *car*. The *factory* that builds it — whose failure stops
output, starves a continental supply chain and, in the 2025 Jaguar Land Rover
case, cost an economy an estimated £1.9 billion — is governed by nothing
comparable and is under-modelled in the literature. This work treats the plant
as critical infrastructure and asks which paths actually reach the assembly
line.

## Headline findings

| # | Finding | Evidence |
|---|---------|----------|
| F1 | **The path of least resistance never touches a controller.** The most likely route to a production stoppage is `actor → Tier-1 supplier → EDI/JIT interface → line stopped` (L = 0.047), **11.6× more likely** than the most likely route that reaches Purdue level 2 or below. | E1 |
| F2 | **The model agrees with the record.** All 20 corpus incidents are expressible as model paths, and the median incident sits at the **4.8th percentile** of all modelled paths to the same consequence. A leave-one-out ablation keeps 65% of them (75% for internal propagation only). | E2 |
| F3 | **The choke points are business systems.** Engineering workstation (0.27 of likelihood mass), employee workstation (0.23), VPN gateway (0.16), Tier-1 supplier IT (0.15), ERP (0.14). | E3 |
| F4 | **Partial hardening displaces risk.** A supply-chain-and-cloud programme cuts espionage loss by **73%** while *raising* ransomware loss by **26%**: removing cheap data-theft objectives concentrates a rational actor on the availability objective. | E4 |
| F5 | **Recovery beats prevention in expected-loss terms**, and the controls that look worthless alone are the least removable ones in a mature programme (SaaS token governance, supplier assurance). | E5 |
| F6 | **Detection efficacy is the dominant parameter**: halving it multiplies annualised loss by 3.7. Qualitative conclusions survive parameter perturbation; the precise ordering of the top ten paths does not. | E6 |

Corpus descriptive statistics: **55%** of the 20 incidents caused a production
impact, **40%** traversed the supply-chain plane, and only **10%** are reported
to have interacted with equipment below Purdue level 3.

## Repository layout

```
capm/                  the model (pure Python 3.9+, zero dependencies)
  model.py             graph/asset/edge/path types and probability semantics
  architecture.py      the reference plant: 12 zones, 48 assets, 91 attack steps
  techniques.py        MITRE ATT&CK Enterprise + ATT&CK for ICS catalogue
  controls.py          17 controls mapped to IEC 62443-3-3 and NIST CSF 2.0
  paths.py             Dijkstra / Yen k-best paths, enumeration, choke points
  risk.py              Monte Carlo campaign simulation, actor profiles, ALE
  incidents.py         corpus loader, reconciliation, leave-one-out ablation
  report.py            CSV, LaTeX table and SVG figure writers
  cli.py               command-line exploration of the model
data/incidents.csv     the empirical corpus, with sources and confidence labels
experiments/run_all.py the full pipeline (E1–E6) -> tables, figures, summary.json
experiments/build_paper_assets.py LaTeX tables and pgfplots figures, in English and Portuguese
experiments/export_model.py      full parameter dump -> data/model_*.csv, docs/model-reference.md
docs/model-reference.md          every zone, control and attack step with its parameters
paper/body.tex         the paper's text, shared by every edition
paper/main.tex         IEEE conference edition; paper-ieee-journal.tex, paper-sae.tex,
                       paper-elsevier.tex and main-pt.tex are the other editions
paper/README.md        which edition is which, and a pre-submission checklist
paper/references.bib   the shared bibliography
capm/i18n.py           pt-BR renderings of asset, control and scenario names
tests/                 pytest suite (42 tests, including a cross-process reproducibility guard)
```

## Reproducing everything

A `Makefile` wraps the same commands (`make experiments assets model test`).

```bash
python3 experiments/run_all.py          # ~10 min, 20k Monte Carlo campaigns per configuration
python3 experiments/build_paper_assets.py  # LaTeX tables and figures (en + pt)
python3 experiments/export_model.py     # full parameter dump for review
pytest                                  # test suite
```

No third-party packages are required. Results land in
`experiments/results/` (`tables/*.csv`, `tables/*.tex`, `figures/*.svg`,
`summary.json`) and are mirrored into `paper/tables/` and `paper/figures/`.
Every number quoted in the paper comes from `summary.json`.

## Exploring the model

```bash
python3 -m capm.cli graph
python3 -m capm.cli paths --target imp_prod_stop -k 10 --scenario S0
python3 -m capm.cli paths --target imp_safety -k 5 --scenario C05,C09,C13
python3 -m capm.cli chokepoints
python3 -m capm.cli risk --scenario S4 --profile sabotage --trials 20000
python3 -m capm.cli corpus
python3 -m capm.cli controls
```

## Building the paper

Five editions share one body of text (`paper/body.tex`) and therefore report
exactly the same numbers: IEEE conference (`main.tex`), IEEE journal
(`paper-ieee-journal.tex`), SAE (`paper-sae.tex`), Elsevier
(`paper-elsevier.tex`) and Portuguese (`main-pt.tex`). See `paper/README.md`.

```bash
cd paper && pdflatex main && bibtex main && pdflatex main && pdflatex main
```

All five compile on a stock TeX Live and on Overleaf with zero errors and zero
undefined references. The English editions read `paper/tables/` and
`paper/figures/`, the Portuguese one `paper/tables-pt/` and `paper/figures-pt/`;
both sets are generated from the same `experiments/results/`, so the editions
cannot drift apart.

## Model in one paragraph

A CAPM instance is a directed labelled graph `G = (V, E, Z, τ, p, δ, c)`: assets
`V` partitioned into IEC 62443 zones `Z`, attack steps `E` each labelled with an
ATT&CK technique `τ`, a conditional success probability `p`, a
detection-and-containment probability `δ`, and an effort `c` in hours. Path
likelihood is `L(π) = Π p(e)(1−δ(e))`; taking `−log` makes the most likely path
a shortest path, so ranking uses Dijkstra and Yen's algorithm exactly. Controls
act multiplicatively on `p` and `δ` (and, for recovery controls, on outage
duration). A Monte Carlo campaign simulation with three actor profiles
(ransomware, espionage, sabotage) converts the structure into annualised loss
expectancy, downtime distributions and time-to-consequence.

## Honest limitations

- Edge probabilities are **expert-elicited point estimates**, not measurements;
  no public dataset supports per-technique success rates in automotive OT. All
  parameters are published and all conclusions are tested under perturbation
  (E6); claims that do not survive perturbation are not made.
- The corpus rests on **public reporting**, which is biased towards incidents
  large enough to disturb production or trigger disclosure. Several
  reconstructions are labelled `low` or `disputed` on purpose.
- Because the corpus informed the graph, plain coverage is a consistency check;
  the leave-one-out ablation is the stricter test and it does not reach 100%.
- The campaign policy assumes a rational, utility-maximising actor; the risk
  displacement result (F4) depends on that assumption.

## Versão em português

O artigo existe também em português: `paper/main-pt.tex`, com tabelas e figuras
em `paper/tables-pt/` e `paper/figures-pt/`, geradas dos mesmos resultados.

## Resumo (PT-BR)

Este repositório contém um artigo acadêmico completo e o artefato que o
sustenta. A tese: a fábrica automotiva — e não o carro — é a infraestrutura
crítica sub-modelada. Construímos um modelo de caminhos de ataque que atravessa
TI corporativa, plano de identidade, nuvem/SaaS, DMZ industrial, MES/SCADA/PLC e
a cadeia de fornecimento, calibrado contra 20 incidentes públicos do setor
(2017–2025), com técnicas classificadas em MITRE ATT&CK Enterprise e ATT&CK for
ICS e controles mapeados para IEC 62443-3-3 e NIST CSF 2.0. O resultado
principal: o caminho mais provável até a parada de produção não passa por
nenhum CLP — ele passa pelo EDI de um fornecedor Tier-1 e pelo ERP —, sendo
11,6× mais provável que a melhor rota que alcança o nível 2 de Purdue. Todos os
experimentos são reprodutíveis com `python3 experiments/run_all.py`, sem
dependências externas.

## Citing

See `CITATION.cff`. The paper's artefact reference is `paper/references.bib`,
entry `capmartifact`.

## Licence

Code and data: MIT (`LICENSE`). The paper text and figures in `paper/`:
CC BY 4.0 (`paper/LICENSE`).
