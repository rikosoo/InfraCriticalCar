# Refreshing the related work

The related-work section rests on the canonical literature (Phillips & Swiler,
Sheyner, MulVAL, Wang's probabilistic metrics, IEC 62443, ATT&CK, the ICS kill
chain) and every entry in `paper/references.bib` was checked. What it does not
yet have is the last two to three years, and a journal will require currency.
This is a job for someone with database access; here is the search to run.

## Where to search

Scopus or Web of Science for coverage, IEEE Xplore and the ACM Digital Library
for venue-specific work, and Google Scholar only to chase citations of a paper
you already trust. Restrict to 2023 onward — everything older is either already
cited or genuinely superseded.

## Queries

```
("attack graph" OR "attack path" OR "attack tree")
  AND ("industrial control" OR "operational technology" OR ICS OR SCADA OR manufacturing)
  AND PUBYEAR > 2022

("risk quantification" OR "risk assessment") AND ("attack graph" OR "Bayesian network")
  AND (IEC 62443 OR "critical infrastructure" OR manufacturing)
  AND PUBYEAR > 2022

("MITRE ATT&CK" OR "ATT&CK for ICS") AND (mapping OR "threat model" OR prioriti*)
  AND PUBYEAR > 2022

(automotive OR "vehicle manufacturing" OR "smart factory" OR "Industry 4.0")
  AND (cybersecurity OR "cyber risk") AND (production OR plant OR "supply chain")
  AND PUBYEAR > 2022
```

Also check, by hand, the last two years of: Computers & Security, International
Journal of Critical Infrastructure Protection, IEEE Transactions on Industrial
Informatics, IEEE Access, Reliability Engineering & System Safety, and the
proceedings of ACM CPSS, ACSAC and ESORICS.

## Inclusion criteria

Include a paper if it does at least one of: builds or generates attack graphs
for OT or manufacturing; quantifies risk over such a graph; maps ATT&CK for ICS
onto a reference architecture; or models supply-chain propagation of cyber
disruption in manufacturing. Exclude pure intrusion-detection papers, anomaly
detection on process data, and vehicle-internal (CAN bus, ECU) security — the
last is what the paper's introduction already distinguishes itself from.

Target: 12 to 20 new references. Fewer and the section looks dated; more and it
becomes a survey the paper is not.

## What to do with each one

For every paper kept, write one sentence answering: *what does it do that CAPM
does not, or what does CAPM do that it does not?* Three outcomes:

1. **It supports a claim already made** — add the citation to the existing
   sentence in section II.
2. **It is close to CAPM** — it must be discussed explicitly in section II.B and
   distinguished. This is the most valuable kind and the most dangerous to miss:
   a reviewer who knows that paper and does not see it cited will assume you do
   not know the field.
3. **It contradicts a finding** — say so in the discussion. A contradicted
   finding that is acknowledged reads as rigour; one that is missed reads as
   carelessness.

Add entries to `paper/references.bib` in the existing style (DOI where one
exists) and cite them in `paper/body.tex` — both language editions read the same
bibliography, so nothing else needs updating.

## A check before submitting

`grep -c '@' paper/references.bib` should have grown by roughly the number you
added, and the lint used throughout this project will tell you if anything is
cited but missing, or present but uncited:

```bash
python3 - <<'PY'
import re
doc = open('paper/body.tex').read() + open('paper/abstract.tex').read()
bib = set(re.findall(r'@\w+\{([^,]+),', open('paper/references.bib').read()))
cited = set()
for c in re.findall(r'\\cite\{([^}]+)\}', doc.replace('%\n', '')):
    cited.update(x.strip() for x in c.split(','))
print('cited but missing:', sorted(cited - bib))
print('present but uncited:', sorted(bib - cited))
PY
```
