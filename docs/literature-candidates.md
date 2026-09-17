# Candidate references for the related-work refresh

**Status: unverified. Do not cite from this file.**

Searches run on 17 September 2026 from a session whose egress policy blocks
Crossref, arXiv, Springer, IEEE Xplore, the ACM Digital Library, ScienceDirect,
MDPI, DBLP, OpenAlex and doi.org. Titles and venues below are as they appeared
in search results; **author lists, volume, page and DOI could not be confirmed
from a primary source**, and a citation is not a citation until they are. Every
line needs one lookup in Scopus, IEEE Xplore or the publisher's own page before
it goes anywhere near `paper/references.bib`.

The purpose of this file is to save you the search, not the verification.

## Queries used

```
attack graph industrial control systems risk assessment 2024 2025
  ("Computers & Security" OR "International Journal of Critical Infrastructure Protection")
"ATT&CK for ICS" mapping threat modeling OT security 2024 2025 attack graph generation
cyber risk quantification manufacturing production disruption model 2024 2025
IEC 62443 zones conduits security risk assessment method 2024 2025 OT segmentation
```

`docs/literature-update.md` has the full query set, the venues to hand-search
and the inclusion criteria; this file is the first harvest from it.

## Candidates

| # | Title as returned | Venue as reported | Where it appeared | Why it matters here |
|---|---|---|---|---|
| 1 | A cybersecurity risk assessment methodology for industrial automation control systems | International Journal of Information Security (2025) | link.springer.com/article/10.1007/s10207-025-00990-9 | IEC 62443-based risk assessment: closest neighbour to our control mapping; must be discussed, not just cited |
| 2 | Security Aspects of Zones and Conduits in IEC 62443 | Journal of Cybersecurity and Privacy | mdpi.com/2624-800X/6/2/52 | Directly addresses the zone-and-conduit model our section VII argues should be widened |
| 3 | Cybersecurity for smart and resilient manufacturing and supply chains: a systematic review | ScienceDirect (review) | sciencedirect.com/science/article/pii/S0360835226004456 | A recent review; use it to check we have not missed a whole strand |
| 4 | Proactive cybersecurity in Industry 4.0: a survey of threat prediction approaches in manufacturing | International Journal of Information Security (2025) | link.springer.com/article/10.1007/s10207-025-01188-9 | Survey of manufacturing threat modelling; positions our contribution |
| 5 | Cyberattacks and the risk to production and service systems, from the perspective of quality management | The TQM Journal | emerald.com/tqm/.../TQM-07-2024-0233 | Production-side consequence modelling; relevant to our consequence model |
| 6 | Cyber security of OT networks: a tutorial and overview | arXiv preprint 2502.14017 | arxiv.org/pdf/2502.14017 | Preprint: cite only if it has since appeared in a venue |
| 7 | Dynamic Vulnerability Criticality Calculator for Industrial Control Systems | arXiv preprint 2404.16854 | arxiv.org/pdf/2404.16854 | Vulnerability-centric prioritisation: a possible fifth baseline for E7 |
| 8 | MITRE ATT&CK: state of the art and way forward | arXiv preprint 2308.14016 | arxiv.org/pdf/2308.14016 | ATT&CK methodology critique; check for a published version |
| 9 | Multi-level risk assessment in additive manufacturing systems | International Journal of Production Research (2025) | tandfonline.com/doi/full/10.1080/00207543.2025.2507107 | Multi-level manufacturing risk: adjacent method, different process |
| 10 | Attack graph-based quantitative assessment for industrial control system security | IEEE (conference) | ieeexplore.ieee.org/document/9327842 | Older but directly comparable; check date before calling it recent |

## What to do with each

For every row: confirm it exists, capture the real author list and DOI, read the
abstract, and decide which of the three outcomes in `docs/literature-update.md`
applies — supports an existing claim, is close enough to need discussion in
section II.B, or contradicts a finding. Rows 1, 2 and 7 are the ones most likely
to require a paragraph rather than a citation: the first two overlap our IEC
62443 framing, and the third is a candidate extra baseline for experiment E7.

Delete a row once it is either in `references.bib` or ruled out, and note why in
the commit message. When this file is empty the refresh is done.
