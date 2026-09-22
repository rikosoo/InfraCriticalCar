# IJCIP submission package

Everything needed to submit *From Cloud to Assembly Line* to the
**International Journal of Critical Infrastructure Protection** (Elsevier,
Editorial Manager). The text is the shared `../body.tex`; only the journal's
front matter, declarations and separate documents live here, so the manuscript
never drifts from the other editions.

## Why this journal, and how it is free

IJCIP is **hybrid**. The subscription route costs nothing: no submission fee,
no article processing charge. The fee only appears if you choose **Open Access**
at the licensing step after acceptance — so at that step, choose the
subscription (non-OA) option. Your institution may have a Read & Publish
agreement that makes OA free too; check before declining it, but the default
answer for a free publication is subscription.

Scope fit is genuine rather than argued: the paper models cross-sector
propagation and just-in-time cascading failure from supplier to OEM, combines
engineering with the regulatory language of IEC 62443 and NIST CSF, and treats a
sector regulators have recently brought inside critical-infrastructure
obligations.

## Build everything

```bash
cd paper/ijcip
for f in manuscript manuscript-blinded title-page cover-letter; do
  pdflatex $f && bibtex $f && pdflatex $f && pdflatex $f
done
python3 ../../experiments/check_submission.py
```

The checker enforces the journal's mechanics: abstract at or under 250 words,
three to five highlights of at most 85 characters, manuscript inside the
5,000–10,000 word range, and no author identity anywhere in the blinded PDF.

## What to upload, in order

| # | Editorial Manager item | File | Notes |
|---|---|---|---|
| 1 | Cover Letter | `cover-letter.pdf` | Fill the bracketed parts first: AI declaration, prior submission, suggested reviewers |
| 2 | Title Page | `title-page.pdf` | The only file that names you: author, affiliation, ORCID, corresponding author, funding |
| 3 | Manuscript | `manuscript-blinded.pdf` | Use the blinded file if the journal runs double-blind review; otherwise `manuscript.pdf` |
| 4 | Highlights | `highlights.txt` | Paste the five lines into the form, or upload the file |
| 5 | Declarations | inside the manuscript | Competing interest, funding, data availability and generative AI are already sections of the manuscript; the form repeats them |
| 6 | Supplementary (optional) | link to the artefact repository | Reviewers who run it are the ones who believe the numbers |

## Before you click submit

1. **`../authors.tex`** — name, affiliation, city, country, e-mail, ORCID. Every
   file here reads it.
2. **`cover-letter.tex`** — the three bracketed passages. If the paper was
   submitted and rejected elsewhere, Elsevier expects you to say so, summarise
   the changes and attach the previous decision letter.
3. **`declarations.tex`** — complete the generative-AI declaration with the tool
   and the purpose. It is a policy requirement, not a formality, and the
   statement of responsibility is what makes it acceptable.
4. **Funding** — the placeholder says no specific grant. Correct it if untrue.
5. Run the checker one last time and rebuild all four PDFs.

## Current status of the package

Measured by `experiments/check_submission.py`:

- abstract: 240 words (limit 250)
- highlights: 5, longest 84 characters (limit 85)
- manuscript: about 5,460 words excluding references (range 5,000–10,000)
- blinded PDF: no author identity, no repository URL
- sections numbered by `elsarticle`, citations numbered in Elsevier style

What is **not** done, and is not mechanical: the parameter elicitation
(`docs/elicitation-protocol.md`) and the related-work refresh
(`docs/literature-update.md`). A journal at this level will ask about both.
