# What I still need from you

> **Block 1 is done** (received 26 September 2026): author, affiliation,
> ORCID, e-mail, no co-authors, no funding, no acknowledgements, no prior
> submission, generative-AI declaration approved. The package is mechanically
> complete. What remains is Block 2, which is scientific rather than
> administrative.

Fill this in and send it back. Everything in **Block 1** is required before the
paper can be submitted at all; **Block 2** is what decides whether it survives
peer review; **Block 3** is optional but cheap.

Copy the block, fill the values after each colon, and paste it back. Leave a
line blank if it does not apply and I will use the safe default noted.

---

## Block 1 — Identity and declarations (blocks submission; ~15 minutes)

```
AUTHOR
  Full name as it should be published:
  Department / school (if any):
  Institution:
  City:
  Country:
  E-mail (the one you will use in Editorial Manager):
  ORCID (0000-0000-0000-0000; create one free at orcid.org if you have none):

CO-AUTHORS (repeat the block above for each, in the order they should appear;
leave empty if you are the sole author):

CORRESPONDING AUTHOR (default: you):

FUNDING
  Funder and grant number, if any:
  (leave blank and I keep: "This research received no specific grant from any
   funding agency in the public, commercial or not-for-profit sectors")

ACKNOWLEDGEMENTS
  People or institutions to thank, and how they should be named:
  (leave blank and I remove the section rather than leave a placeholder)

PRIOR SUBMISSION
  Was this manuscript submitted to another journal before?  yes / no
  If yes: which journal, the decision, and can you attach the decision letter?
  (Elsevier expects this disclosed in the cover letter, with a summary of what
   changed)

GENERATIVE AI DECLARATION
  Elsevier requires the tool and the purpose. Based on how this work was
  actually produced, I propose:

    "During the preparation of this work the author used Claude (Anthropic) to
     assist with drafting and editing the manuscript text and with implementing
     and testing the accompanying software artefact. After using this tool the
     author reviewed and edited the content as needed and takes full
     responsibility for the content of the publication."

  Approve as written?  yes / adjust like this:

SUGGESTED REVIEWERS (optional, 3-5; not recent co-authors, not same institution)
  Name, affiliation, e-mail, one line on why they fit:
```

---

## Block 2 — What determines the review outcome

### 2.1 Elicitation panel (the single biggest gap)

The model's probabilities are currently my estimates and the paper says so. Send
me **one filled CSV per expert** (3 to 5 people, ~45 min each) and I run the
aggregation, re-run the whole study on the elicited values, and write the
subsection describing the procedure.

- The form is already generated: `data/elicitation_form.csv`
- The protocol, including what to tell respondents, is `docs/elicitation-protocol.md`
- Send them as separate files. Do not merge them: the disagreement between
  respondents is the measurement.

Also send, for the paper's method subsection:

```
PANEL
  Number of respondents:
  Role of each, anonymised (e.g. "OT engineer at a Tier-1 supplier",
    "SOC analyst at an OEM", "incident responder, consultancy"):
  Years of experience of each, roughly:
  Did any employer require approval, and was it given?  yes / no / n/a
```

### 2.2 References to add (needs your database access)

I cannot verify bibliographic metadata from this environment: the network policy
blocks Crossref, arXiv, Springer, IEEE, ACM, ScienceDirect and doi.org. Ten
candidates are listed in `docs/literature-candidates.md`.

For each paper you decide to cite, send me a line in this exact shape and I will
format it, insert it into `references.bib` and cite it in the right place:

```
Authors (full list, as printed) | Title | Journal or conference | Year | Volume(Issue) | Pages or article number | DOI
```

Tell me for each one which of the three applies: it supports a claim we already
make, it is close enough to need discussion in section 2.2, or it contradicts a
finding of ours.

### 2.3 Incident corpus verification

The 20 records are in `data/incidents.csv` with the source URL of each. Open
them and confirm or correct: dates, victim name, duration of disruption, number
of vehicles or plants, economic figures, entry vector and attribution.

The four to check first, because they carry the weakest labels:

- `INC-18` Jaguar Land Rover — entry vector labelled **disputed**
- `INC-02` Honda 2017 — internal propagation labelled **low**
- `INC-03` Honda 2020 — internal propagation labelled **low**
- `INC-06` Bridgestone — internal propagation labelled **low**

Send corrections as `INC-xx: field → corrected value (source URL)`. If a source
has gone dead, say so and I will mark the record accordingly.

---

## Block 3 — Optional, cheap, and it helps

```
ARTEFACT
  Should the GitHub repository be public at submission?  yes / no
  (reviewers who can run it are the ones who believe the numbers; if it stays
   private I will remove the claim that it is openly available)

  Do you want a citable DOI for the artefact?  yes / no
  (link the repository to Zenodo, cut a release, and send me the DOI; it takes
   about ten minutes and makes the artefact citable and permanent)

INSTITUTION
  Does your institution have a Read & Publish agreement with Elsevier?
  (if yes, open access may cost you nothing; if no or unknown, I keep the paper
   on the subscription route, which is free to publish)

LANGUAGE
  Do you want the Portuguese edition kept in step with every change?  yes / no
```

---

## What happens when you send it

1. Block 1 alone: I fill `paper/authors.tex`, the title page, the cover letter
   and the declarations, rebuild all nine PDFs and re-run the submission checks.
   The package is then mechanically complete and you can submit.
2. Block 2.1: I re-run the full study on the elicited parameters, regenerate
   every table and figure, and write the elicitation subsection. Some numbers in
   the paper will change, and if a conclusion changes, that becomes a result
   worth reporting.
3. Block 2.2 and 2.3: I update the bibliography, the related-work section and
   the corpus, and re-run the consistency checks.

Block 1 is enough to submit. Blocks 2.1 to 2.3 are what a reviewer at this
journal will probe, and the honest advice is not to submit without at least
having started the elicitation.
