# Parameter elicitation protocol

The model's `p`, `delta` and `effort` values are currently the authors' own
estimates. This is the first thing a journal reviewer will challenge, and the
answer is not to defend the numbers but to replace them with a documented
procedure. This file is that procedure; it is written so that the paper can
describe it in a subsection and a reader can repeat it.

## What you need

* **3 to 5 respondents.** Fewer than three gives no dispersion to report; more
  than five rarely changes a median. Aim for a mix: at least one OT/automation
  engineer who knows the plant floor, one IT security or SOC analyst, and one
  person who has run or observed an incident response.
* **About 45 minutes of each person's time.** The form covers the 30 steps that
  carry most of the risk mass, not all 91.
* **Nothing else.** No tooling, no plant access, no data extraction.

## Round 1

```bash
python3 experiments/elicitation.py form --limit 30
# -> data/elicitation_form.csv
```

Send **one copy per respondent** and collect them separately. Do not let them
answer together and do not merge the files: the disagreement between them is the
measurement, and a group answer destroys it.

The form deliberately leaves `current_p`, `current_delta` and `current_effort_h`
empty. Showing your own estimate would anchor the panel on it, which is the
failure mode this exercise exists to avoid.

Each row asks three questions, answered with a label or a number:

| Label | `p` — how often the step succeeds | `delta` — how often you detect **and contain** it | `effort` |
|---|---|---|---|
| VL | rarely works, even against a weak target | we would almost certainly not notice | under half a day |
| L | works occasionally, needs a specific weakness | we might notice, probably too late | about a day |
| M | works about as often as not | even chance of catching and containing | a few days |
| H | usually works against a typical plant | we would usually catch and contain it | one to two weeks |
| VH | almost always works | we would almost certainly catch it | over a month |

Two points to make to respondents before they start, because both are common
misunderstandings:

1. `p` is **conditional**: assume the attacker already controls the source
   asset. You are not estimating how likely the whole attack is.
2. `delta` is **detect *and* contain**, not detect. An alert nobody acts on
   within the attacker's dwell time is not containment.

## Aggregation

```bash
python3 experiments/elicitation.py ingest responses/*.csv
```

The median across respondents becomes the parameter; the interquartile range is
the disagreement measure. Order statistics, not means, because panels are small
and a single outlier should not move the estimate. Steps whose IQR exceeds 0.25
(for `p` and `delta`) are flagged as unresolved.

## Round 2, only for the flagged steps

Re-issue the form for the flagged steps with `--show-current`, so the panel sees
the round-1 median and the spread, and ask each person to either revise or say
why they are holding their position. Two rounds is the standard Delphi stopping
point; more rarely converges further and starts to manufacture agreement.

## Re-running the study

```bash
python3 experiments/run_all.py --overrides data/parameter_overrides.csv
python3 experiments/build_paper_assets.py
```

`data/elicitation_shift.csv` records how far each parameter moved. Report it:
the interesting result is not only the new numbers but **which conclusions
changed**, and the honest case is the one where a conclusion does change.

## What to write in the paper

A subsection of four or five sentences covering: how many respondents and their
roles (anonymised — "a Tier-1 supplier's OT engineer", not a name or employer,
unless they have agreed in writing); that answers were collected independently;
the scale; the median-and-IQR aggregation; how many steps needed a second round;
and the resulting change in the headline numbers. Add one sentence to Threats to
Validity noting the panel size and that respondents came from a limited set of
plants.

## Ethics and consent

Tell respondents in writing, before they answer, that their answers will be
published in aggregate, that no individual's answers or employer will be
identified, and that they may withdraw. Ask whether their employer requires
approval — several OEMs treat detection-capability estimates as sensitive, and
an aggregated median across an anonymous panel is usually acceptable where a
named individual estimate is not. If your institution has an ethics board, a
professional-opinion survey of this kind is normally exempt or minimal-risk, but
check rather than assume.
