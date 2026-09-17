PYTHON ?= python3

.PHONY: all experiments assets model test papers paper paper-ieee-journal paper-sae paper-elsevier paper-pt clean

all: experiments assets model test

## run the full experiment pipeline (E1-E6): tables, SVG figures, summary.json
experiments:
	$(PYTHON) experiments/run_all.py

## quick run with fewer Monte Carlo trials (for development)
quick:
	$(PYTHON) experiments/run_all.py --quick

## regenerate the LaTeX tables and figures used by both papers (en + pt)
assets:
	$(PYTHON) experiments/build_paper_assets.py

## dump the full model specification for review
model:
	$(PYTHON) experiments/export_model.py

## run the test suite
test:
	$(PYTHON) -m pytest

## build every edition (requires TeX Live with IEEEtran, elsarticle, pgfplots)
papers: paper paper-ieee-journal paper-sae paper-elsevier paper-pt

define build_paper
	cd paper && pdflatex -interaction=nonstopmode $(1).tex \
		&& bibtex $(1) && pdflatex -interaction=nonstopmode $(1).tex \
		&& pdflatex -interaction=nonstopmode $(1).tex
endef

## IEEE conference edition
paper:
	$(call build_paper,main)

## IEEE journal edition (OJVT / TVT / Access)
paper-ieee-journal:
	$(call build_paper,paper-ieee-journal)

## SAE International edition
paper-sae:
	$(call build_paper,paper-sae)

## Elsevier edition (Computers & Security, IJCIP)
paper-elsevier:
	$(call build_paper,paper-elsevier)

## Portuguese edition
paper-pt:
	$(call build_paper,main-pt)

clean:
	rm -rf __pycache__ */__pycache__ .pytest_cache
	rm -f paper/*.aux paper/*.bbl paper/*.blg paper/*.log paper/*.out
