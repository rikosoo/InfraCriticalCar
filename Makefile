PYTHON ?= python3

.PHONY: all experiments assets model test paper paper-pt clean

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

## build the English paper (requires a TeX distribution with IEEEtran and pgfplots)
paper:
	cd paper && pdflatex -interaction=nonstopmode main.tex \
		&& bibtex main && pdflatex -interaction=nonstopmode main.tex \
		&& pdflatex -interaction=nonstopmode main.tex

## build the Portuguese paper
paper-pt:
	cd paper && pdflatex -interaction=nonstopmode main-pt.tex \
		&& bibtex main-pt && pdflatex -interaction=nonstopmode main-pt.tex \
		&& pdflatex -interaction=nonstopmode main-pt.tex

clean:
	rm -rf __pycache__ */__pycache__ .pytest_cache
	rm -f paper/*.aux paper/*.bbl paper/*.blg paper/*.log paper/*.out
