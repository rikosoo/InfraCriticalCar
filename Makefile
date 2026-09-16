PYTHON ?= python3

.PHONY: all experiments figures model test paper clean

all: experiments figures model test

## run the full experiment pipeline (E1-E6): tables, SVG figures, summary.json
experiments:
	$(PYTHON) experiments/run_all.py

## quick run with fewer Monte Carlo trials (for development)
quick:
	$(PYTHON) experiments/run_all.py --quick

## regenerate the pgfplots figures used by the paper
figures:
	$(PYTHON) experiments/make_tex_figures.py

## dump the full model specification for review
model:
	$(PYTHON) experiments/export_model.py

## run the test suite
test:
	$(PYTHON) -m pytest

## build the paper (requires a TeX distribution with IEEEtran and pgfplots)
paper:
	cd paper && pdflatex -interaction=nonstopmode main.tex \
		&& bibtex main && pdflatex -interaction=nonstopmode main.tex \
		&& pdflatex -interaction=nonstopmode main.tex

clean:
	rm -rf __pycache__ */__pycache__ .pytest_cache
	rm -f paper/*.aux paper/*.bbl paper/*.blg paper/*.log paper/*.out
