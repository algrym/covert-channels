all: covert.pdf

.SUFFIXES  : .pdf .preview .tex .dvi .xdvi .gnuplot .eps

.gnuplot.eps : 
	gnuplot $*.gnuplot

.eps.pdf :
	epstopdf $*.eps

.tex.dvi : $*.aux
	latexmk $*.tex

.dvi.xdvi : $*.tex
	xdvi $*.dvi

.tex.pdf : $*.aux
	latexmk -pdf $*.tex

.pdf.preview :
	open -a Preview $*.pdf
	sleep 1

clean:
	rm -f *.dvi *.ps *.pdf *.aux *.log *~ *.eps *.out *.bak
