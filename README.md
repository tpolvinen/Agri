# Agri
*You can find the work in progress -files of my thesis in folder `source`. In there, `oppari.md` is an old, first try of literature survey and `luonnos.md` is the current working file where I'm gathering my new sources and refactored things.*

This repository holds my research of applications of AIoT-technologies (Agriculture Internet of Things) in southern Finland. As of end of May 2017, research plan was accepted as a starting point and initial plan for my bachelor's thesis and this repository will be refactored to better suit that purpose.

Initially this research consistst of only a literature survey for a theoretical background as this is written for a three credit research 101-ish course. For the purpose of my thesis on the same subject, research plan will be refactored to include more interviews and more in-depth literature survey.

The purpose of my initial research is to prepare me for my planned thesis on the same subject.
The purpose of my thesis is to give reader a view of current state of research and practical applications of AIoT technologies on the field of plant production.

## Workflow with Markdown, Pandoc, Zotero & BetterBiBLaTeX
As a side note, I just hate Word. My school requires that everyone turns in their thesis and most of their essays, reports and whatnot in Word (.docx) files. Well, technically it's allowed to turn in a PDF, but we only get a valid template file in .docx. 

Therefore I'm testing a few workflows and tools like Pandoc and Zotero for scientific writing in order to 
* do the actual writing in a text editor of my choice
* bibliography in a bibliography application
* use the Word template file as a template file for conversion only
* keep the text, template and bibliography files in version control
* ...and finally, convert the text file with bibliography and citations in to Word format and add final touches to make it formally acceptable.

This should make the writing process a bit more bearable. I **know** that if I would make a proper LaTeX template file to replace the Word monstrosity I could almost altogether skip the final step of adding front-, toc- and abstract pages and whatnot, but RIGHT NOW I can't do it well and fast enough for it to seem profitable to me.

Also, DISCLAIMER: This is not (yet, at least) a guide how to do it, but rather a couple notes for my own reference.

For more information, please see [Chris Krycho's blog post](http://www.chriskrycho.com/2015/academic-markdown-and-citations.html)
and [Pandoc User Manual -Citations](http://pandoc.org/MANUAL.html#citations)

What we need to produce a half decent .docx file with text editor, Pandoc & bibliography application are (I'm using SublimeText & Zotero for now):

* a markdown `textSource.md` file for text content with citation keys picked from bibliography
* a bibliography `bibliography.bib` file --exported from Zotero in BetterBiBLaTex format (Zotero needed a plugin for that)
* a citation style `harvard1.csl` file to render citations --in this case I've initially used Harvard Reference format 1 (author-date)
* a reference `template.docx` file for styles of final document (sadly, Pandoc does not take page layout from .docx reference file so I may have to rustle up my own LaTeX reference file for that)
Note that you may name your files any way you like, but since we're using a command line tool like Pandoc let's not use spaces in file names. Also, special characters, dashes, dots and all things fancy should be avoided. :)

Next, the commands I've used to test things:

```
pandoc textSource.md -f markdown -t docx --reference-docx=template.docx --toc -o output.docx
```
↑ Which is to test that I can use a reference `template.docx` with `textSource.md` file in order to produce a new `output.docx` file that has the contents of `textSource.md` file with styles taken from reference `template.docx`. NOTE: with Word (.docx) reference file only **styles** will be applied to the resulting file and NOT the page format/layout. 

```
pandoc revelation.md --smart --standalone \
--bibliography /Users/chris/Dropbox/writing/library.bib \
--csl=/Users/chris/Dropbox/writing/chicago.csl -o revelation.docx
```
↑ Which is (from Chris Krycho's blog) to be used as a reference how to apply a bibliography file in .bib format (in my case, BetterBiBLaTeX exported from Zotero).

```
pandoc source/textSource.md --smart --standalone --bibliography=bib/bibliography.bib --csl=style/harvard1.csl -o output/tPolvinenOutput.docx
```
↑ Which is to produce a .docx file from content in `textSource.md` file combined with bibliography in `bibliography.bib` file. Note the folders `source`, `bib` and `style` where text source, bibliography and style files are located in and that the final file will be in `output` folder. You may put them anywhere you like, just write the paths in the command.

## TL;DR
The Pandoc command...
```
pandoc source/textSource.md --smart --standalone --bibliography=bib/bibliography.bib --csl=style/harvard1.csl --reference-docx=template/template.docx -o output/output.docx
```
↑ ...which will produce final(ish) `output.docx` file rom content in `textSource.md` file combined with bibliography in ´bibliography.bib´ file, with styles from reference file `template.docx`.

```
pandoc source/Tutkimusraportti.md --smart --standalone --bibliography bib/agri.bib --csl=style/harvard1.csl --reference-docx=template/template.docx -o output/tPolvinenTutkimusraporttiZ.docx
```
↑ For my own reference, the command with my own files & folder structure.
