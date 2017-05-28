# Agri

This repository holds my research for a study of applications of AIoT-technologies (Agriculture Internet of Things) in southern Finland. As of end of May 2017, research plan was accepted as a starting point and initial plan for my bachelor's thesis and this repository will be refactored to better suit that purpose.

Initially this research consistst of only a literature survey for a theoretical background and a single themed interview as this is written for a three credit research 101-ish course. For the purpose of my thesis on the same subject, research plan will be refactored to include more interviews and more in-depth literature survey.

The purpose of my initial research is to prepare me for my planned thesis on the same subject.
The purpose of my thesis is to give reader a view of current state of research and practical applications of AIoT technologies on the field of plant production.

## Workflow with Markdown, Pandoc, Zotero & BetterBiBLaTeX
As a side note, I'm also testing a few workflows and tools like Pandoc and Zotero for scientific writing to make the writing of my thesis a bit more bearable. This is not (yet, at least) a guide how to do it, but rather a couple notes for my own reference.

For more information, please see [Chris Krycho's blog post](http://www.chriskrycho.com/2015/academic-markdown-and-citations.html)
and [Pandoc User Manual -Citations](http://pandoc.org/MANUAL.html#citations)

Here are the commands I've used to produce a final .docx file with Pandoc using 
* a markdown .md file for text content with citation keys picked from bibliography
* a .bib bibliography file exported from Zotero in BetterBiBLaTex format (Zotero needed a plugin for that)
* a citation style .csl file to render citations, in this case I've initially used Harvard Reference format 1 (author-date)
* a reference .docx file for styles (sadly, Pandoc does not take page layout from .docx reference file so I'll have to rustle up my own LaTeX reference file for that)

This is to test that I can use a reference .docx with .md-file in order to produce a new .docx file that has the contents of .md file with styles taken from reference .docx. NOTE: with .docx reference file only **styles** will be applied to the resulting file and NOT the page format/layout. 
```
pandoc AIHE-EHDOTUS.md -f markdown -t docx --reference-docx=aihepohja.docx --toc -o tPolvinenAiheEhdotus.docx
```

This is (from Chris Krycho's blog) to be used as a reference how to apply a bibliography file in .bib format (in my case, BetterBiBLaTeX exported from Zotero).
```
pandoc revelation.md --smart --standalone \
--bibliography /Users/chris/Dropbox/writing/library.bib \
--csl=/Users/chris/Dropbox/writing/chicago.csl -o revelation.docx
```
Here are the paths to my files just in case I'm too lazy to type them.
```
/Users/tatu/Documents/MaatalousIoT/bib/MaatalousIoT.bib
/Users/tatu/Documents/MaatalousIoT/pohja/pohja.docx
/Users/tatu/Documents/MaatalousIoT/style/harvard1.csl
```
This is to make a .docx file from content in .md file combined with bibliography in .bib file.
```
pandoc Tutkimussuunnitelma2017-03-14.md --smart --standalone --bibliography /Users/tatu/Documents/MaatalousIoT/bib/MaatalousIoT.bib --csl=/Users/tatu/Documents/MaatalousIoT/style/harvard1.csl -o tPolvinenTutkimussuunnitelma.docx
```
## TL;DR
Finally, this is to make final(ish) .docx file rom content in .md file combined with bibliography in .bib file, with styles from reference .docx file.
```
pandoc Tutkimussuunnitelma2017-03-14.md --smart --standalone --bibliography /Users/tatu/Documents/MaatalousIoT/bib/MaatalousIoT.bib --csl=/Users/tatu/Documents/MaatalousIoT/style/harvard1.csl --reference-docx=/Users/tatu/Documents/MaatalousIoT/pohja/pohja.docx -o tPolvinenTutkimussuunnitelma.docx
```

And the rest, as they say, is in Finnish.
