# Agri

This repository holds my research plan for a study applications of AIoT-technologies (Agriculture Internet of Things) in Finland. 
This research consistst of only a literature survey for a theoretical background and a single themed interview. 
The purpose of this research is to prepare me for my planned thesis on the same or like subject.
As a side note, I'm also testing a few workflows and tools like Pandoc and Zotero for scientific writing to make the writing of my thesis a bit more bearable.

Here are the commands I've used to produce a final .docx file with Pandoc using 
* a markdown .md file for text content with citation keys picked from bibliography
* a .bib bibliography file exported from Zotero in BetterBiBLaTex format (Zotero needed a plugin for that)
* a reference .docx file for styles (sadly, Pandoc does not take page layout from .docx reference file so I'll have to rustle up my own LaTeX reference file for that)
* 

This is to test that I can use a reference .docx with .md-file in order to produce a new .docx file that has the contents of .md file with styles taken from reference .docx. NOTE: with .docx reference file only **styles** will be applied to the resulting file and NOT the page format/layout. 
pandoc AIHE-EHDOTUS.md -f markdown -t docx --reference-docx=aihepohja.docx --toc -o tPolvinenAiheEhdotus.docx

This is to be used as a reference how to apply a bibliography file in .bib format (in my case, BetterBiBLaTeX exported from Zotero).
pandoc revelation.md --smart --standalone \
--bibliography /Users/chris/Dropbox/writing/library.bib \
--csl=/Users/chris/Dropbox/writing/chicago.csl -o revelation.docx

Here are the paths to my files just in case I'm too lazy to type them.
/Users/tatu/Documents/MaatalousIoT/bib/MaatalousIoT.bib
/Users/tatu/Documents/MaatalousIoT/pohja/pohja.docx
/Users/tatu/Documents/MaatalousIoT/style/harvard1.csl

This is to make a .docx file from content in .md file combined with bibliography in .bib file.
pandoc Tutkimussuunnitelma2017-03-14.md --smart --standalone --bibliography /Users/tatu/Documents/MaatalousIoT/bib/MaatalousIoT.bib --csl=/Users/tatu/Documents/MaatalousIoT/style/harvard1.csl -o tPolvinenTutkimussuunnitelma.docx

Finally, this is to make final(ish) .docx file rom content in .md file combined with bibliography in .bib file, with styles from reference .docx file.
pandoc Tutkimussuunnitelma2017-03-14.md --smart --standalone --bibliography /Users/tatu/Documents/MaatalousIoT/bib/MaatalousIoT.bib --csl=/Users/tatu/Documents/MaatalousIoT/style/harvard1.csl --reference-docx=/Users/tatu/Documents/MaatalousIoT/pohja/pohja.docx -o tPolvinenTutkimussuunnitelma.docx


And the rest, as they say, is in Finnish.
