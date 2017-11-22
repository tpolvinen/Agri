100_merkkiä_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx_100_merkkiä

Maatalouden kenttä on hyvin hajanainen ja pirstaleinen. Teknologioita otetaan käyttöön yksittäin, tapaus tapaukselta, eikä viljelyprosessien digitalisointi toimi samalla tavoin kuin teollisuuden prosessien kanssa. On hyvin vaikeaa tehdä kattavia yksittäisiä ratkaisuja jonka voisi ostaa kerralla ja joka kattaisi koko viljelyprosessin.

Maatilat ovat yksittäistapauksia: tuotantosuunniltaan, tilakooltaan, henkilöstöltään, historialtaan, teknologiatasoltaan, teknologiaorientoitumiseltaan hyvin erilaisia. Kentällä on otettu digitaalisia työkaluja käyttöön hyvin vaihtelevasti. Osa viljelijöistä aktiivisesti etsii ja ottaa käyttöön uusia teknogioita toimintansa tehostamiseksi, osa taas ei ottaisi niitä käyttöön vaikka niitä tarjottaisiin valmiina ratkaisuina.

Kotieläintuotannossa on jo laajasti käytössä pitkälle automatisoituja tehdasmaisia laitoksia, koska niiden tapauksessa ollaan voitu soveltaa olemassaolevan teollisuusautomatiikan ratkaisuja. Kasvihuoneet ovat myös samankaltaisia tehdasmaisia laitoksia, joihin automatiikan ja tietoverkkojen asennus ja käyttö on ollut verrattain helppoa. Tosin teollisuusautomaatiota on tässä tapauksessa jouduttu muokkaamaan käyttäjäystävällisemmäksi, jotta viljelijä voi hallita järjestelmää omalla osaamisellaan eikä hänellä tarvitse olla käyttöinsinöörin taitoja. 

On tärkeää huomata, että tehdasmaisessa toimintaympäristössä yksi toimija on voinut valmistaa kattavan kokonaisratkaisun tai 2-3 toimijaa ovat voineet muodostaa pienen ekosysteemin, joiden tuotteet muodostavat keskenään vastaavan kokonaisratkaisun. Tämänkaltaisen ratkaisun ei tarvitse olla yhteensopiva tai toimia minkään muun toimittajan järjestelmien kanssa, mikä tekee kehitystyöstä paljon helpompaa.

Samoin kuin muussa teollisuusautomaatiossa, voi maataloudessa telemetriaa käyttävä järjestelmä havaita itse siinä ilmeneviä vikoja ja lähettää huoltokutsuja tarvittaessa. Tällöin valmistaja voi kerätä järjestelmän tuottamaa dataa oman tuotekehityksensä tueksi ja antaa etätulea tarvittaessa. Toisaalta järjestelmän hankkineen käyttäjän on aikaisemmin ollut vaikeaa saada tietoa omistamansa järjestelmän tuottamasta datasta, saati saada tuotettua dataa omaa analyysiä varten. Jokin aika sitten oli käyttäjälle yleisesti mahdollista saada vain joitain valmistajan ennalta määrittelemiä graafeja, mutta nyt on enenevissä määrin tullut mahdolliseksi ladata tietoja esimerkiksi Excel-formaateissa. Yleisesti ollaan vielä kaukana siitä, että käyttäjä voisi saada järjestelmiensä tuottamaa dataa haluamassaan formaatissa tai ladata sitä itselleen suoraan rajapinnasta vaikka itselleen räätälöityyn järjestelmään. Samoin ollaa kaukana siitä, että käyttäjä pystyisi määräämään, että hänen tuottamansa data siirrettäisiin vaikka kilpailijan vastaavaan järjestelmään. Tällä hetkellä järjestelmistä saadaan lähinnä monitorointitietoa tuotantotoiminnan tehostamista ja vahinkojen välttämistä varten, mitkä ovat järjestelmien yleisimmät hankintaperusteet ja myyntiargumentit. Samalla käyttäjät ovat kuitenkin edelleen yhden toimittajan loukussa. Tämä on teollisuusautomaatiossa ollut täysin käypä ratkaisumalli koska yksi toimittaja on voinut tuottaa kokonaisvaltaisen järjestelmäratkaisun, jonka avulla asiakas on voinut hallita koko tuotantoprosessinsa.

Pääasiallinen ongelma peltoviljelyssä on, että yksittäinen toimija ei pysty toteuttamaan kokonaisvaltaista järjestelmää jolla peltoviljely toimisi sille tyypillisessä hajanaisessa käyttöympäristössä, jossa on käytössä eri valmistajien hyvin erilaisia ja pitkälle erikoistuneita laitteita. Tämän takia kokonaisvaltaisia peltoviljelyn järjestelmäratkaisuita on tuotettu ns. full-liner -käyttöympäristöihin, joissa kaikki maatilan traktorit implementteineen, puimurit ja muut koneet ovat saman valmistajan tuotteita. Tällöin valmistaja on voinut oman järjestelmänsä sisällä varmistaa datan liikkuvuuden, viljelyprosessien kehittämisen ja tehokkaan täsmäviljelyn toteuttamisen full-liner -ratkaisun hankkineen käyttäjän toiminnassa.

Full-liner -järjestelmät ovat hyvin kalliita investointeja joihin on varaa vain hyvin suurilla maatiloilla, minkä takia kokonaisvaltaisia peltoviljelyn järjestelmiä on käytössä harvoilla toimijoilla. Lisäksi full-liner -ratkaisut eivät sovi kaikkien käyttöön, esimerkiksi John Deeren valikoimassa ei ole kylvölannoitinta jota käytetään pohjoismaissa. Tällöin pohjoismaiset viljelijät eivät pysty toimimaan John Deeren full-liner -ratkaisun puitteissa, vaan joutuvat hankkimaan käyttöönsä myös muiden valmistajien työkoneita kuten kylvölannoittimen.

Useiden eri valmistajien työkoneiden yhteistoiminnan varmistamiseksi on kehitetty ISOBUS-standardi, jonka kehittämistä AEF johtaa erilaisissa työryhmissä. Standardi takaa laitteiden käytännössä muiden standardin mukaisten laitteiden kanssa, mutta siirto työkoneen CAN-väylästä pilvipalveluun tai maatilan datavarastoihin on vielä työn alla. Voi vaikuttaa siltä, että maatalous olisi jäljessä muihin teollisuudenaloihin verrattuna mutta tämä johtuu osin alan pirstaleisuudesta ja ISOBUS-standardin kehittämisessä ollaan pitkään jouduttu keskittymään traktorien ja työkoneiden väliseen kommunikointiin.

Täsmäviljelyssä pyritään asettamaan jokaiseen pellon neliöön vain sen tarvitsema panos eikä yhtään enempää, jolloin suurilla peltopinta-aloilla toimittaessa voidaan täsmäviljelyn vaatiman järjestelmähankinnan vaatima investointi kattaa usein jo kolmessa vuodessa saavutettavilla lannoitesäästöillä. Tämä on tullut mahdolliseksi tarvittavien teknologioiden leviämisen ja hintojen alenemisen myötä, jolloin niistä on tullut ns. perusteknologiaa.

Pienillä peltopinta-aloilla toimittaessa tulee täsmäviljelyn vaatima lisäinvestointi koneiden hinnassa kattaa työn tehostamisella. Työtehoa saadaan yleensä lisättyä työkoneiden automaattiohjauksella ja telemetriatoimintojen avulla toimivan ennakoivan huollon sekä vikadiagnostiikan avulla. Telemetriapalveluista saadaan myös analytiikan avulla tietoa paitsi koneiden myös tuotantoprosessien tilasta, jolloin toimintaa voidaan optimoida parempien tulosten saavuttaamiseksi. Tällaisia etuja on aikaisemmin saatu vain full-liner -järjestelmien avulla, mutta nyt vastaavia tietoja tuottavia järjestelmiä on tullut markkinoille myös full-liner -ratkaisuiden ulkopuolelle. Oman työn tehostumisen lisäksi säästöjä voidaan saavuttaa myös tehokkaammalla urakoitsijoiden käytöllä, kun töiden ohjeistaminen tehdään digitaalisesti. 

Pienillä tiloilla voidaan toteuttaa täsmäviljelyä viljelijän oman hiljaisen tiedon avulla ilman täsmäviljelyssä käytettäviä tietojärjestelmiä, mutta tehtäviä ulkoistettaessa täsmäviljelyn vaatimien ohjeiden määrä on suuri. Työkoneiden ja prosessien datan keräämisellä ja pilvipalveluun tallentamisella viljelijän omaa hiljaista tietoa voidaan tehokkaasti hyödyntää myös urakoitsijan hoitaessa töitä.

Kuluttajalle asti näkyvä tuotantoketju mahdollistuisi jos olisi standardit joiden mukaisesti datavirtaa käsiteltäisiin. Samalla mahdollistuisi tehokas tiedon jako ja verkostomainen toiminta erilaisten toimijoiden kesken. Tähän tarvittavat standardit ovat vasta kehitteillä. Näkemykseni mukaan kentällä on edelläjkävijöinä toimijoita, jotka soveltavat uusia toimintamalleja käytäntöön ja määrittelevät kehitettävien standardien toimintaa. Standardeja kehitetään liiketoiminnan lähtökohdista ja liiketoiminnan yhteyteen tarkoituksena kehittää toimintaa entistä kustannustehokkaammaksi ja sujuvammin toimivaksi.

Koska maatalouden kenttä on niin hajanainen, mikään yksittäinen toimija ei ole halunnut tehdä suurinvestointeja oman standardinsa kehittämiseen ja riskeerata niin suurta tappiota kilpailutilanteessa muiden toimijoiden kanssa. Kilpailun sijaan on päädytty lähtökohtaisesti kehittämään toimintaympäristön standardeja yhdessä ja jakaen kehitystyön kustannukset. 10 vuotta sitten uskottiin suljettujen järjestelmien luovan kilpailuetua ja lisäävän liiketoimintaa. Nyt toimijat ovat havainneet kentän olevan niin hajanainen, että liiketoiminta on mahdollista vain  kun toimitaan avoimesti. Avoimesti kehitetty mahdollisimman toimiva standardi on näkemykseni mukaan tekninen alusta, jota kehittää ekosysteemi erilaisia toimijoita. Sitten kun standardin tekniset ongelmat on ratkottu ja pullonkaulat avattu sen ympärille kehittyy sitä hyödyntävä liiketoiminan ekosysteemi.

Valmistajat voivat standardien mukaan toimiessaan rakentaa omia edistyneempiä tai erikoistuneempia ominaisuuksia, jotka toimivat heidän laitteissaan heidän määrittelemissä puitteissa, esimerkiksi tietyn merkin traktorin kanssa voidaan saman merkin työkoneesta saada käyttöön enemmän kuin jos työkonetta käytettäisiin toisen valmistajan traktorin kanssa. Käyttökohteita ja -tarpeita on niin suuri kirjo, että toiminnallisuuksia pitääkin räätälöidä ja näiden erikoistoimintojen sisällöllä voidaan erottua kilpailijoista. Kilpailussa ollaan siirtymässä yhä enemmän koneen fyysisistä ominaisuuksista palveluiden ominaisuuksiin ja siihen, millaista lisäarvoa käyttäjälle tulee palvelun tuottaman tiedon avulla. Avointen standardien avulla valmistajat, jotka eivät voi tarjota full-liner -ratkaisua, voivat tarjota samankaltaista lisäarvoa koneidensa hankkineille käyttäjille kuin suuret fill-liner:eiden valmistajat. Tällöin valmistajat voivat keskittyä tekemään parhaan mahdollisen koneen, joka on avoimien standardien avulla yhteensopiva modernien automaatio - ja pilvijärjestelmien kanssa ja jolle voidaan tällöin luvata full-liner:eiden kokonaisjärjestelmien edut. Esimerkiksi kylvökoneen arvolupaus on suurempi, jos se toimii osana urakoitsijan konevalikoimaa tai yrittäjien keskinäistä ketjua. Yksittäinen kylvökone voi tehdä mekaaniset toimintonsa hyvin, mutta se on vain se yksittäinen kylvökone ja sen arvolupaus rajoittuu siihen itseensä. Ollessaan kytketty suurempaan kokonaisuuteen kylvökone voi tuottaa enemmän liiketoimintaa, arvoa ja tuottoa.

Toivoisin, että myös Suomeen tulisi käyttöön Farmobile:n [https://www.farmobile.com] kaltainen järjestelmä, jossa viljelijät voisivat varastoida ja halutessaan jakaa tai myydä toiminnastaan saatua dataa. Toinen vastaava palvelu on Farmer's Business Network [https://www.farmersbusinessnetwork.com] jossa käyttäjä voi verkostoitua, jakaa täsmäviljelyn reseptejä, vertailla analyysidataa jne. Sosiaalisesta mediasta löytyy kyllä ryhmiä vinkkien ja tietojen vaihtoon, mutta datojen jakoon ei ole palvelua, eikä datoja ole sillä tavalla käyttäjien omassa hallinnassa että niitä voisi oman halunsa mukaan jakaa kenelle haluaa. 







Suomessa on pitkälle tutkittu suljettuja kasvihuoneita, jotka ovat myös hyvin pitkälle automatisoituja ja puhutaan monikerrosviljelystä.


































