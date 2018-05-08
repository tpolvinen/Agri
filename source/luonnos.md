---
Title: OPINNÄYTETYÖ: IoT-teknologioiden sovellukset kasvintuotannossa
Author: Tatu Polvinen
Tags: IoT, IIoT, AIoT, maatalous, kasvintuotanto, kasvitehdas
Category: IT
Date: 2017-10-12 18:40
Template: ../template/template.docx
bibliography: ../bib/AIoT.bib
csl: ../style/harvard1.csl
...

<23-04-2018  17:03> bibliografian testaus:
ckey    @elovaaraAggregatingOPCUA2015
(ckey)    (@elovaaraAggregatingOPCUA2015)
(ckey 3, 33)    (@elovaaraAggregatingOPCUA2015 3, 33)
ckey    buyya2016internet
(ckey)  (@buyya2016internet)
(ckey 3, 33)    (@buyya2016internet 3, 33)


# Tiivistelmä

Tässä opinnäytetyössä käytetään lähdeviittausten tyylinä Södertörns högskola - Harvard -tyyliä.

# Johdanto

-- Omia huomioita 17.11.2017: Olen jotenkin olettanut, että totta kai maataloudessa oltaisiin jo omaksuttu paljon enemmän IoT-teknologioita, samaaan tapaan kuin muualla teollisuudessa. Jokin alan vieraudessa on vaikuttanut minuun. Ehkä työni ensimmäinen hämmästynyt kysymys oli: "Sitä tietoa ei siis saa sieltä koneesta ulos?" Viljelijöiden harkitsevuus uusien teknologioiden käyttöönotossa ei ole takapajuisuutta, ymmärtämättömyyttä tai typeryyttä, vaan sille on hyvä syy: teknologian tulee todistettavasti olla tuottavaa jotta sen käyttöönottoa edes voitaisiin harkita. Niin kuin missä tahansa liiketoiminnassa tai tuotannossa. Kentän hajanaisuus, järjestelmäintegration vaikeus ja hitaus ovat hidastaneet laajamittaista käyttöönottoa huomattavasti peltotuotannossa, osin myös puutarhatuotannossa. Kyse ei ilmeiseti olekaan alan takapajuisuudesta tai merkityksettömyydestä. --

Kirjoittajan tietämyksen mukaan kasvintuotannossa käytettävistä IoT-ratkaisuista on viime vuosien (2010 - 2018) aikana julkaistu runsaasti tutkimuksia ja erilaisia artikkeleita. Opinnäytetyön esitöissä kävi ilmi, että kirjoittajalla ei ole kovin vahvaa ymmärrystä tai kokemusta maataloudessa käytettävistä IoT-ratkaisuista. Koska maatalouden esineiden internet (Agricultural Internet of Things, AIoT) on voimakkaasti kasvava teollisen esineiden internetin (Industrial Internet of Things, IIoT) osa **(LÄHDE???)** ja se voi vaikuttaa huomattavasti ruoantuotannon kehitykseen **(LÄHDE???)** tekijä arvioi, että AIoT:n tilanteesta kannattaa olla tietoinen. Lisäksi tekijä arvelee, että AIoT:n teknologiaratkaisuiden kehittämisessä tullaan tarvitsemaan asiantuntijoita joilla on sekä maatalouden että ICT-alan ymmärrystä.

Tämä opinnäytetyö pyrkii tuottamaan ajankohtaisen yleiskatsauksen kasvintuotannossa käytettäviin IoT-teknologiasovelluksiin.

Opinnäytetyön aihepiirinä on maatalouden esineiden internetiin (Agriculture Internet of Things, AIoT) liittyvät tutkimukset, julkaisut ja teknologiasovellukset. Opinnäytetyössä haastatellaan asiaan perehtyneitä tutkijoita, viljelijöitä, yrittäjiä ja yritysten edustajia.

Opinnäytetyön laajuuden rajallisuuden vuoksi aihealueeksi on rajattu kasvintuotannon IoT-ratkaisut, minkä kirjoittaja arvioi olevan yleisen ruoantuotannon kannalta vaikuttavin osa. Samasta syystä tässä opinnäytetyössä ei käsitellä teknologiaratkaisuita kuten verkkoprotokollia, sensoritekniikkaa tai algoritmejä, vaan keskitytään kuvailemaan kasvintuotannon IoT-ratkaisuita yleistasolla.

Teknologiasovelluksista käsitellään sekä tutkimus- ja prototyyppiluonteisia toteutuksia että kaupallisia tuotteita. Tutkimuksessa pyritään luomaan kuva sekä AIoT:n tutkimuskentän että käytännön sovellusten ja tuotteiden tilasta.

Ilmastonmuutos, ekosysteemipalvelujen heikkeneminen, resurssien niukkeneminen, ruoan ja energian lisääntyvä tarve, nopea sosiaalinen eriarvoistuminen, maahanmuutto ja ihmisten etääntyminen ruoan alkuperästä
*(Evernote: Abstract: Hyvin sanottu! Parasta ruokaa - hyvää elämää)*
--Samalla kuluttajien vaatimukset lähiruoalle, läpinäkyvälle tuotantiketjulle ja luomulle-- lähde?

Alkutuotannon kehittyessä yhä riippuvaisemmaksi internetiin kytketystä tietotekniikasta ja automaatiosta järjestelmien kyberturvallisuus on otettava huomioon. Kyberturvallisuuden puutteista aiheutuva uhka on sitä suurempi mitä pidemmälle kehityksessä edetään.
*(Evernote: Kyberturvallisuus on elintärkeä myös maataloudessa - Luonnonvarakeskus)* 

IoTn historia on hienosti kuvattu Mina Nasirin gradussa Internet of Things as an enabler in disruptive innovation for sustainability
-miten sen saisi tähän?
*(Evernote: Master's w/ expert interviews: Internet of Things as an enabler in disruptive innovation for sustainability)*

*Pylväs esityksessään KoneAgriassa: ei ole vielä otettu pelloista läheskään kaikkea irti*

Artikkelista voi noukkia monet hyvät pointit.
*(Evernote: Paljon viitteitä: The future of agriculture | The Economist)*

"Luonnonvarakeskuksen teknologiapäivässä asiasta oltiin yksimielisiä" Datan omistajuus tykätään pitää tekijöillä.
"– Hankkeemme merkittävä havainto oli, että maatilan data on erotettava sovelluksista, jotta sitä voidaan käyttää tehokkaasti hyväksi viljelijää avustavissa palveluissa ja sovelluksissa, toteaa Cropinfra-hankkeen vetäjä, vanhempi tutkija Liisa Pesonen."
Automaattiohjausjärjestelmät yleistyneet huomattavasti Australiassa, muut täsmäv. maltillisemmin -Timo Oksanen "Syyksi jonkin tietyn teknologian nopeaan yleistymiseen nähtiin järjestelmien käytettävyys ja suora työsuorituksen helpottuminen."
"Teknologiapäivässä alan toimijoiden välisessä keskustelussa kuitenkin todettiin, etteivät teollisen Internetin mukanaan tuomat uudet teknologiat tule syrjäyttämään tällä hetkellä yleistymässä olevia tekniikoita kuten ISOBUS-tekniikkaa.
Haasteena uusien teknologioiden käyttöönottoon nähtiin koneketjujen ja palveluiden muodostaman kokonaisuuden sekä uusien toimintamallien riittävä testaaminen."
*(Evernote: Digitalisoituminen avaa kasvinviljelyyn ja metsänhoitoon uusia toimintamalleja - Luonnonvarakeskus)*

## PUUTARHATUOTANTO
Puutarhatuotannossa yritykset hakevat Voimakas-hankkeessa parempaa kannattavuutta energiatehokkuudella, uusilla myyntikanavilla ja uusilla toimintamalleilla. Yritykset saattavat profiloitua tehdasmaisiin ja asiakasta lähempänä toimiviin.
*(Evernote: Tutkimus myllertää puutarhayrityksiä - Luonnonvarakeskus Voimakas.fi)*

Paljon uusia tuotantolaitoksia (vertical farming), osa jo mennyt nurin. Markkinapaikkaa etsitään.
Kaupallisesti kasvattaminen ei ole helppoa, on monimutkaista.
"Stiina Kotiranta of Valoya"
Tarvitaan enemmän lajikkeita ruokatarpeen tyydyttämiseksi.
Monet asiat ovat toteutettavissa, mutta mitkä ovat järkeviä toteuttaa? Mikä on oman operaation motiivi? Misä olisi tuottava bisneskeisi?
Vertical farming ja kasvihuoneteollisuus voisivat oppia paljon toisiltaan *(ks. Robbe)*
Paikallisempi, tuoreempi premium-tuote on OK, ei pelkästään viljelytekniikan takia tehty tuote.
*(Evernote: Does vertical farming make sense?)*

Olisiko levätehtaista teknologialähdettä? "Haastavaa...Vuodenaikojen ja sään vaihtelu suosii sisätiloihin asennettavien suljettujen fotobioreaktorien valintaa levänkasvatusmenetelmäksi."
*/Evernote: Via Luke/Kari Jokinen: Utilization of microalgae in industrial symbiosis, focus on Finland)*

## PELTOTUOTANTO
Samoin maatilojen määrä on vähentymässä, tilakoko kasvussa ja osin koneellistumisen seurauksena työvoiman kokonaismäärä vähentymässä. 2013 EU:n Maatalouden rakennetutkimuksen mukaan kolmannes maatiloista harjoitti myös muuta yritystoimintaa.
*(Evernote: Maatilojen määrä vähenee – toiminta monipuolistuu - Luonnonvarakeskus)*

Koneellistumisen osana on toimintojen digitalisaatio, jonka avulla kasvintuotannossa käytetyt koneet saadaan tuottamaan tietoa ja kommunikoimaan keskenään samaan tapaan kuin teollisuuden esineiden internetissä. "Kotimainen maatalouskoneteollisuus on vielä alkutaipaleella teollisen internetin hyödyntämisessä"." Erityisesti tarvitaan yhteensopivien tiedonsiirtomenetelmien kehittämistä.
*(Evernote: Digitalisaatio laittaa koneet kommunikoimaan - Luonnonvarakeskus)*

Valtran ja Luken tutkimusyhteistyötä on tehty vuodesta 2003. GNSS-paikannus + Isobus Jo automaattiohjauksen avulla tehtävällä kylvörivien optimoinnilla saadaan samasta kasvatuspinta-alasta enemmän irti. 2015 tehtiin testejä, voisiko tiedonkulkua ohjata Isobus-väylässä työkoneelta traktorin suuntaan. **Mikä nykytilanne on?**
*(Evernote: Asiakkaan ääni: Automaatio yleistyy pelloilla - Luonnonvarakeskus)*

"Luonnonvarakeskuksen (Luke) koordinoimassa OPAL-Life-hankkeessa selvitetään peltojen sadontuottokykyä 20 pilottitilalla yhteistyössä viljelijöiden kanssa." "Drone-lentoja on tehty neljällä pilottitilalla, ja niiden tarkoituksena on tarkentaa satelliittikuvien avulla tehtyä analyysiä. Tämän lisäksi viljelijöiltä kerätään havaintoja peltojen kunnosta ja saaduista sadoista lukuisten muiden hyödynnettävien aineistojen rinnalle." "Droneja voidaan käyttää pellolla sadontuottokyvyn laskemisen lisäksi muun muassa kasvien kunnon määrittämiseen, karjan laskentaan sekä täsmälannoituksen suunnitteluun."
*(Evernote: Pellon yllä lentävä drone rekisteröi monenlaista tietoa - Luonnonvarakeskus)*

Täsmäviljelyä toteutetaan tietotekniikan, satelliittipaikannuksen ja kaukokartoituksen avulla tuotannon tehokkuuden, voitollisuuden ja ympäristöystävällisyyden parantamiseksi. Täsmäviljely voi näytellä huomattavaa osaa vastatessa globaalisti kasvavan ruoan tarpeeseen, samalla varmistaen kestävän luonnonvarojen käytön.
Euroopassa maatilojen koko ja suuret tilojen väliset keskinäiset erot vaikeuttavat täsmäviljelyn käyttöönottoa.
Suositellaan kampanjointia tiedostavuuden lisäämiseksi ja EU:n "täsmäviljelylaskimen" kehittämistä viljelijöiden päätöksenteon tueksi.
Sovelluksiin kuuluvat automaattiohjausjärjestelmät, vaihtelevan määrän tekniikat joilla mahdollistuu täsmällinen kynnön, kylvön, lannoituksen, kastelun, rikkakasvintorjunnan kontrollointi. 
Maatalouskoneisiin asennettujen sensorien tuottaman tiedon (maanlaatu, lehtiala) sekä kaukokartoituksen korkearesoluutiokuvien (kasvien fysiologinen tila) tuottaman tiedon avulla voidaan optimoida viljelmien hallintaa, jolla voidaan saavuttaa parempia satoja ja parantaa tuottavuutta ympäristöystävällisemmin.
*(Evernote: PEER: Precision agriculture: an opportunity for EU farmers)*

Esimerkki sijoitusinnosta: 15 miljoonaa USD B-kierroksella kerännyt Tel Avivlainen Prospera. Pelloilta kerättävää dataa AI:lla analysoivaa. Siirymässä kasvihuoneista pelloille. Laajentunut tautien ja tuholaisten havaitsemisesta “every aspect of farm production,” sis.  soil management and crop production
...operations and managing a farm’s labor. Sijoittajissa mukana Qualcomm ja Cisco.
*(Evernote: Agtech startup Prospera, which uses AI and computer vision to guide farmers, harvests $15M – TechCrunch)*

Evernote, muut tagilla "Tausta":

Alku, ei tuloksia/tekniikkaa: BIONET - Teollisen Internetin soveltaminen biotalouteen
Yleistä lätinää, mutta afrikka "(IoT) towards poverty reduction": The Internet of Things in Agriculture for Sustainable Rural Development
4.1 Smart farming: Internet of things: from internet scale sensing to smart services
Internet of Things in Industries: A Survey Abstraktista iot-määritelmä!
Farmboxgreens.com Urban Ag News | Issue 9 | April 2015 by urbanagnews - issuu
Econ.feasibility aquaponics
Finland: Fujitsu and Robbe's Little Garden start cloud based ag trial
Fujitsu  ja Robben Pikku Puutarha  perustavat koeviljelmän *ks. ed.*
Farm Smart « ACCJ Journal
Can agritech save the future of food? - Japan Today *sama kuin ed.*
Teleoper. Kiinnostus IoThen: IoT-käyttöliittymän luonti pilvipalvelua käyttäen *eeeehkäää...*
Decagon Irrigation Monitoring System from SCRI-MINDS
FAO - News Article: Scarcity and degradation of land and water: growing threat to food security *Tämä voi olla tärkeä taustaksi, miksi tarvitaan AIoT:n hyötyjä*

# Teoriatausta
## Taustaa

<23-04-2018  13:22>
Maatalouteen kohdistuu jatkuvasti kovenevia tehokkuusvaatimuksia, samalla kun teknologinen kehitys mahdollistaa tehokkaampia viljelyprosesseja. Lisäksi maataloudelle ja ruokaturvalle asettaa haasteita ilmastonmuutos ja väestönkasvu. Näihin vaatimuksiin ja haasteisiin pyritään osaltaan vastaamaan digitalisoimalla maatalouden prosesseja kuin muilla teollisuuden aloilla.

*IIoT Industry 4.0:sta sivut 2-5*

*Sitten miten maatalous liittyy IIoT:hen*

<23-04-2018  12:15>
*Perustuen Joona Elovaaran "Aggregating OPC UA Server for Remote Access to Agricultural Work Machines" diplomityön osioon 1.1 Background:*
Agroteknologian viime vuosien nopea kehitys on mahdollistunut muilla alueilla tapahtuneen teknologiakehityksen myötä. Prosessien automatisointi, reaaliaikainen ohjaus ja konenäköjärjestelmät ovat keskeisiä agroteknologian kehitykseen vaikuttaneita teknologiakehityksen alueita *(Ronkainen, 2014)*. Täsmäviljelyn (Precision Agriculture, PA [http://www.aumanet.fi/tasmaviljely/maaritelma.html]) ja määränsäätöautomatiikan (Variable Rate Application VRA) laajentuva käyttö on myös osaltaan nopeuttanut maataloustyökoneiden teknologian kehitystä **(Ronkainen, 2014)**.

Työkoneiden kehityksen myötä maatilojen toiminnan hallinta on monimutkaistunut. Viljelijän tulee tehdä päätöksiä viljelytoimien laadusta, sisällöstä, ajankohdasta ja järjestyksestä ottaen samalla huomioon sekä ympäristönsuojelun että maataloustukien säädökset, lisäksi huolehtien liiketoiminnastaan ja tilansa työkoneista ja muusta infrastruktuurista. Tätä toimintaa ja päätöksentekoa tukemaan on kehitetty erilaisia tiedonhallinnan järjestelmiä, joita kutsutaan Farm Management Information System:eiksi (FMIS). (@elovaaraAggregatingOPCUA2015) FMIS on määritelmällisesti järjestelmä, joka kerää, käsittelee, tallentaa ja välittää dataa tiedon muodossa, jota tarvitaan maatilan operatiivisten toimintojen suorittamisessa **(Sørensen et al. 2010a)-Elsevier, ei pääsyä**.

Useimpien traktorien ja työkoneiden ollessa sähköisesti hallittuja ja niihin asennettujen sensorien tuottaessa dataa, voitaisiin tämä data kerätä ja jalostaa tiedoksi esimerkiksi koneiden huollosta, rikkoutumisista ja työsuorituksista. Tämän tiedon avulla voitaisiin parantaa täsmäviljelyn ja työkoneiden hallinnan käytänteitä.


## AIoT:n käytännön sovelluksia ja tutkimustuloksia
### AIoT-täsmäviljely peltokasvituotannossa


### AIoT-täsmäviljely puutarhatuotannossa
# Tutkimuksen tavoitteet
## Tutkimusongelmat
*Refaktoroidaan tutkimusongelmat!*
Tutkimuksessa haetaan vastauksia -kahteen- kolmeen tutkimusongelmaan, jotka alaongelmineen ovat:

I) Millaista tutkimusta IoT-teknologioiden soveltamisesta kasvintuotantoon on julkaistu?
*Luetaan materiaali läpi ja tarkennetaan kysymyksiä sen mukaan!*

* Millaisia teknologiasovelluksia tutkimuksissa on esitelty?
* Minkä tyyppiset sovellukset tulevat tutkimusmateriaalissa selkeimmin esille, eli millaisista sovelluksista ja teknologioista kirjoitetaan ja tehdään tutkimusta tällä hetkellä?
* Muut kysymykset? Vaikuttavuus, mitä tilanne kertoo ylipäänsä, jne.

II) Miten kasvintuotannossa hyödynnetään IoT-teknologioita?

* Miten peltotuotannon ja puutarhatuotannon erot vaikuttavat IoT-teknologioiden sovelluksiin?
* 
    
III) Millaisia IoT-teknologioita haastateltavalla toimijalla on joko käytettävissään tai millaisista hän on tietoinen?

* Mitä vaikutuksia niillä on tuotantoon ja/tai työntekoon?
* Millaisia kokemuksia niistä haastateltavalla on?
* Millaisia muita sovelluksia haastateltava tuntee tai tietää?
* Millainen käsitys haastateltavalla on edelllä mainituista sovelluksista (sekä käyttämistään että tietämistään)?
* Millaisia toiveita tai tarpeita haastateltavalla on IoT-teknologioille?

## Työhypoteesit:

Saturaatioon ei todennäköisesti päästä haastattelujen tuloksissa, koska opinnäytetyön rajattu laajuus ei mahdollista useiden samaan erikoisalaan perehtyneiden asiantuntijoiden haastatteluja. Samasta syystä haastattelukierroksia voidaan toteuttaa vain yksi, jolloin kerättyä tietoa ei voi pitää kovin syvällisenä. Tiedon syventäminen joudutaan jättämään jatkotutkimukselle.

# Aineisto ja (tutkimus)menetelmät
## Tutkimusmenetelmät

Tämä on tutkimustyyppinen opinnäytetyö, jossa toteutetaan laadullinen tutkimus.
Laadullisen tutkimuksen tutkimusote valittiin kolmesta syystä: 1) tutkimusaiheesta ei löydetty merkittävää määrää tutkimusta työn alkuvaiheessa tutustuttaessa tutkittavaan ilmiöön, 2) kasvintuotannon ala on tekijälle tuntematon ja 3) työn alkuvaiheessa havaittiin, että kasvintuotannossa IoT-ratkaisuiden käyttöönotto on laajassa mittakaavassa alkuvaiheessa ja ala on tältä osin muutosvaiheessa. 
Käytettävät tutkimusmenetelmät ovat kuvaileva (narratiivinen) kirjallisuuskatsaus sekä teemahaastattelut.
Kirjallisuuskatsauksen ja teemahaastattelujen tuottamaa tietoa käsitellään sisällönanalyysin keinoin käyttäen myös narratiivisen tutkimuksen keinoja.
Teemahaastattelun tutkimusmenetelmää käytetään yhdessä kuvailevan kirjallisuuskatsauksen kanssa trianguloimaan tutkimusaihetta.
Aineiston keruumenetelmiä oli useita. Varsinaista tutkimustyötä edelsi ilmiöön tutustuminen erilaisia keruumenetelmiä testattaessa, keräämällä kontakteja, käyden asiantuntijakeskusteluja, vierailemalla alan tapahtumissa ja haastatteluja tehden. Varsinaisen tutkimustyön aluksi haettiin IoT:tä yleistasolla ja ilmiönä käsittelevää kirjallisuutta. Seuraavaksi käytettiin sateenvarjokatsausta, jolla haettiin ilmiötä käsitteleviä kirjallisuuskatsauksia. Valittujen kirjallisuuskatsausten pohjalta muotoiltiin omat hakumetodit ja valittiin osa lähteistä. Omien hakumetodien tuloksista on valittu tekijän harkinnan mukaan aihetta parhaiten kuvaavat. Lisäksi ollaan käytetty aiheeseen tutustuttaessa löydettyjä lähteitä jos ne ovat tekijän harkinnan mukaan olleet tähdellisiä aiheen käsittelylle ja ymmärryksen luomiselle.

Tutkimuksen luotettavuutta pyritään parantamaan käyttämällä aineistotriangulaatiota: kirjallisuuskatsauksen tuloksia vertaillaan haastattelujen tuloksiin sekä tuodaan esille ammattijulkaisuissa, laitevalmistajien sekä muiden toimijoiden tiedotteissa, lehtiartikkeleissa jne. ilmestyneitä asiaan liittyviä asioita.

Lisäksi tutkimuksen luotettavuutta pyritään parantamaan luettamalla haastatteluista tehdyt johtopäätökset muistiinpanoineen haastateltavalla.

Haastattelujen litteroinnissa käytetään yleiskielistä litterointia. Yleiskielistä litterointia tarkempaa sanatarkkaa litterointia on käytetty, jos sanojen poistamisella litteroinnista on arvioitu olevan tarkoitusta mahdollisesti muuttava vaikutus.

Tutkimuksen alustavassa vaiheessa ilmiöön tutustuttaessa tehtiin useita hakuja aiheeseen liittyvillä asiasanoilla, selattiin erilaisten organisaatioiden ja julkaisujen verkkosivuja, haettiin asiantuntijakontakteja eri tapahtumista jne. Löydöt merkittiin muistiin mahdollista myöhempää käyttöä varten.

Haastateltavia etsittiin tapahtumista saatujen kontaktien, aineistosta löytyneiden asiantuntijoiden ja omien verkostojen kautta.  Lisäksi käytettiin "snowballing" -menetelmää, jossa keskusteluissa informanttia pyydettiin suosittelemaan muita asiantuntijoita haastateltaviksi.

*Tästä poistettu hakujen kuvaukset <02-05-2018 18:32>*

Mitä nyt on tehty ja mitä seuraavaksi:
    Käytetty hieman erilaisia hakulauseita eri kantoihin niiden vaatimusten ja toimintojen mukaan.
    Tuloksena kohtuullinen määrä tieteellisiä lähteitä.
    Lähteistä pitää seuraavaksi tarkistaa onko kirjallisuuskatsauksia saturoiva tai muuten riittävä määrä. Katsauksia ollaan haettu erikseen vasta Google Scholarin avulla. Kirjoitetaan havainnot katsauksista.

Kirjallisuuskatsausten käyttämät tietokannat:
    Talaveran: Google Scholar, IEEE, Scopus
    Kamilaris: IEEE, ScienceDirect, Web of Science, Google Scholar
    Verdouw: Scopus, Google Scholar 
    "*We searched in the Scopus database for papers that on the one hand include Internet of Things or IoT in the title and on the other hand agriculture, farming or food in the title, abstract or the keywords section. In addition, we used generic references on IoT and enabling technologies by using Google scholar especially searching for review articles that provide an overview of the application of specific enabling technologies in the agricultural domain.*"



Löydettyjä kirjallisuuskatsauksia käytetään seuraavasti:
Tiedon kattavuutta pyritään parantamaan hakemalla sateenvarjokatsauksen omaisesti aihetta käsitteleviä kirjallisuuskatsauksia. Hakutuloksista valituista kirjallisuuskatsauksista käydään läpi tutkimusmetodit joista löytyviä hakumenetelmiä käytetään hyväksi soveltuvin osin tämän työn seuraavissa tiedonhakuvaiheessa.

## SEURAAVAKSI:

<02-05-2018  21:27>

1. Sateenvarjokatsauksen loppuun vienti:
    Luetaan kirjallisuuskatsaukset, merkitään teemat ja aiheet niiltä osin kun tiedon arvellaan olevan tarpeellista omalle työlle. Merkitään muistiin myös assosiaatiot muihin lähteisiin.
    Seuraavaksi sama kirjoille.
    Seuraavaksi sama muille katsauksille.
    Asetellaan muistiinpanot luonnokseen.
    Muokataan rakennetta samalla.
2. Sitten teknologiasovellukset ja muut lähteet, jotka löydettiin dokumetoiduissa hauissa.
3. Käydään läpi CEMA, IoF2020, AEF, Luke sekä muut mahdollisesti vastaan tulleiden toimijoiden julkaisut. Kirjoitetaan havainnot.
4. Käydään läpi haastattelujen litteroinnit ja kirjoitetaan löydökset. Tarkistetaan oikeellisuus haastateltavien kanssa.
5. Lisätään mahd. mukaan aikaisemmista vaiheista mukaan tulleet lähteet ja kirjoitetaan löydökset. Kirjoitetaan tulokset.
6. Refaktoroidaan haastatteluprotokolla jos se tarvitaan mukaan työhön.
7. Refaktoroidaan tutkimusongelma ja -kysymykset.
8. Kirjoitetaan Johtopäätökset ja suositukset

Mahdollinen rakenne:
    Lähteiden hankinta
    Metodit
    Jaottelu

## Kirjallisuus:

* Internet of things: Principles and paradigms
* Industry 4.0: The industrial internet of things 
* Internet of Things - Global Technological and Societal Trends

## Kirjallisuuskatsaukset:

* Atzori: The Internet of Things: A survey 2010
* Talavera: Review of IoT applications in agro-industrial and environmental fields @talaveraReviewIoTApplications2017
    Muistiinpanot:
    Tässä kirjallisuuskatsauksessa esitettiin AIoT:n sovellusalueiksi käsiteltyjen tutkimusten perusteella: tarkkailu (monitoring) 62 %; kontrollointi (control) 25 %; logistiikka (logistics) 7 %; ennustus (prediction) 6 %.
    Kustakin kategoriasta alikategorioineen on kuvailu esimerkein.
    Löydöksien perusteella on kuvailtu AIoT:n käyttöönottoon vaikuttavat esteet (limitations) ja avoimet haasteet: Stronger standardization; Better power management; Security; Design using modular hardware and software; Improve unit cost; Aim for a good compatibility with legacy infrastructure; Consider scalability early on; Adopt good practices of software engineering; Improve robustness for field deployments; User-centered design; Contribute to the IoT the ecosystem; Sustainable practices.
    Lopuksi esitetään AIoT-arkkitehtuurimalli, joka vetää yhteen suurimman osan kirjallisuuskatsauksessa käsitellyistä tutkimuksista. Arkkitehtuurin neljä päätasoa ovat: physical; communication; service; application.
    Tekijöiden mukaan käsitellyt tutkimukset tarjoavat kompaktin näköalan (view) maatalouden ongelmien ratkaisemiseksi ehdotettuista teknologiasovelluksista vuosien 2006 - 2016 ajalta. Tekijät olivat havainneet suurimman osan ehdotettuista teknologiasovelluksista käyttävän heterogeenisiä komponentteja ja langattomia verkkoja. Tekijöiden mukaan on järkevää olettaa että tulevaisuudessa vastaavien ratkaisujen kuitenkin tulee täysimittaisesti käyttää hyväkseen pilvipalveluita ja uusia yhteystapoja (ways of connectivity) saavuttaakseen todella yhdistetyn ja älykkään (truly connected and smart) IoT-ekosysteemin edut.  

        Systemaattinen kirjallisuuskatsaus
        Tutkimuskysymykset:
            1. What are the main technological solutions of the Internet of Things in agro-industrial and environmental fields?
            2. Which infrastructure and technology are using the main solutions of IoT in agro-industrial and environmental fields?
        Tiivistelmä:
            Tarkoituksena selvittää sovellusalueet, trendit, arkkitehtuurit, avoimet haasteet.
            Vuosilta 2006 - 2016.
            Sovellusalueet: tarkkailu (monitoring) 62 %, kontrollointi (control) 25 %, logistiikka (logistics) 7 %, ennustus (prediction) 6 %.
            Analysoitu sensoreiden, aktuaattoreiden, virtalähteiden, edge computing -mallien, viestintäteknologioiden, tallennusratkaisuiden, visualisaatiostrategioiden mukaan.
            Lopuksi koottu IoT-arkkitehtuuriksi.
        Taustaa:
            Internetin laajamittainen käyttö on kahden viime vuosikymmenen aikana tuottanut globaalisti lukemattoman määrän etuja ja hyötyä ihmisille ja organisaatioille. Voidaan väittää, että näistä tärkein on kyky (ja mahdollisuus) kuluttaa ja tuottaa dataa sekä palveluita reaaliaikaisesti. Viime aikoina esineiden internet (Internet of Things, IoT) lupaa tuottaa samat edut (ja hyödyt) jokapäiväisille esineille. Tämä voi mahdollistaa meille sekä havainnointikykymme laajentamisen että ympäristömme muokkaamisen/kontrolloinnin.
            Havainnoinnin ja hallinnan kontekstissa maatalousteollinen ala (?) on ihanteellinen tarkastelun kohde, koska toiminnassa on tarpeen jatkuvasti havainnoida ja hallita/kontrolloida/vaikuttaa laajoja alueita. IoT mahdollistaa uusia toimintamalleja tehdasautomaation ulkopuolelle kun kerättyä dataa syötetään koneoppimisalgoritmeille ennusteiden tekoon **(Saville et al., 2015)** ja näitä ennusteita voidaan käyttää päätöksenteon helpottamiseen ja suunnitteluun niin omistajien, johtajien kuin lainsäätäjienkin toiminnassa.
            IoT:tä voidaan käyttää maataloustuotannon eri tasoilla/vaiheissa **(Medela et al., 2013)**. IoT:tä voidaan käyttää arvioidessa maaperän tilaa, ilmastoa/säätilaa ja kasvien tai eläinten biomassaa. IoT:tä voidaan käyttää arvioidessa ja säätäessä/kontrolloidessa tuotteiden kuljetuksessa lämpötilaa, kosteutta, tärinää ja iskuja **(Pang et al., 2015)**. IoT:tä voidaan käyttää tuotteiden tilan arviointiin ja seurantaan sekä tuotteiden määrään hyllyillä tai kylmätiloissa. IoT:tä voidaan käyttää välittämään loppukäyttäjälle/kuluttajalle tietoa tuotteen alkuperästä ja ominaisuuksista.
            IoT:n soveltaminen maatalouteen voi osaltaan edistää maaseutuyhteisön kehitystä aikaisempaakin asiantuntevammaksi (informed), yhdistyneemmäksi (connected), edistyneemmäksi (developed) ja sopeutumiskykyisemmäksi (adaptable).
            IoT-paradigman alla edulliset/halvat (low-cost) elektoniset laitteet voivat edistää ihmisten kanssakäymistä (interaction) fyysisen maailman kanssa. Internetin kautta saatavilla olevan laskentatehon ja ohjelmistojen avulla voidaan tuottaa arvokasta analytiikkaa. Tulevina vuosina IoT voi olla tärkeä työkalu maatalouden järjestelmien kanssa toimiville ihmisille kuten tavaratoimittajille, viljejijöille, mekaanikoille, jälleenmyyjille, liiketoiminnan harjoittajille, kuluttajille ja valtiohallinnon edustajille.
        Tutkimusmetodit:
            Tehtiin useita hakuja erilaisiin digitaalisiin kirjastoihin ja hakukoineisiin. Hakutulokset koottiin manuaalisesti jotta parhaat tietolähteet saataisiin valikoitua tutkimuskysymyksiin vastauksen saamiseksi.  Tulosten analysoinnin jälkeen valittiin digitaaliset kirjastot ja hakukoneet tieteellisen ja teknisen sisällön perusteella, lisäksi ottaen huomioon tietoalueet (?) jotka sopivat tutkimuksen tavoitteeseen.
            Määriteltiin avainsanat/asiasanat ja hakuprosessi. Avainsanat valittiin tutkimuskysymyksistä muodostaen kaksi avainsanaryhmää. Avainsanaryhmissä oli kootut avainsanat synonyymeineen tai samaa tarkoittavine termeineen. Ryhmä 1 sisälsi IoT:hen liittyvät ja ryhmä 2 maatalouteen liittyvät. Digitaalisten kirjastojen edistyneiden hakutoimintojen tukemien loogisten operaattoreiden avulla koostettiin hakulauseet, jotka perustuivat tutkimuskysymyksiin ja jotka yhdistivät avainsanaryhmät. Yleistä hakulauseiden rakennetta käytettiin hakujen tekoon valittuihin tietolähteisiin.
            Laatuvaatimukset tarkasteltaville artikkeleille (papers) olivat: vertaisarviointi, englanninkielisyys, julkaisuvuosi 2006-2016. Jos aihe ei ollut relevantti tai tämän tutkimuksen rajauksen ulkopuolella, se poistettiin. Sitten käytettiin ICtä ja QCtä määrän pienentämiseksi. 
        Toteutus:
            Lopulta 3578:sta hakutuloksesta valittiin 72. Suurin osa valikoiduista tutkimuksista oli julkaistu vuosina 2012 - 2016. Vuosien 2012 - 2014 välillä oli lähes neljänneksen (noin 5 kpl.) vuosittainen kasvu, vuoden 2016 ollessa tutkimusajankohtana vielä kesken.
        Tulokset - Vastaukset tutkimuskysymyksiin:
            Ensimmäinen tutkimuskysymys:
                *"What are the main technological solutions of the Internet of Things in agro-industrial and environmental fields?"*
                Valittujen tutkimusten havaittiin jakautuvan neljään sovellusaueeseen seuraavasti: tarkkailu (monitoring) 62 %, kontrollointi (control) 25 %, logistiikka (logistics) 7 %, ennustus (prediction) 6 %.
                    Mittaus/Tarkkailu-kategoria:
                        Fyysisten ja ympäristöparametrien keruuta esimerkiksi sadosta ja langattomia sensoriverkkoja (Wireless Sensor Network, WSN) käyttävistä tiloista. Tarkkailukategorian tutkimusten kohteina olevien teknologiasovellusten pääasiallinen tarkoitus oli informaation keruu ilman operaattoria ja sen siirto palvelimelle tai tallennuspalveluun käsittelyä ja visualisointia varten. Integroidut tarkkailutyökalut mahdollistavat sekä jatkuvan viestinnän käytetyn WSN:n kanssa että tallennetun datan tarkastelun (accessing) Internetin yli.
                        Tarkkailun avulla IoT-perustainen älykäs maanviljelytoiminta lisää arvoa viljelijöille auttamalla relevantin/merkityksellisen tiedon keruussa sadosta ja tilan toiminnasta käyttämällä sensorilaitteita. Osa tutkimusten käsittelemistä IoT-järjestelmistä kykeni näyttämään, käsittelemään ja analysoimaan etäistä dataa (?! remote data) käyttämällä pilvipalveluita uusien näkemysten ja suositusten antamiseen paremman päätöksenteon mahdollistamiseksi.
                        Tarkkailu-kategorian tutkimusten käsittelemät teknologiasovellukset voitiin jakaa kolmeen arkkitehtuuritasoon **(Zou, 2014)**: I) WSN:n tukema havaintokerros (perception layer) II) verkkotaso (network layer), missä sensoreilta saatu informaatio siirretään pitkiä matkoja ja III) sovellustaso (application layer) joka pitää sisällään web-palvelimen ja tietokannan.
                        Tarkkailu-kategorian tutkimusten käsittelemät teknologiasovellukset keskittyivät tarkkailemaan useita erityyppisiä fyysisiä muuttujia sen mukaan, mihin alikategoriaan ne kuuluivat. Tarkkailu-kategorian alikategorioita havaittiin olevan: ilmanlaadun tarkkailu (air monitoring) 34.5 %, maaperän tarkkailu (soil monitoring) 27.3 %, vedenlaadun tarkkailu (water monitoring) 16.4%, kasvien tarkkailu (plant monitoring) 10.9 % sekä muut (others) 10.9 % johon kuuluivat sellaiset teknologiasovellukset kuten kalanviljely (aquaculture) ja eläinten tarkkailu (animal monitoring). Monet tässä kirjallisuuskatsauksessa viitatuista tutkimuksista käsitelivät useampia alikategorioita.
                            Tarkkailu-kategorian alikategoriat:
                                ilmanlaadun tarkkailu (air monitoring) 34.5 %
                                    Tämän alikategorian teknologiasovellukset pyrkivät ajoittaiseen tai jatkuvaan ympäristöarvojen (environmental parameters) tai saastumisen (pollution levels) mittaamiseen negatiivisten tai vahingollisten vaikutusten ennaltaehkäisemiseksi. Tässä alikategorian teknologiasovelluksissa pyrittiin myös ennustamaan ekosysteemin tai biosfäärin kokonaisuuden muutoksia. 
                                    Esimerkkinä mainittiin **Watthanawisuth et al. (2009)**, jossa esitettiin WSN-perusteinen AIoT-järjestelmä mikroilmaston reaaliaikaisen mittaukseen/havainnointiin. Järjestelmä sisälsi lämpötilan ja suhteellisen kosteuden mittauksen sensorit (SHT15), joiden virtalähteinä toimivat aurinkopaneelit ja perustui ZigBee-verkkoratkaisuun.
                                    Toinen katsauksessa mainittu esimerkki ilmanlaadun tarkkailusta IoT-ratkaisulla on GEMS **(Lu et al., 2010)**, jossa esitettiin GPRS-perustainen omenapuutarhojen ympäristön seurantajärjestelmä, jolla mitattiin erilaisia ympäristömuuttujia kuten suhteellista kosteutta, lämpötilaa sekä säteilyä ja jota testattiin 
                                    Kiinassa viidellä eri alueella yli kahden vuoden ajan.
                                maaperän tarkkailu (soil monitoring) 27.3 %
                                    Maaperän tarkkailun alikategoriassa esitetyt järjestelmät kuten **(Chen et al., 2014 and Mafuta et al., 2012)** tarkkailivat monitasoista maaperän lämpötilaa ja kosteutta pelloilla WSN-perusteisilla ratkaisuilla. Tiedonsiirtoon nämä järjestelmät käyttivät ZigBee:tä, GPRS:ää ja Internetiä, käyttäjän toimintojen käsittelyn mennessä web-sovelluksen kautta. *_hyi saatana mikä virke_*
                                vedenlaadun tarkkailu (water monitoring) 16.4%
                                    Vedenlaadun alikategoriassa esitetyt järjestelmät pyrkivät tarkkailemaan veden saastuneisuutta tai veden laatua mittaamalla kemikaalipitoisuuksia, pH:ta ja lämpötilaa. Esimerkkinä mainitaan **Postolache et al. (2013)** ehdottama IoT-järjestelmä, jossa sähkönjohtavuuden, lämpötilan ja sameuden mittauksilla toteutettiin vedenlaadun tarkkailua. Ratkaisussa tarkkailtiin useita veden laadun parametreja matalissa vesistöissä kaupunkialueilla ja järjestelmässä käytettiin edullisia mittauslaitteita yhdistettynä WSN-arkkitehtuuriin.
                                    Toisena esimerkkinä mainitaan **(Xijun et al., 2009)** esittämä kastelujärjestelmään rakennettu WSN-perustainen vedenkorkeuden (water level) ja sademäärän tarkkailua tekevä ratkaisu.
                                kasvien tarkkailu (plant monitoring) 10.9 %
                                    Kasvien tarkkailun esimerkkinä katsauksessa mainitaan LOFAR-agro Project **(Langendoen et al.,2006)** joka pyrki perunan suojeluun phytophthora-sientä vastaan mikroilmaston tarkkailulla laajamittaisen WSN-ratkaisun avulla. Järjestelmällä pyrittiin kehittämään käytänne perunasadon suojelemiseksi sieniperäistä kasvitautia vastaan käyttämällä kerätyn datan perusteella. **Fourati et al. (2014)** tekijät esittävät web-pohjaisen kosteutta, auringonsäteilyä, lämpötilaa ja sadetta mittaavan tukijärjestelmän oliivien kastelujärjestelmälle, jonka tiedonsiirto perustui WSN-ratkaisuun.
                                muut (others) 10.9 %
                                    Katsauksessa mainittiin myös eläinten tarkkailun ratkaisut, jotka eivät kuulu tämän opinnäytetyön rajauksen piiriin.

                    Kontrollointi-kategoria
                        Kontrollointi-kategoriaan valitut tutkimukset käsittelivät ohjattavaan ympäristöön asennettuja etätoimilaitteita (remote actuator). Toisin kuin tarkkailu-kategorian ratkaisuissa, joissa tiedon kulku on yksisuuntainen, tämän kategorian ratkaisuissa tiedon kulku on kaksisuuntainen. Tällöin komentoja voidaan lähettää palvelimelta tai käyttöpalvelusta (data center) langattomaan sensori- ja aktuaattori/toimilaiteverkkoon (Wireless Sensor and Actuator Network, WSAN) aktuaattorien/toimilaitteiden kontrolloimiseksi prosessin tai ympäristön muuttamiseksi.
                        Katsauksessa käsitellyissä tutkimuksissa komentoja lähetettiin joko käyttäjän toimesta käyttöliittymän avulla tai analytiikkamodulien tukeman päätöksentekoalgoritmin tuloksena. Useat järjestelmät pyrkivät veden, lannoitteiden ja kasvinsuojeluaineiden käytön optimointiin. Tähän optimointiin pyrittiin sääennustepalveluiden ja paikallisen (on-site) WSN:n tuottaman informaation perusteella.
                        Tämän kategorian ratkaisut voivat auttaa viljelijöitä optimoimaan kasteluveden käyttöä säätämällä kastelun ajastusta ja määrää kasvien todellisen tarpeen mukaiseksi. Kontrollointijärjestelmät oli ohjelmoitu sopeutuviksi, esimerkisi keskeyttämään kastelu sateen sattuessa. Kokonaisuudessaan käsitellyt ratkaisut voivat säästää rahaa ja samalla tarjota arvokasta tietoa kasteluveden, lannoitteiden, kasvinsuojeluaineiden ja sähkön kulutuksesta.
                        Ratkaisuissa käytettyjen aktuaattori/toimilaitteiden tyyppi vaihteli huomattavasti riippuen alakategoriasta johon tarkasteltu järjestelmä kuului. Katsauksen Kontrollointi-kategorian alakategoriat olivat: kastelu (irrigation) 72.22 %, lannoitus (fertilizers) 5.56 %, kasvinsuojelu (pesticides) 5.56%, valaistus (illumination) 5.56 %, pääsyn hallinta (access control) 5.56 %. Osa katsauksessa käsitellyistä ratkaisuista käytti aktuaattoreita/toimilaitteita logistiikassa (logistics) 5.56 %.
                        Kontrollointi-kategorian alakategoriat:
                            kastelu (irrigation) 72.22 %
                                Esimerkkinä WSN-perustaisesta tarkkuuskasteluratkaisusta (precision irrigation) katsauksessa mainittiin **Kanoun et al.(2014)** esittämä ratkaisu, jossa automaattisen kastelujärjestelmän avulla pyrittiin vähentämään kasteluveden käyttöä, säästämään energiaa, aikaa ja rahaa. Järjestelmä rakennettiin kolmesta TelosB mote -laitteista: I) yksi maaperän kosteuden ja lämpötilan mittaamisessa, II) yksi ympäristöparametrien (ilman lämpötila, ilmankosteus, tuulen nopeus, kirkkaus) mittaamisessa, III) ja yksi kasteluventtiilin kontrolloinnissa. Sensorien tuottama data lähetettiin tallennettavaksi perusasemalle (base station) ja siirrettiin sieltä viljelijän PC:lle, josta voitiin kontrolloida järjestelmän toimintaa.
                                Toinen esimerkki IoT-avusteisesta kastelujärjestelmän toteutuksesta oli **Jiao et al. (2014)** esittelemä tomaattikasvihuoneen WSN-perustainen ratkaisu, joka sisälsi ympäristön tarkkailun ja tarkkuustihkukastelun. Järjestelmää kuvailtiin katsauksessa omaksi kolmitasoiseksi IoT-ekosysteemikseen, jonka tasot olivat mittaus (sensing), tiedonsiirto (transmission) ja sovellus (application). WSN:ia käytettiin kasvatustilan reaaliaikaiseen sensorointiin ja myöhemmin siirtämiseen etäpalvelimelle (remote server management system).
                                Kolmas esimerkki kastelujärjestelmistä oli **Shuwen and Changli (2015)** kuvailema ZigBee-verkkoratkaisuun perustuva kaukaisen peltokastelun ratkaisu, jossa aurinkokennoja voimanlähteenä käyttävä kastelunhallintajärjestelmä sisälsi myös ilman lämpötilan, kosteuden ja maaperän kosteuden tarkkailun.
                            lannoitus (fertilizers) 5.56 % ja kasvinsuojelu (pesticides) 5.56%
                                Katsauksessa käsitellyt IoT-ratkaisut tässä alikategoriassa keskittyivät käytänteisiin ravinteiden käytön tehostamiseksi, tehokkuuden lisäämiseksi, sadon laadun parantamiseksi ja määrän lisäämiseksi sekä taloudellisen tuloksen parantamiseksi.
                                Esimerkkinä **Pahuja et al. (2013)**, missä tekijät kehittivät mikroilmaston tarkkailu- ja hallintajärjestelmän kasvihuoneille. Järjestelmä käytti WSN:ia kasveihin liittyvän sensoridatan keräämiseen ja analysointiin. Analyysin tuloksia käytettiin kasvihuoneen ilmaston, lannoituksen, kastelun ja tuholaistorjunnan ohjaamiseen. 
                            valaistus (illumination) 5.56 %
                                Esimerkkinä valaistuksen hallinnasta katsauksessa mainittiin **Yoo et al. (2007)**, missä kuvailtiin WSN-perustainen ratkaisu melonien ja kaalien kasvihuonekasvatuksen tueksi. Järjestelmä tarkkaili kasvuprosessia halliten kasvatusympäristöä. Tarkkailtuja ympäristöparametreja olivat muun muassa vallitseva valo, lämpötila ja kosteus. Melonien kasvatuksessa järjestelmä kykeni kontrolloimaan kasvihuoneen valaistusta releen avulla.  
                            pääsyn hallinta (access control) 5.56 %
                                **Roy et al. (2015)** esittivät tunkeutumisen havaitsemisjärjestelmän, joka havaitessaan tunkeutujan pellolla suorittaa hälytyksen viljejijän talossa ja lähettää tekstiviestin viljelijän matkapuhelimeen.
                            logistiikka (logistics) 5.56 %
                                Ei ollut, ilmeisesti omassa kategoriassaan, eikä alikategoriana.
                    Ennustus-kategoria
                        Ennustus-kategoriaan valittut tutkimukset keskittyivät viljelijän päätöksenteossa tarvittavan tiedon ja työkalujen tuottamiseen. Esitettyjen ratkaisujen arkkitehtuurissa oli tähän tarkoitukseen erityiset modulit. Ratkaisujen ennustamat muuttujat ryhmiteltiin seuraavalla tavalla: ympäristön tila (environmental conditions) 42.86 %, tuotannon arviointi (production estimation) 42.86 %, satoisuus **(?)** (crop growth) 14.29 %.
                        Ennustus-kategorian alikategoriat:
                            ympäristön tila (environmental conditions) 42.86 %
                                **Khandani and Kalantari (2009)** kuvailivat suunnittelumenetelmän jonka avulla voitiin määritellä alueellinen näytteenotto maaperän kosteussensoreille WSN:in sisällä. Tietokannasta johon oli tallennettu historiadataa maaperän kosteuden mittauksista tiheällä mittausvälillä määriteltiin kaksiulotteinen korrelaatio läheisten sensorien mittauksille. Tätä korrelaatiota käytettiin myöhemmin suurimman alueellisen näytteenoton löytämiseen, jolla voidaan varmistaa käyttäjän määrittelemä suurin vaihtelu arviossa missä tahansa määritellyn tilan pisteessä.
                                **Luan et al. (2015)** kuvailivat järjestelmän, jossa integroitiin kuivuuden tarkkailu ja ennustus sekä kastelun ennustus IoT-ratkaisua käyttäen.
                            tuotannon arviointi (production estimation) 42.86 %
                                **Lee et al. (2013)** esittelivät IoT-pohjaisen maataloustuotannon järjestelmän jolla pyritään tasaamaan tuotteiden kysyntää ja tarjontaa. Tähän päästiin mittaamalla ympäristömuuttujia ja kehittämällä ennustusjärjestelmä kasvun ja satoisuuden ennustamiseen.
                            satoisuus **(?)** (crop growth) 14.29 %
                                **Lee et al. (2012)** esittelivät järjestelmän, jolla pyritään viljelymaan dynaamiseen analysointiin mobiilien sensorien avulla. Järjestelmä pyrki luomaan hallintasuunnitelmia rypäleiden kasvatukselle sekä muille viininviljelyn toiminnoille. 
                    Logistiikka-kategoria
                        Logistiikka-kategoriaan valittut tutkimukset keskittyivät fyysisten kokonaisuuksien virtaukseen ja siihen liittyvään informaatioon tuottajalta kuluttajalle kulutuskysynnän tyydyttämiseksi. Tähän sisältyy maataloustuotanto, hankinta, kuljetus, varastointi, lastaus, käsittely, pakkaus, jakelu sekä niihin liittyvät toiminnot. Maatalouden logistiikan tavoitteisiin kuuluivat muun muassa maataloustuotteiden arvon lisäys, jakelukustannuksien vähentäminen, kuljetustehokkuuden lisäys, tarpeettoman hävikin vähentäminen sekä jossakin määrin riskien välttäminen **(Liping, 2012)**. Käsiteltyjen logistiikan kategorian tutkimukset ryhmiteltiin seuraavalla tavalla: tuotanto (production) 55.6 %, kaupankäynti (commerce) 22.2 %, kuljetus (transport) 22.2 %.
                            tuotanto (production) 55.6 %
                                **Feng et al. (2012)** esittelivät älykkään järjestelmän omenapuutarhan tarkkailuun joka toteutti dataan perustuvia ehdotuksia. Järjestelmä pyrki vähentämään omenapuutarhojen hallinnointikulujen vähentämiseen, omenoiden laadun parantamiseen sekä yksityiskohtaisen, kattavaan ja tarkkaan sähköiseen informaatioon istutustöitä, tuholaisvaroituksia ja omenien tuotannon laaduntarkkailuun. Järjestelmään kuului WSN, jossa käytettiin ZigBee-verkkoratkaisua, GPRS-mobiiliyhteyksiä sekä IoT-teknologioita joiden avulla tuotettiin yksityiskohtaista dataa omenoiden kasvusta maatalousosuuskunnille päätöksenteon tueksi. 
                            kaupankäynti (commerce) 22.2 %
                                **Li et al. (2013)** esittelivät IoT-perustaisen tietojärjestelmän jossa käytettiin hajautettua arkkitehtuuria. Järjestelmä seurasi ja jäljitti koko tuotantoprosessin hajautettujen IoT-palvelinten avulla. Lisäksi kehitettiin tiedonhakujärjestelmä joka pystyi implementoimaan, keräämään, standardisoimaan, hallitsemaan, paikantamaan ja hakemaan (query) liiketoimintadataa tuotannosta. Järjestelmä mahdollisti myös tuotteiden laatu- ja alkuperätietojen haun kuluttajille.
                            kuljetus (transport) 22.2 %
                                **Pang et al. (2015)** esittelivät IoT-arkkitehtuurin ruoantuotannon arvoketjulle. Esitetyssä ratkaisussa seurattiin logistiikan toimintaa melonien 46 päivää kestävässä kuljetuksessa Brasiliasta Ruotsiin. Sensorit mittasivat kuljetuksen ympäristömuuttujista lämpötilan, kosteuden ja mekaanisen rasituksen (tärinä, kallistus, isku) lisäksi hapen, hiilidioksidin ja etyleenin pitoisuuksia.

            Toinen tutkimuskysymys:
            *"Which infrastructure and technology are using the main solutions of IoT in agro-industrial and environmental fields?"*
                Infrastruktuurit ja teknologiat valituissa IoT-ratkaisuissa jaettiin seitsemään ryhmään:
                    *(i) sensing variables, (ii) actuator devices, (iii) power sources, (iv) communication technologies, (v) edge computing technologies (Shi et al., 2016), (vi) storage strategies, and (vii) visualization strategies*
                    (i) sensing variables 
                        Noin 26 % käsitellyistä tutkimuksista mittasi lämpötilaa, 16 % kosteutta, 11 % fysikaaliskemiallisia ominaisuuksia ja 10 % säteilyä. Lämpötilan ja fysikaaliskemian sensorit olivat jakautuneet kaikkiin alikategorioihin. 55 % sensoreista oli ilmanlaadun mittaukseen. Tämän perusteella ilman lämpötilaa, ilmankosteutta, maaperän kosteutta ja auringonsäteilyä voidaan pitää universaaleina muuttujina maatalouden sovelluksissa.
                    (ii) actuator devices
                        Aktuaattori- tai toimilaitteita oli käsitellyistä tutkimuksissa käytössä huomattavasti vähemmän kuin sensoreita. Suurin osa toimilaitteista oli käytössä kontrolloinnin ja logistiikan kategorioissa. 60 % toimilaitteista oli käytössä kasteluprosesseissa.
                    (iii) power sources
                        Tarkkailu-kategorian sovelluksista suurin osa käytti aurinkopaneeleilla ladattavia akkuja, joka on yksinkertainen ja kestävä (sustainable) ratkaisu.
                        Kontrollointi-kategorian sovelluksista, joissa tyypillisesti vaativat enemmän energiaa, suurin osa käytti verkkovirtaa. Uudenaikaisempia energialähteitä kuten sähkömagneettisen tai tärinän energiankeräimiä (harvesters) ei löytynyt käsitellyistä tutkimuksista. Katsauksen tekijöiden mukaan tämä osoittaa kyseisten energiaratkaisuiden kypsyyden ja suosion puutetta maatalouden sovelluksissa.
                    (iv) communication technologies
                        Viestintätekniikoista 40 % perustui langattomiin henkilökohtaisien verkkojen (Wireless Personal Area Network, WPAN) protokolliin kuten Bluetooth ja ZigBee, kolmanneksi yleisimpänä ollessa Wireless Metropolitan Area Network (WMAN). 36 % perustui vastaavasti matkapuhelinverkon ratkaisuihin (GPRS/GSM/3G/4G). Likiyhteystekniikat (near-field communication) on alkanut ilmaantua joihinkin ratkaisuihin pelto/kenttäsovelluksissa (field).
                    (v) edge computing technologies (Shi et al., 2016)
                        Reuna-laskennan teknologiasovelluksista mikrokontrolleripohjaisia ratkaisuja oli katsauksessa käsitellyissä sovelluksissa yli puolessa. Yhden kortin tietokoneet (Single Board Computers, SBC) eivät katsauksen tekijöiden mukaan ole vielä sopivia maatalouden sovelluksiin, ilmeisesti niiden harvinaisuuden perusteella käsitellyissä sovelluksissa.
                    (vi) storage strategies
                        Tiedon tallennusstrategioissa suurin osa käsitellyissä tutkimuksissa käytetyistä ratkaisuista oli omia ratkaisuita. Pilvipalveluita tiedon tallentamiseen käytti vain 7.32 % katsauksessa käsitellyistä tutkimuksista.
                    (vii) visualization strategies
                        Visualisaatiostrategiat jakaantuvat web-, mobiili- ja paikallisiin ratkaisuihin neljässä kategoriassa: tarkkailu, kontrollointi, ennustus, logistiikka. Katsauksen tekijöiden mukaan voi sanoa, että web-pohjaiset ratkaisut ovat tiedon näyttämiseen selkeästi yleisimpiä kaikissa kategorioissa.
                Suurin osa katsauksessa käsitellyistä tutkimuksista ei nimenomaisesti ota kantaa tietoturvaan. Katsauksen tekijät ovat kuitenkin löytäneet joitakin asiaa sivuavia tutkimuksia. 
                **(Jardak et al., 2009)** kuvailivat WSN-suunnitelun (design) joka implementoi RANdom SAmple Consensus (RANSAC) -filtterin vahingollisen/pahantahtoisen tai viallisen sensorinoden aiheuttaman epäjohdonmukaisen tietoliikenteen eliminoimiseksi verkossa.
                **Sun et al. (2012)** esittelivät padonhallintajärjestelmän jossa käytäjien tulee kirjautua järjestelmään oikeuksien tarkistamiseksi.
                **Tao et al. (2014)** käyttivät AppWeb-sulautettua Web-palvelinta IoT Gatewaylle älykkäässä viljasiilon hallintajärjestelmässä. Tällöin voitiin käyttää hyväksi Secure Sockets Layer (SSL) -protokollaa salatun tietoliikenneyhteyden luomiseksi. Tämä oli katsauksen tekijöiden mukaan tärkeää yhteyden toimiessa langattoman verkon ylitse.
                **Kuroda et al. (2015)** esittelivät WSN-ratkaisun, jossa helppokäyttöinen ja turvallinen tietoliikenneyhteys toteutettiin käyttämällä Zero-admin:in salaus- ja salauksenpurkutoiminnallisuuksia sensorinodejen (?) ja coordinator node:n (?) välillä.
        Viimeaikaiset julkaisut:
            Toukokuun 2016 ja heinäkuun 2017 välillä saatavilla olleita ja edustavia tutkimuksia.
            Alueilla/kategorioissa communications, energy management, monitoring, logistics.
                Tietoliikenne (communications)
                    **Barrachina-Muñoz et al. (2017)** mukaan pienitehoiset (low-power) WAN (LPWAN) -teknologiat kuten SigFox, LoRa, kapean kaistanleveyden IoT jne. ovat kasvattaneet suosiotaan IoT-sovelluksissa pienen virrankulutuksensa, laajan kattavuusalueen ja suhteellisen edullisuutensa (verrattuna pidemmän kantaman ratkaisuihin).
                    **Sinha et al. (2017)** mukaan LoRa on paras vaihtoehto älykkäiden maatalousratkaisuiden tarpeisiin.
                    **Lukas et al. (2015)** tekijät suunnittelivat pitkän kattavuusalueen tarkkailujärjestelmän kaukaloille LoRa-lähettimille perustuvalla WSN-ratkaisulla. Tällöin veden saatavuutta karjalle voitiin tarkkailla yhden tai kolmen kilometrin etäisyydeltä.
                    **Pham et al., 2016** esittelivät IoT-puitekehyksen (framework) maaseudun kehittämiselle implementoimalla maatalouden sovelluksia avoimen lähdekoodin laitteita ja pitkän kantaman tietoliikennelaitteita. LoRa oli tähän luonteva valinta johtuen maaseudun kylien kaukaisesta sijainnista sekä edullisesta infrastruktuurista.
                Energianhallinta (energy management)
                    **Borgia (2014)** mukaan IoT-projektien keskeisiä laitevaatimuksia on energiatehokkuus. Erityisesti laitteet, jotka eivät ole yhteydessä sähköverkkoon, jotka asennetaan ulkotiloihin ja joita ei huolleta säännöllisesti.

    Soita Hydenille
    laita meiliä dodolle
    Kontaktoi tuotantotukku

tautivaroitus
tuholaisvaroitus

    
* Verdouw: Internet of Things in agriculture
* Madakam: Internet of Things (IoT): A Literature Review
* Kamilaris: A review on the practice of big data analysis in agriculture
* Wolfert: Big Data in Smart Farming – A review
* Xu: Internet of Things in Industries: A Survey
* Rose: The Internet of Things (IoT): An Overview

## Katsaukset:

* Pivoto: Scientific development of smart farming technologies and their application in Brazil
* Farooq: A Review on Internet of Things (IoT) 2015
* Tzounis: Internet of Things in agriculture, recent advances and future challenges 2017
* Gubbi: Internet of Things (IoT): A vision, architectural elements, and future directions 2013
* Shaikh: Enabling Technologies for Green Internet of Things 2017
* Khodadadi: Internet of Things: An Overview
* Bo: The Application of Cloud Computing and the Internet of Things in Agriculture and Forestry
* Sundmaeker: Vision and Challenges for Realizing the Internet of Things
* Dlodlo: The internet of things in agriculture for sustainable rural development (2015)
* Stočes: Internet of things (iot) in agriculture-selected aspects 2016
* Motlagh: Low-Altitude Unmanned Aerial Vehicles-Based Internet of Things Services: Comprehensive Survey and Future Perspectives 2016
* Fahran: A survey on the challenges and opportunities of the Internet of Things (IoT) 2017
* Fantana: Internet of Things - Converging Technologies for Smart Environments and Integrated Ecosystems 2013
* Sreekantha: Agricultural Crop Monitoring  using IOT- A Study 2017

## Järjestöjen julkaisut
...

## Teknologiasovellukset/prototyypit/ehdotukset tutkimuksessa
...

## Kaupalliset tuotteet ja julkaisut
...


# Tulokset
## Tutkimusongelma I:n vastaukset
## Tutkimusongelma II:n vastaukset
# Johtopäätökset ja suositukset

## *Yhdistetään kirjallisuuskatsaus ja haastikset*
## *Conclusion*
Määriteltiin tutkimuskysymykset
Vastaukset tutkimuskysymyksiin/ongelmiin

# Lähteet

