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

Kirjoittajan tietämyksen mukaan kasvintuotannossa käytettävistä IoT-ratkaisuista on viime vuosien (2010 - 2018) aikana julkaistu runsaasti tutkimuksia ja erilaisia artikkeleita. Opinnäytetyön esitöissä kävi ilmi, että kirjoittajalla ei ole kovin vahvaa ymmärrystä tai kokemusta maataloudessa käytettävistä IoT-ratkaisuista. Koska maatalouden esineiden internet (AIoT) on voimakkaasti kasvava teollisen esineiden internetin (IIoT) osa (LÄHDE???) ja se voi vaikuttaa huomattavasti ruoantuotannon kehitykseen (LÄHDE???) kirjoittaja arvioi, että AIoT:n tilanteesta kannattaa olla tietoinen. Lisäksi kirjoittaja arvelee, että AIoT:n teknologiaratkaisuiden kehittämisessä tullaan tarvitsemaan asiantuntijoita joilla on sekä maatalouden että ICT-alan ymmärrystä.

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
Agroteknologian viime vuosien nopea kehitys on mahdollistunut muilla alueilla tapahtuneen teknologiakehityksen myötä. Prosessien automatisointi, reaaliaikainen ohjaus ja konenäköjärjestelmät ovat keskeisiä agroteknologian kehitykseen vaikuttaneita teknologiakehityksen alueita *(Ronkainen, 2014)*. Täsmäviljelyn (Precision Agriculture, PA [http://www.aumanet.fi/tasmaviljely/maaritelma.html]) ja määränsäätöautomatiikan (Variable Rate Application VRA) laajentuva käyttö on myös osaltaan nopeuttanut maataloustyökoneiden teknologian kehitystä *(Ronkainen, 2014)*.

Työkoneiden kehityksen myötä maatilojen toiminnan hallinta on monimutkaistunut. Viljelijän tulee tehdä päätöksiä viljelytoimien laadusta, sisällöstä, ajankohdasta ja järjestyksestä ottaen samalla huomioon sekä ympäristönsuojelun että maataloustukien säädökset, lisäksi huolehtien liiketoiminnastaan ja tilansa työkoneista ja muusta infrastruktuurista. Tätä toimintaa ja päätöksentekoa tukemaan on kehitetty erilaisia tiedonhallinnan järjestelmiä, joita kutsutaan Farm Management Information System:eiksi (FMIS). (@elovaaraAggregatingOPCUA2015) FMIS on määritelmällisesti järjestelmä, joka kerää, käsittelee, tallentaa ja välittää dataa tiedon muodossa, jota tarvitaan maatilan operatiivisten toimintojen suorittamisessa *(Sørensen et al. 2010a)-Elsevier, ei pääsyä*.

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
Aineiston keruumenetelmiä oli useita. Varsinaista tutkimustyötä edelsi ilmiöön tutustuminen erilaisilla keruumenetelmiä testattaessa, käyden asiantuntijakeskusteluja, vierailemalla alan tapahtumissa, keräämällä kontakteja ja haastatteluja tehden. Varsinaisen tutkimustyön aluksi haettiin IoT:tä yleistasolla ja ilmiönä käsittelevää kirjallisuutta. Seuraavaksi käytettiin sateenvarjokatsausta, jolla haettiin ilmiötä käsitteleviä kirjallisuuskatsauksia. Valittujen kirjallisuuskatsausten pohjalta muotoiltiin omat hakumetodit ja valittiin osa lähteistä. Omien hakumetodien tuloksista on valittu tekijän harkinnan mukaan aihetta parhaiten kuvaavat. Lisäksi ollaan käytetty aiheeseen tutustuttaessa löydettyjä lähteitä jos ne ovat tekijän harkinnan mukaan olleet tähdellisiä aiheen käsittelylle ja ymmärryksen luomiselle.

Tutkimuksen luotettavuutta pyritään parantamaan käyttämällä aineistotriangulaatiota: kirjallisuuskatsauksen tuloksia vertaillaan haastattelujen tuloksiin sekä tuodaan esille ammattijulkaisuissa, laitevalmistajien sekä muiden toimijoiden tiedotteissa, lehtiartikkeleissa jne. ilmestyneitä asiaan liittyviä asioita.

Lisäksi tutkimuksen luotettavuutta pyritään parantamaan luettamalla haastatteluista tehdyt johtopäätökset muistiinpanoineen haastateltavalla.

Haastattelujen litteroinnissa käytetään yleiskielistä litterointia. Yleiskielistä litterointia tarkempaa sanatarkkaa litterointia on käytetty, jos sanojen poistamisella litteroinnista on arvioitu olevan tarkoitusta mahdollisesti muuttava vaikutus.

Tutkimuksen alustavassa vaiheessa ilmiöön tutustuttaessa tehtiin useita hakuja aiheeseen liittyvillä asiasanoilla, selattiin erilaisten organisaatioiden ja julkaisujen verkkosivuja, haettiin asiantuntijakontakteja eri tapahtumista jne. Löydöt merkittiin muistiin mahdollista myöhempää käyttöä varten.

Haastateltavia etsittiin tapahtumista saatujen kontaktien, aineistosta löytyneiden asiantuntijoiden ja omien verkostojen kautta.  Lisäksi käytettiin "snowballing" -menetelmää, jossa keskusteluissa informanttia pyydettiin suosittelemaan muita asiantuntijoita haastateltaviksi.

*Tästä poistettu hakujen kuvaukset <02-05-2018 18:32>*

Mitä nyt on tehty ja mitä seuraavaksi:
    Käytetty hieman erilaisia hakulauseita eri kantoihin niiden vaatimusten ja toimintojen mukaan.
    Tuloksena kohtuullinen määrä tieteellisiä lähteitä.
    Lähteistä pitää seuraavaksi tarkistaa onko kirjallisuuskatsauksia saturoiva tai muuten riittävä määrä. Katsauksia ollaan haettu erikseen vasta Google Scholarin avulla. Kirjoitetaan havainnot katsauksista. Lähdetään liikkeelle Talaveran kirjallisuuskatsauksesta: mitä kantoja kannattaa hakea? Google Scholar, IEEE, Scopus. Kamilaris et al. käytti IEEE, ScienceDirect, Web of Science, Google Scholar. Verdouw et al. käytti Scopusta, Google Scholaria "*We searched in the Scopus database for papers that on the one hand include Internet of Things or IoT in the title and on the other hand agriculture, farming or food in the title, abstract or the keywords section. In addition, we used generic references on IoT and enabling technologies by using Google scholar especially searching for review articles that provide an overview of the application of specific enabling technologies in the agricultural domain.*"



Löydettyjä kirjallisuuskatsauksia käytetään seuraavasti:
Tiedon kattavuutta pyritään parantamaan hakemalla sateenvarjokatsauksen omaisesti aihetta käsitteleviä kirjallisuuskatsauksia. Hakutuloksista valituista kirjallisuuskatsauksista käydään läpi tutkimusmetodit joista löytyviä hakumenetelmiä käytetään hyväksi soveltuvin osin tämän työn seuraavissa tiedonhakuvaiheessa.

SEURAAVAKSI: 
Sateenvarjokatsauksen loppuun vienti:
    Katsausten asiasanat yhteen, haku niillä katsausten metodeista parhaisiin kantoihin. Lisäksi käydään läpi kannoista kuhunkin katsaukseen liittyvät julkaisut, esim. Science Direct:in "Recommended articles"
Valituista katsauksista otetaan asiasanat ja mallit hakulauseisiin/metodeihin. Asiasanoihin lisätään sellaiset, jotka ovat tulleet aikaisemmissa vaiheissa esille ja joiden oletetaan olevan keskeisiä tutkittavalle ilmiölle tai jollekin sen osalle. Kirjoitetaan löydökset.
Tehdään varsinaiset hakulauseet ja valitaan kannat. Tehdään haut. Valitaan tuloksista sopivat metodilla Mutu-X. Kirjoitetaan löydökset.
Käydään läpi CEMA, IoF2020, AEF sekä muut mahdollisesti vastaan tulleiden toimijoiden julkaisut. Kirjoitetaan havainnot.
Käydään läpi haastattelujen litteroinnit ja kirjoitetaan löydökset. Tarkistetaan oikeellisuus haastateltavien kanssa.
Lisätään mahd. mukaan aikaisemmista vaiheista mukaan tulleet lähteet ja kirjoitetaan löydökset.
Kirjoitetaan tulokset.
Refaktoroidaan haastatteluprotokolla jos se tarvitaan mukaan työhön.
Refaktoroidaan tutkimusongelma ja -kysymykset.
Kirjoitetaan Johtopäätökset ja suositukset

Mahdollinen rakenne:
    Lähteiden hankinta
    Metodit
    Jaottelu
    Kirjallisuuskatsaukset:
        Atzori: Internet of Things in Industries: A Survey 2010
        Talavera: Review of IoT applications in agro-industrial and environmental fields 2017
        Verdouw: Internet of Things in agriculture 2016
        Madakam: Internet of Things (IoT): A Literature Review 2015
        Farooq: A Review on Internet of Things (IoT) 2015
        Kamilaris: A review on the practice of big data analysis in agriculture 2017
        Wolfert: Big Data in Smart Farming – A review
        Pivoto: Scientific development of smart farming technologies and their application in Brazil
    Katsaukset:
        Tzounis: Internet of Things in agriculture, recent advances and future challenges 2017
        Gubbi: Internet of Things (IoT): A vision, architectural elements, and future directions 2013
        Shaikh: Enabling Technologies for Green Internet of Things


    Muut katsaukset
    Teknologiasovellukset (tieteelliset lähteet)
        Tekn.sov. puutarhatuotannossa
        Tekn.sov. peltotuotannossa


# Tulokset
## Tutkimusongelma I:n vastaukset
## Tutkimusongelma II:n vastaukset
# Johtopäätökset ja suositukset

## *Yhdistetään kirjallisuuskatsaus ja haastikset*
## *Conclusion*
Määriteltiin tutkimuskysymykset
Vastaukset tutkimuskysymyksiin/ongelmiin

# Lähteet

