# TERMIT

tilanhallintajärjestelmä Farm Management System FMS
viljelysuunnitteluohjelma
rajapinta
satopotentiaali
satovaste
satotappio
sadonlisä
satotasomittari
tuotantoketju
ruokaketju
arvoketju

telemetria

# JOHDANTO

*<13-05-2018  12:09> Tämä on nyt vain yleistä lätinää eikä mikään johdanto! Uusiks.*

-- Omia huomioita 17.11.2017: Olen jotenkin olettanut, että totta kai maataloudessa oltaisiin jo omaksuttu paljon enemmän IoT-teknologioita, samaaan tapaan kuin muualla teollisuudessa. Jokin alan vieraudessa on vaikuttanut minuun. Ehkä työni ensimmäinen hämmästynyt kysymys oli: "Sitä tietoa ei siis saa sieltä koneesta ulos?" Viljelijöiden harkitsevuus uusien teknologioiden käyttöönotossa ei ole takapajuisuutta, ymmärtämättömyyttä tai typeryyttä, vaan sille on hyvä syy: teknologian tulee todistettavasti olla tuottavaa jotta sen käyttöönottoa edes voitaisiin harkita. Niin kuin missä tahansa liiketoiminnassa tai tuotannossa. Kentän hajanaisuus, järjestelmäintegration vaikeus ja hitaus ovat hidastaneet laajamittaista käyttöönottoa huomattavasti peltotuotannossa, osin myös puutarhatuotannossa. Kyse ei ilmeiseti olekaan alan takapajuisuudesta tai merkityksettömyydestä. --
-- <15-05-2018  12:15> ...vaan viljelijöiden omasta harkinnasta liiketoiminnan harjoittajina ja yrittäjinä: jokaiselle omaksuttavalle ja käyttöön otettavalle teknologiaratkaisulle tulee löytyä selkeä taloudellinen peruste. Tämän lisäksi uuden teknologian tulee soveltua yrityksen toimintatapoihin ja liiketoimintaprosesseihin, eli maatilojen viljelykäytänteisiin ja tapoihin tehdä asioita ja hoitaa tilaa. --

Lähti liikkeelle kysymyksestä: "Sitä dataa ei siis saa siitä koneesta ulos?"
Tämä hämmästytti, joten asiaan tutustuttiin pintapuolisesti ja havaittiin, ettei mitään tiedetä mutta tilanne vaikuttaa mielenkiintoiselta: on tulossa uusia teknologioita ja toimintatapoja. Saman tien ei tullut esiin selkeää kokonaiskuvaa alan standardeista ja käytänteistä esineiden internetin (Internet of Things, IoT) käytössä, joten asiaa päätettiin tutkia tarkemmin. 
Lähtökohtaisesti määriteltiin IoT:n olevan järjestelmiä/ratkaisuita, joissa toteutui jatkuvasti kiertävä tiedon tuottamisen, siirtämisen, tallennuksen, analytiikan, päätöksenteon ja aktuoinnin/ohjaamisen/kontrolloinnin täysautomaattinen ketju ilman ihmisen puuttumista ja ohjausta prosessissa.

Aluksi tiedon hankkiminen oli hankalaa ja hyvät lähteet olivat harvassa. Käytetyn IoT-määrittelyn mukaisten ratkaisujen löytäminen alkoi vaikuttaa lähes mahdottomalta.  Ajan kuluessa, kontaktien karttuessa ja hakumenetelmiä opetellessa parempia lähteitä alkoi löytyä. Omat hakutulokset paranivat, kontakteilta saatiin hyviä lähteitä sekä hyviksi todettujen lähteiden viittauksien kautta löytyi yhä enemmän tietoa.
Kokonaiskuva alkoi hitaasti hahmottua samojen asioiden/analyysien/mielipiteiden tullessa vastaan useista eri lähteistä.
Aiheeseen tutustumisen jälkeen tehtiin systemaattisempi tiedonhaku löydettyjen kirjallisuuskatsausten pohjalta.

Kirjoittajan tietämyksen mukaan kasvintuotannossa käytettävistä IoT-ratkaisuista on viime vuosien (2010 - 2018) aikana julkaistu runsaasti tutkimuksia ja erilaisia artikkeleita. Kirjoittajalla ei ole kovin vahvaa ymmärrystä tai kokemusta maataloudessa käytettävistä IoT-ratkaisuista. Koska maatalouden esineiden internet (Agricultural Internet of Things, AIoT) on voimakkaasti kasvava teollisen esineiden internetin (Industrial Internet of Things, IIoT) osa **(LÄHDE???)** ja se voi vaikuttaa huomattavasti ruoantuotannon kehitykseen **(LÄHDE???)** tekijä arvioi, että AIoT:n tilanteesta kannattaa olla tietoinen. Lisäksi tekijä arvelee, että AIoT:n teknologiaratkaisuiden kehittämisessä tullaan tarvitsemaan asiantuntijoita joilla on sekä maatalouden että ICT-alan ymmärrystä.

Motivaatio: Merkittävät vaikutukset ruoantuotannon koko arvoketjuun ja sitä kautta kaikkien elämään. Tästä ei kuitenkaan ole tietoa maatalouden alan ulkopuolella. Maatalouden digitalisoituessa voi syntyä IoT- ja IT-alan osaamisvaje maatalouden sovelluksien suunnittelussa, kehityksessä ja käytön tuessa. Digitalisaation on sanottu etenevän ja muuttavan alan toimintaa räjähdysmäisesti, eikä hiljakseen. Tämä voi olla merkittävä työllistäjä lähivuosina IT-alan osaajille ja varsinkin IoT-erikoisosaajille ja erityisesti sekä maatalouden että IT-alan hallitsevia ihmisiä tullaan tarvitsemaan.

## Yleisjohdanto (sis. Tavoitteet, tutkimusongelma, rajaus, käsitteet)

Maatalouteen kohdistuu jatkuvasti kovenevia tehokkuusvaatimuksia, samalla kun teknologinen kehitys mahdollistaa tehokkaampia viljelyprosesseja. Lisäksi maataloudelle ja ruokaturvalle asettaa haasteita ilmastonmuutos ja väestönkasvu. Näihin vaatimuksiin ja haasteisiin pyritään osaltaan vastaamaan digitalisoimalla maatalouden prosesseja kuin muilla teollisuuden aloilla.

*IIoT Industry 4.0:sta sivut 2-5*  *Sitten miten maatalous liittyy IIoT:hen*

"Ilmastonmuutos, ekosysteemipalvelujen heikkeneminen, resurssien niukkeneminen, ruoan ja energian lisääntyvä tarve, nopea sosiaalinen eriarvoistuminen, maahanmuutto ja ihmisten etääntyminen ruoan alkuperästä"
*(Evernote: Abstract: Hyvin sanottu! Parasta ruokaa - hyvää elämää)*
--Samalla kuluttajien vaatimukset lähiruoalle, läpinäkyvälle tuotantiketjulle ja luomulle-- lähde?

*Pylväs esityksessään KoneAgriassa: ei ole vielä otettu pelloista läheskään kaikkea irti*

Artikkelista voi noukkia monet hyvät pointit.
*(Evernote: Paljon viitteitä: The future of agriculture | The Economist)*

"Luonnonvarakeskuksen teknologiapäivässä asiasta oltiin yksimielisiä" Datan omistajuus tykätään pitää tekijöillä.
"– Hankkeemme merkittävä havainto oli, että maatilan data on erotettava sovelluksista, jotta sitä voidaan käyttää tehokkaasti hyväksi viljelijää avustavissa palveluissa ja sovelluksissa, toteaa Cropinfra-hankkeen vetäjä, vanhempi tutkija Liisa Pesonen."
Automaattiohjausjärjestelmät yleistyneet huomattavasti Australiassa, muut täsmäv. maltillisemmin -Timo Oksanen "Syyksi jonkin tietyn teknologian nopeaan yleistymiseen nähtiin järjestelmien käytettävyys ja suora työsuorituksen helpottuminen."
"Teknologiapäivässä alan toimijoiden välisessä keskustelussa kuitenkin todettiin, etteivät teollisen Internetin mukanaan tuomat uudet teknologiat tule syrjäyttämään tällä hetkellä yleistymässä olevia tekniikoita kuten ISOBUS-tekniikkaa.
Haasteena uusien teknologioiden käyttöönottoon nähtiin koneketjujen ja palveluiden muodostaman kokonaisuuden sekä uusien toimintamallien riittävä testaaminen."
*(Evernote: Digitalisoituminen avaa kasvinviljelyyn ja metsänhoitoon uusia toimintamalleja - Luonnonvarakeskus)*

"Alkutuotannon kehittyessä yhä riippuvaisemmaksi internetiin kytketystä tietotekniikasta ja automaatiosta järjestelmien kyberturvallisuus on otettava huomioon. Kyberturvallisuuden puutteista aiheutuva uhka on sitä suurempi mitä pidemmälle kehityksessä edetään."
*(Evernote: Kyberturvallisuus on elintärkeä myös maataloudessa - Luonnonvarakeskus)* 

*Perustuen Joona Elovaaran "Aggregating OPC UA Server for Remote Access to Agricultural Work Machines" diplomityön osioon 1.1 Background:*
Agroteknologian viime vuosien nopea kehitys on mahdollistunut muilla alueilla tapahtuneen teknologiakehityksen myötä. Prosessien automatisointi, reaaliaikainen ohjaus ja konenäköjärjestelmät ovat keskeisiä agroteknologian kehitykseen vaikuttaneita teknologiakehityksen alueita *(Ronkainen, 2014)*. Täsmäviljelyn (Precision Agriculture, PA [http://www.aumanet.fi/tasmaviljely/maaritelma.html]) ja määränsäätöautomatiikan (Variable Rate Application VRA) laajentuva käyttö on myös osaltaan nopeuttanut maataloustyökoneiden teknologian kehitystä **(Ronkainen, 2014)**.

...

Tämä on tutkimustyyppinen opinnäytetyö, jossa toteutetaan laadullinen tutkimus.

Käytettävät tutkimusmenetelmät ovat kuvaileva (narratiivinen) kirjallisuuskatsaus sekä teemahaastattelut.

Tämä opinnäytetyö pyrkii tuottamaan ajankohtaisen yleiskatsauksen kasvintuotannossa käytettäviin esineiden internetin (Internet of Things, IoT) teknologiasovelluksiin ja niiden tutkimukseen.

Teknologiasovelluksista käsitellään sekä tutkimus- ja prototyyppiluonteisia toteutuksia että kaupallisia tuotteita.

Opinnäytetyön aihepiirinä on kasvituotannon esineiden internetiin (Agriculture Internet of Things, AIoT) liittyvät tutkimukset, julkaisut ja teknologiasovellukset. Opinnäytetyössä haastatellaan asiaan perehtyneitä tutkijoita (*viljelijöitä, yrittäjiä -nämä haastattelut puuttuvat vielä*) ja yritysten edustajia. Teemahaastatteluilla saatujen tietojen avull pyritään trianguloimaan kirjallisuuskatsauksessa ja esitöissä löydettyä tietoa paremman yleiskuvan hahmottamiseksi.

Opinnäytetyön laajuuden rajallisuuden vuoksi aihealueeksi on rajattu kasvituotannon IoT-ratkaisut, minkä kirjoittaja arvioi olevan yleisen ruoantuotannon kannalta vaikuttavin osa. Samasta syystä tässä opinnäytetyössä ei käsitellä teknologiaratkaisuita kuten verkkoprotokollia, sensoritekniikkaa tai algoritmejä, vaan keskitytään kuvailemaan kasvintuotannon IoT-ratkaisuita yleistasolla.

## Peltokasvituotanto-johdanto

Yleistä lätinää peltokasvituotannosta. Määrittely, luonne.
Kevyesti luonnehdittu tavoitetila.
Lyhyesti millaisia sovelluksia nyt on.

*Perustuen Joona Elovaaran "Aggregating OPC UA Server for Remote Access to Agricultural Work Machines" diplomityön osioon 1.1 Background:*
Työkoneiden kehityksen myötä maatilojen toiminnan hallinta on monimutkaistunut. Viljelijän tulee tehdä päätöksiä viljelytoimien laadusta, sisällöstä, ajankohdasta ja järjestyksestä ottaen samalla huomioon sekä ympäristönsuojelun että maataloustukien säädökset, lisäksi huolehtien liiketoiminnastaan ja tilansa työkoneista ja muusta infrastruktuurista. Tätä toimintaa ja päätöksentekoa tukemaan on kehitetty erilaisia tiedonhallinnan järjestelmiä, joita kutsutaan Farm Management Information System:eiksi (FMIS). (@elovaaraAggregatingOPCUA2015) FMIS on määritelmällisesti järjestelmä, joka kerää, käsittelee, tallentaa ja välittää dataa tiedon muodossa, jota tarvitaan maatilan operatiivisten toimintojen suorittamisessa **(Sørensen et al. 2010a)-Elsevier, ei pääsyä**.

Useimpien traktorien ja työkoneiden ollessa sähköisesti hallittuja ja niihin asennettujen sensorien tuottaessa dataa, voitaisiin tämä data kerätä ja jalostaa tiedoksi esimerkiksi koneiden huollosta, rikkoutumisista ja työsuorituksista. Tämän tiedon avulla voitaisiin parantaa täsmäviljelyn ja työkoneiden hallinnan käytänteitä.

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
FAO - News Article: Scarcity and degradation of land and water: growing threat to food security *Tämä voi olla tärkeä taustaksi, miksi tarvitaan AIoT:n hyötyjä*s

## Puutarhatuotanto-johdanto

Yleistä lätinää puutarhatuotannosta. Määrittely, luonne.
Kevyesti luonnehdittu tavoitetila.
Lyhyesti millaisia sovelluksia nyt on.

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

## Kasvihuonetuotanto-johdanto

*Tähän tavarat puutarhatuotannosta, jotka menevät suoraan kasvihuoneisiin ja -tehtaisiin*f

# TEORIATAUSTA

## Metodologiaa (ei opparitekstiin)

"käsitellään ilmiötä selittäviä teorioita...esitellään ne tieteelliset työt, teoriat ja mallit, joilla ilmiötä on aikaisemmin selitetty"
Teoriatausta-luvussa pyritään hahmottelemaan kasvintuotannon IoT-ratkaisuista tähän asti tehty tutkimus, tai mitä aiheesta on jo kirjoitettu.

MUTTAKUN: Nasirin gradussa on ilmiöiden kuvailu 
Chapter 2 is Business Sustainability
Chapter 3 is Innovation for Sustainability
Chapter 4 is about IOT as Expression of Disruptive Innovation
Chapter 5 is about IOT in Disruptive Innovation for Sustainability. This chapter will answer to the second and third sub-question
Chapter 6 is about the Practical Perspective
Chapter 7 is Discussion ...first part is the results which draw a comparison between findings from literature review among different scientific articles and SITRA’s perspective...
Chapter 8 is Conclusion which finalizes this thesis with the findings

"...voidaan ymmärtää myös niin, että sillä tarkoitetaan sitä, mitä aiheesta on kirjoitettu...voidaan ymmärtää siksi kirjoitteluksi, mitä ilmiön osalta kirjallisuudesta ja tieteestä löytyy."

## Taustaa

Maatalous/kasvituotanto ja IoT ovat yhdistymisen alkuvaiheessa, vaikka kaikki tarvittavat teknologiat ovat jo saatavilla.
On sanottu (?) että ollaan maatalouden vallankumouksen reunalla. Vaikka tällä odotetulla vallankumouksella voi olla huomattavat vaikutukset ruoantuotantoon sekä koko arvo- ja tuotantoketjuun pellolta lautaselle asti, niin tekijällä ei ollut ennen työn aloitusta siitä minkäänlaista havaintoa. Teollisesta esineiden internetistä (Industrial Internet of Things, IIoT) on uutisoitu, mutta maatalouden esineiden internetistä ei ilmeisesti olla laajasti tietoisia. Tämä voi johtua siitä, että laajamittaista käyttöönottoa ei ole vielä tapahtunut ja näin ollen asiasta ei juuri uutisoida alan ulkopuolella.

Miksi tämä kasvintuotannon IoT on kiinnostava -ja ajankohtainen aihe?
Useissa lähteissä viitattu FAO:n raportti! Muut perusteet IoF2020.
Tällä teknologiakehityksellä voi olla todella merkittävät vaikutukset
-tähän haasteet ja saavutukset
-tähän yhteys IIoT:hen, IIoT:n saavutukset

Jotta lukija ymmärtäisi ilmiön kokonaisuudessaan, käydään lyhyesti läpi IoT:n, IIoT:n, AIoT:n ja kasvintuotannon määrittelyt ja historiaa.

## Kasvintuotanto

Ensin määritellään lyhyesti kasvintuotanto osana maataloutta ja maatalous osana teollisuutta.

-tähän kasvintuotannon/maatalouden vallankumoukset, miksi viimeisin "green revolution" on osoittautumassa kestämättömäksi (mahd. viittaus FAO-raporttiin ja muualle, tästä oli puhetta ööh jossain). Täsmäviljelyn kehitys ja vaatimukset sensoreille ja sitten datalle, analytiikalle, Farm Management System:eille
-tähän kuvaus kentän hajanaisuudesta, hankkeista, uudet ja vanhat toimijat

 

### Kasvintuotannon määrittely
### Kasvintuotannon historia (aiheeseen liittyen)
### Kasvintuotannon ...
## Internet of Things, esineiden internet

Tässä luvussa/osassa pyritään havainnollistamaan miten esineiden internetin (IoT) kokonaisuutta, taustaa ja historiaa on kuvailtu eri lähteissä.

Lisäksi p.h. miten kasvintuotannon IoT-teknologiaratkaisut ovat osa maatalouden internetiä (AioT), miten AIoT on osa teollista internetiä (IIoT) ja miten IIoT on osa IoT:tä.


Seuraavaksi pyritään havainnollistamaan (pääasiassa kirjallisuuden ja tieteellisten julkaisujen lähteistä) IoT:n tausta historioineen.
Seuraavaksi p.h. miten IIoT ja AIoT liittyvät IoT:hen.
-miten IIoT on osa IoT:tä ja miten Industry 4.0 liittyy tähän?
-miten AIoT on osa IIoT:tä? Eri kategoriat & miten kirjallisuudessa on mainittu maatalous?

### IoTn määrittely

#### Principles & Paradigms

#### Industry 4.0

#### ETLAn IIoT-koosteesta

#### Muualta

International Telecommunication Union, “Overview of the Internet of things,” Ser. Y Glob. Inf. infrastructure, internet Protoc. Asp. next-generation networks - Fram. Funct. Archit. Model., p. 22, 2012.
[Y.2060 : Overview of the Internet of things](https://www.itu.int/rec/T-REC-Y.2060-201206-I) 21.4.2018

International Telecommunication Union:in (ITU) suosituksen Y.2060 Overview of the Internet of things määrittelyn mukaan *IoT* on globaali tietoyhteiskunnan infrastruktuuri, joka mahdollistaa edistyneitä palveluita yhdistämällä (interconnecting) sekä fyysisiä että virtuaalisia esineitä (things); perustuen tieto- ja viestintäteknologioihin jotka ovat yhteentoimivia ja voivat olla joko olemassaolevia tai vasta kehittyviä. 

Lisäksi määrittelyssä on huomautettu, että:
1. IoT voi tarjota palveluita kaikenlaisille sovelluksille käyttämällä hyväkseen esineiden tunnistamisen, tiedon tuottamisen (data capture) ja käsittelyn antamia mahdollisuuksia; samalla varmistaen että tietoturvan ja yksityisyyden suojan asettamat vaatimukset täyttyvät.
2. IoT voidaan laajemmasta näkökulmasta katsoen nähdä visiona, jolla on sekä teknologisia että yhteiskunnallisia vaikutuksia.

Samassa suosituksessa IoT:n kontekstissa *laitteen* määrittelyssä on laitteella vähintään kyky kommunikaatioon ja mahdollisesti kyky havainnointiin (sensing), toimintaan (actuation), tiedon tuottamiseen, tallentamiseen ja käsittelyyn (capture, storage, processing).

Suosituksen määrittelyyn *esine*eksi  IoT:n kontekstissa on merkitty vaatimukset esineen fyysisestä tai virtuaalisesta olemassaolosta, tunnistettavuudesta ja integroitavuudesta tietoverkkoihin.

Tämän suosituksen määrittelyyn perustuen IoT koostuu sekä *laitteista* että *esineistä*, jotka yhdessä olevat tunnistettavia, integroitavissa tietoverkkoihin joiden ylitse ne pystyvät kommunikoimaan ja mahdollisesti  havainnoimaan ympäristöään (sensing), toimimaan (actuation) sekä tiedon tuottamiseen, tallentamiseen ja käsittelyyn (capture, storage, processing).

### IoTn historia
### Industrial Internet of Things, teollinen esineiden internet
### Agricultural Internet of Things, maatalouden esineiden internet

Miten nämä IoT ja kasvintuotanto tulevat yhteen?
OMA MUTU, EI LÄHDETTÄ: IoT:n ja kasvintuotannon konvergenssi alkoi tapahtua teollisuusautomaation kehityksen myötä niin, että kasvihuoneiden automatiikassa voitiin ottaa käyttöön sensorien keräämän tiedon siirto tallennettavaksi. Tätä dataa voitiin sitten analysoida ja analyysien tuloksia ottaa käyttöön

#### Kirjallisuuskatsaukset

##### Talavera: Review of IoT applications in agro-industrial and environmental fields

@talaveraReviewIoTApplications2017

jakoivat kirjallisuuskatsausessa käsitellyt tutkimukset:
sovellusalueet, 
käyttöönottoon vaikuttavat esteet ja avoimet haasteet, 
ehdotus arkkitehtuurista (4 tasoa)
havaittu: heterogeenisiä komponentteja ja langattomia verkkoja
pohdinta: pitäisi saada pilveä ja yhteystapoja etujen saavuttamiseksi

AIoT:tä käytetään 
tarkkailu (monitoring) 62 %; 
kontrollointi (control) 25 %; 
logistiikka (logistics) 7 %; 
ennustus (prediction) 6 %.

AIoT:n teknologiat
(i) sensing variables, 
(ii) actuator devices, 
(iii) power sources, 
(iv) communication technologies, 
(v) edge computing technologies (Shi et al., 2016), 
(vi) storage strategies, and 
(vii) visualization strategies

AIoT:n omaksumisen/käyttöönoton esteet ja avoimet haasteet: 
Vahva standardisaatio
Parempi virranhallinta
Tieto- ja kyberturvallisuus
Modulaarisen laitteistojen ja ohjelmistojen kehittäminen
Yksikköhintojen alentaminen
Pyritään yhteensopivuuteen vanhan, olemassaolevan infrastruktuurin kanssa
Huomioidaan skaalautuvuus jo alkuvaiheessa
Ohjelmistokehityksen parhaiden käytänteiden käyttönotto
Kentälle/käyttöön asennettavien laitteiden lujatekoisuuden parantaminen
Käyttäjälähtöinen suunnittelu
IoT-ekosysteemin edistäminen
Kestävät käytänteet


##### Verdouw: Internet of Things in agriculture
@verdouwInternetThingsAgriculture2016a

Ruokaturva, 
väestönkasvu, 
elintason nousu, 
maan kantokyky ylitetty nykyisillä viljelymenetelmillä,
Globalisaatio, ilmastonmuutos, polttoaineperusteisesta taloudesta bioperustaiseen talouteen siirtyminen, maankäyttöön, makeaan veteen ja työvoimaan kohdistuva kilpailu monimutkaistaa haastetta maailman ruokkimiseen ilman suurempaa saastuttamista tai resurssien liikakäyttöä/liikaottoa.

IoT-laitteet voivat helpottaa haasteisiin vastaamista:
Tuotannon parempaa tarkkailua/havainnointia/monitorointia/sensorointia
Parempi ymmärrys maatilan olosuhteista
Edistyneempi ja etänä toteutettava kontrollointi
Ruoan laadun tarkkailu ja jäljitettävyys
Lisäämällä kuluttajatietoisuutta

IoT-määrittely:
IoT on seuraava Internetin vaihe, jossa myös fyysiset esineet (things) kommunikoivat.
“a world-wide network of interconnected objects uniquely addressable, based on standard communication protocols” **4**
aajentunut kohti maailmanlaajuista älylaitteiden verkkoa jossa laitteet ovat tilannetietoisia (context-sensitive) ja voidaan tunnistaa, tuntea (sense) ja kontrolloida etäisesti käyttäen sensoreita ja aktuaattoreita **6-8**.
IoT:ssä jokainen laite/esine on yksilöllisesti tunnistettavissa, varustettu sensoreilla ja kytketty reaaliaikaisesti internetiin.
IoT:n odotetaan olevan seuraava Internetin vallankumous.

IoT-arkkitehtuuri:
Fyysinen kerros
    Valmiudet fyysisten objektien automaattiseen tunnistukseen, havainnointiin, aktuointiin.
    RFID:tä on käytetty elintarvikeketjun jäljitettävyyden valvonnassa. Tutkimusten mukaan teknologian käyttöönotto on vielä vähäistä vaikka se on saanut suurta huomiota kirjallisuudessa.
    Lämpötilan, kosteuden, valon, hiilidioksidin, pH-arvojen anturointia.
    Älypuhelimilla voidaan tehdä muun muassa viivakoodien ja RFID:n lukemista, maatalouden sovelluksissa yleisimmin älypuhelinten käyttämät sensorit ovat GPS ja kamerat.
    Satelliittien, ilma-alusten, maahan pystytettyjen alustojen avulla tapahtuva kaukohavainnointi on ollut täsmäviljelyn tärkeä tutkimusaihe jo pitkään. Pienet miehittämättömät ilma-alukset (drone), ovat enenevissä määrin käytössä korkean resoluution paikka- ja aikatietojen kuvantamistiedon hankinnassa.
    Aktuaattoreita käytetään...

Verkkokerros
    Valmiudet verkottumiseen, verkkoyhteyksiin/liitettävyyteen, tiedonsiirtoon objektien informaation kommunikaatioon turvallisesti ja tehokkaasti.
    ...

Sovelluskerros
    ...


IoT:tä käsittelevät julkaisut:
Määrä selkeässä kasvussa,
Tieteellisissä julkaisuissa julkaistujen artikkeleiden määrä oli vuonna 2015 noussut aiemmasta, mutta samana vuonna kaikkien tieteellisten julkaisujen määrä oli vähentynyt. -> AIoT:n tutkimus voi olla kypsymässä.
Kirjojen luvuista ei yhtään maatalouden kirjasarjoissa.
Tieteellisissä julkaisuissa julkaistujen artikkeleiden joukossa oli sekä maatalouden että IT-alan julkaisuissa julkaistuja.
Aasialaiset dominoivat, erityisesti kiinalaiset.
Muilla mantereilla IoT on ollut muiden kuin maatalouden tutkimusaiheena.

Avoimet haasteet

Suurin osa tutkimuksista esittelee IoT-järjestelmäsuunnitelman tai raportoi IoT-implementoinneista prototyyppeinä tai pilotteina.
Paljon selvitystutkimuksia

AIoT:ä tutkitaan eniten (yhteensä 168):
68 Food supply chains
33 Arable farming
26 Agriculture in general
14 Greenhouse horticulture
8 Open air horticulture, including orchards
5 Food consumption
3 Leisure agriculture

Yleiset havaitut teemat:
Täsmäviljely sekä pelto- että puutarhaviljelyssä
Ruoan jäljitettävyyden järjestelmät
Ruoan turvallisuuden ja laaduntarkkailun järjestelmät
Kuluttajavuorovaikutus

*AIoT muut katsaukset ja vastaavat*
*AIoT tutkimukset, tieteelliset julkaisut -ovatko konferenssipaperit tieteellisiä julkaisuja?*
(*mahd. Harmaa kirjallisuus*)
*AIoT Järjestöt, organisaatiot esim. Luke ja IoF2020, ehkä FAO*
*AIoT Valmistajat, yhtiöt*
*AIoT muut julkaisut*


#### AIoT kasvintuotannossa
#### AIoT peltokasvituotannossa
#### AIoT puutarhatuotannossa (& muu kasvintuotanto)

Yleensä puutarhatuotannon ratkaisuita on helpompi kehittää ja ottaa käyttöön nojautuen teollisuudessa käytettyhin ratkaisuihin (haastattelut), koska ympäristö on yleensä tehdasmaisempi ja siellä voidaan tehdä kiinteitä laiteasennuksia toisin kuin peltokasvituotannossa.

# TUTKIMUS

Kuvaileva kirjallisuuskatsaus valittiin *metodin/tutkimusotteen?* mahdollistaessa:
1. Paitsi tieteellisten julkaisujen myös ammattilehtien, valmistajien omien julkaisujen ja muiden vastaavien aiheeseen liittyvien lähteiden käsittelyn.
2. Ilmiöihin liittyvien yhteyksien vapaan kuvailun ja haastatteluista saatujen tietojen kanssa dialogiin asettelun.

Koska opinnäytetyön tarkoituksena on tehdä laadullinen yleiskatsaus rajatulla työmäärällä,  yksilöteemahaastattelu valittiin menetelmän [?] mahdollistaessa:
1. Erilaisten informanttien haastattelun saman haastatteluprotokollan mukaan.
2. Kunkin informantin oman erityisosaamisen ja kokemusten käsittelyn.
3. Haastattelijan ja informantin keskinäisen yhteistyön ennen haastattelua sekä itse haastattelutilanteessa.

## MAHD. Kuvaileva kirjallisuuskatsaus
*Tarvitaanko tähän yleistä kuvailua kuvailevasta kirjallisuuskatsauksesta?*

## MAHD. Teemahaastattelu
*Tarvitaanko tähän yleistä kuvailua teemahaastatteluista?*

## Tutkimuksen tavoitteet
### Tutkimusongelmat

Tässä opinnäytetyössä tutkimusongelmana on jäsennellyn tiedon puute kasvintuotannon IoT-ratkaisuista. Tutkimusongelma pyritään ratkaisemaan etsimällä vastaukset tutkimuskysymyksiin. Vastauksia pyritään löytämään sekä kuvailevan kirjallisuuskatsauksen että teemahaastattelujen avulla.

### Tutkimuskysymykset

*tähän miten tutkimuskysymykset valittiin -teoriataustan perusteilla!*

Tutkimuksessa haetaan vastauksia kahteen *kolmeen* tutkimuskysymykseen, jotka alakysymyksineen ovat:

1. Millaista tutkimusta IoT-teknologioiden soveltamisesta kasvintuotantoon on julkaistu?

    1.1 Millaisia teknologiasovelluksia tutkimuksissa on esitelty? 

    1.2 Minkä tyyppiset sovellukset tulevat tutkimusmateriaalissa selkeimmin esille, eli millaisista sovelluksista ja teknologioista kirjoitetaan ja tehdään tutkimusta tällä hetkellä?

2. Miten kasvintuotannossa hyödynnetään IoT-teknologioita?

    2.1 Miten peltokasvituotannossa hyödynnetään IoT-teknologioita?

    2.2 Miten puutarhatuotannossa hyödynnetään IoT-teknologioita?

*Jos saadaan viljelijähaastis, mahd. tämä:*
3. Millaisia IoT-teknologioita haastateltavalla toimijalla on joko käytettävissään tai millaisista hän on tietoinen?
    * Mitä vaikutuksia niillä on tuotantoon ja/tai työntekoon?
    * Millaisia kokemuksia niistä haastateltavalla on?
    * Millaisia muita sovelluksia haastateltava tuntee tai tietää?
    * Millainen käsitys haastateltavalla on edelllä mainituista sovelluksista (sekä käyttämistään että tietämistään)?
    * Millaisia toiveita tai tarpeita haastateltavalla on IoT-teknologioille?

*Muut kysymykset? Vaikuttavuus, mitä tilanne kertoo ylipäänsä, jne.*
*Miten peltokasvituotannon ja puutarhatuotannon erot vaikuttavat IoT-teknologioiden sovelluksiin?*
 
*1. What are the main technological solutions of the Internet of Things in agro-industrial and environmental fields?*
*2. Which infrastructure and technology are using the main solutions of IoT in agro-industrial and environmental fields?*

#### Tutkimuskysymys, jos viljelijähaastis

III) Millaisia IoT-teknologioita haastateltavalla toimijalla on joko käytettävissään tai millaisista hän on tietoinen?

* Mitä vaikutuksia niillä on tuotantoon ja/tai työntekoon?
* Millaisia kokemuksia niistä haastateltavalla on?
* Millaisia muita sovelluksia haastateltava tuntee tai tietää?
* Millainen käsitys haastateltavalla on edelllä mainituista sovelluksista (sekä käyttämistään että tietämistään)?
* Millaisia toiveita tai tarpeita haastateltavalla on IoT-teknologioille?

### Työhypoteesit

*Tarvitaanko työhypoteeseja ollenkaan?*

Kirjallisuuskatsauksen tuloksissa voidaan kohdata hajanaisuutta sekä päällekkäisyyttä eri toimijoilta. Tämä perustuu aiheeseen tutustuttaessa (sekä aineiston alustavassa keruussa) tehtyihin yleisiin havaintoihin. Havaintojen mukaan aihe on vasta kypsymässä eikä yleisiä käytänteitä, standardeja jne. ole vielä päässyt muodostumaan.

Teemahaastattelujen tuloksissa ei todennäköisesti saavuteta --ainakaan kaikissa teemoissa-- selkeää saturaatiota, koska opinnäytetyön rajattu laajuus ei mahdollista kattavaa määrää asiantuntijoiden haastatteluja. Samasta syystä haastattelukierroksia voidaan toteuttaa vain yksi, jolloin kerättyä tietoa ei ehkä voi pitää kovin syvällisenä.

## Aineisto ja (tutkimus)menetelmät

### Tutkimusmenetelmät

Tämä on tutkimustyyppinen opinnäytetyö, jossa toteutetaan laadullinen tutkimus.
Laadullisen tutkimuksen tutkimusote valittiin kolmesta syystä: 1) tutkimusaiheesta ei löydetty merkittävää määrää tutkimusta työn alkuvaiheessa tutustuttaessa tutkittavaan ilmiöön, 2) kasvintuotannon ala on tekijälle tuntematon ja 3) työn alkuvaiheessa havaittiin, että kasvintuotannossa IoT-ratkaisuiden käyttöönotto on laajassa mittakaavassa alkuvaiheessa ja ala on tältä osin muutosvaiheessa. 
Käytettävät tutkimusmenetelmät ovat kuvaileva (narratiivinen) kirjallisuuskatsaus sekä teemahaastattelut.

Kirjallisuuskatsauksen ja teemahaastattelujen tuottamaa tietoa käsitellään sisällönanalyysin keinoin käyttäen myös narratiivisen tutkimuksen keinoja. *Tuleekohan tähän oikeasti sisältöanalyysiä?*

Teemahaastattelun tutkimusmenetelmää käytetään yhdessä kuvailevan kirjallisuuskatsauksen kanssa trianguloimaan tutkimusaihetta.

Aineiston keruumenetelmiä oli useita. Varsinaista tutkimustyötä edelsi ilmiöön tutustuminen erilaisia keruumenetelmiä testattaessa, keräämällä kontakteja, käyden asiantuntijakeskusteluja, vierailemalla alan tapahtumissa ja haastatteluja tehden. Varsinaisen tutkimustyön aluksi haettiin IoT:tä yleistasolla ja ilmiönä käsittelevää kirjallisuutta. Seuraavaksi käytettiin sateenvarjokatsausta, jolla haettiin ilmiötä käsitteleviä kirjallisuuskatsauksia. Valittujen kirjallisuuskatsausten pohjalta muotoiltiin omat hakumenetelmät ja valittiin osa lähteistä. Omien hakumenetelmien tuloksista on valittu tekijän harkinnan mukaan aihetta parhaiten kuvaavat. Lisäksi ollaan käytetty aiheeseen tutustuttaessa löydettyjä lähteitä jos ne ovat tekijän harkinnan mukaan olleet tähdellisiä aiheen käsittelylle ja ymmärryksen luomiselle.

Tutkimuksen luotettavuutta pyritään parantamaan käyttämällä aineistotriangulaatiota: kirjallisuuskatsauksen tuloksia vertaillaan haastattelujen tuloksiin sekä tuodaan esille ammattijulkaisuissa, laitevalmistajien sekä muiden toimijoiden tiedotteissa, lehtiartikkeleissa jne. ilmestyneitä asiaan liittyviä asioita.

Lisäksi tutkimuksen luotettavuutta pyritään parantamaan luettamalla haastatteluista tehdyt johtopäätökset muistiinpanoineen haastateltavalla.

Haastattelujen litteroinnissa käytetään yleiskielistä litterointia. Yleiskielistä litterointia tarkempaa sanatarkkaa litterointia on käytetty, jos sanojen poistamisella litteroinnista on arvioitu olevan tarkoitusta mahdollisesti muuttava vaikutus.

Tutkimuksen alustavassa vaiheessa ilmiöön tutustuttaessa tehtiin useita hakuja aiheeseen liittyvillä asiasanoilla, selattiin erilaisten organisaatioiden ja julkaisujen verkkosivuja, haettiin asiantuntijakontakteja eri tapahtumista jne. Löydöt merkittiin muistiin mahdollista myöhempää käyttöä varten.

Haastateltavia etsittiin tapahtumista saatujen kontaktien, aineistosta löytyneiden asiantuntijoiden ja omien verkostojen kautta.  Lisäksi käytettiin "snowballing" -menetelmää, jossa keskusteluissa informanttia pyydettiin suosittelemaan muita asiantuntijoita haastateltaviksi tai muutoin kontaktoitaviksi.

#### Opinnäytetyön/tutkimuksen vaiheet

Tähän kuvaus millaisin vaihein edettiin.
Esim.
    Aiheen valinta
    Tutkimussuunnitelma
    Teoriatieto
    Tutkimuskysymysten määrittäminen
    Alkuperäistutkimusten haku
    Alkuperäistutkimusten valinta ja arviointi
    Alkuperäistutkimusten analysointi eli tutkimustulokset



### Kirjallisuuskatsaus

#### Kirjallisuuskatsauksen vaiheet

Tähän kuvaus millaisin vaihein edettiin.
Esim.
    Aiheen valinta
    Tutkimussuunnitelma
    Teoriatieto
    Tutkimuskysymysten määrittäminen
    Alkuperäistutkimusten haku
    Alkuperäistutkimusten valinta ja arviointi
    Alkuperäistutkimusten analysointi eli tutkimustulokset

##### Aiheeseen tutustumisen osa (?)

##### Systemaattisempi osa

Käytetty hieman erilaisia hakulauseita eri kantoihin niiden vaatimusten ja toimintojen mukaan.

*Tähän Talaveran katsauksesta + hakuliitteestä metodia*

Aikaisemman vaiheen tuloksista valittiin joukko keskeisimmiksi arvioituja asiasanoja. Nämä asiasanat yhdistettiin löydettyjen kirjallisuuskatsausten tutkimusmenetel

*Tuloksena kohtuullinen määrä tieteellisiä lähteitä.*
Lähteiden joukosta on valittu aihetta käsittelevät kirjallisuuskatsaukset, joita käytetään sateenvarjokatsauksen omaisesti. Tällä pyritään varmistamaan, että kirjallisuudessa selkeästi havaitut teemat/asiat tulevat huomioiduksi myös tässä työssä sekä alkuperäistutkimusten hakumenetelmät ja käsitteet/asiasanat ovat laadukkaita ja aiheelle sopivia.

Kirjallisuuskatsausten käyttämät tietokannat:
    Talaveran: Google Scholar, IEEE, Scopus
    Kamilaris: IEEE, ScienceDirect, Web of Science, Google Scholar
    Verdouw: Scopus, Google Scholar 
    "*We searched in the Scopus database for papers that on the one hand include Internet of Things or IoT in the title and on the other hand agriculture, farming or food in the title, abstract or the keywords section. In addition, we used generic references on IoT and enabling technologies by using Google scholar especially searching for review articles that provide an overview of the application of specific enabling technologies in the agricultural domain.*"

Löydettyjä kirjallisuuskatsauksia käytetään seuraavasti:
Tiedon kattavuutta pyritään parantamaan hakemalla sateenvarjokatsauksen omaisesti aihetta käsitteleviä kirjallisuuskatsauksia. Hakutuloksista valituista kirjallisuuskatsauksista käydään läpi tutkimusmenetelmät joista löytyviä hakumenetelmiä käytetään hyväksi soveltuvin osin tämän työn seuraavissa tiedonhakuvaiheessa.

##### Keskeisten käsitteiden valinta

(##### Tutkimussuunnitelma ja tutkimuskysymysten määrittäminen?)

##### Alkuperäistutkimusten haku

##### Alkuperäistutkimusten valinta

##### Alkuperäistutkimusten laadun arviointi

##### Alkuperäistutkimusten analysointi ja tutkimustulosten esittäminen

##### Kirjallisuuskatsauksen luotettavuus


### Teemahaastattelut

*teemahaastattelujen kuvaus, haastattelukysymysten valinta, haastateltavien valinta, haastattelujen toteutus*


 
Teemahaastatteluja tulisi yleisesti tehdä syvällisemmän tiedon hankkimiseksi useita kierroksia, mutta opinnäytetyön rajatun työmäärän ja ajan puitteissa päädyttiin tekemään vain yksi haastattelukierros mahdollisimman monen eri keskeisiä tahoja/sidosryhmiä edustavien informanttien kanssa.

Haastatteluissa saatavia tietoja verrattiin työn edetessä kirjallisuuteen sekä muihin lähteisiin pyrittäessä varmistamaan tietojen oikeellisuus ja [todellisuusvastaavuus/korrelaatio?]. Samalla tietoja käytettiin osaltaan uusien lähteiden hankintaan sekä käsitteiden keräämiseen pyrittäessä parantamaan kirjallisuuskatsauksen kattavuutta ja [oikeisiin asioihin ja ilmiöihin keskittymistä?].




# TUTKIMUSTULOKSET

## Kirjallisuuskatsauksen tulokset



## Haastattelujen tulokset

### Haastattelujen teemat

#### Haastateltavan kuvailu AIoT:n ja maatalouden yleistilanteesta (1 2 3 4 5) 1634

##### H1

H1.1 Maatalouden kenttä on hyvin hajanainen ja pirstaleinen. Teknologioita otetaan käyttöön yksittäin, tapaus tapaukselta, eikä viljelyprosessien digitalisointi toimi samalla tavoin kuin teollisuuden prosessien kanssa. On hyvin vaikeaa tehdä kattavia yksittäisiä ratkaisuja jonka voisi ostaa kerralla ja joka kattaisi koko viljelyprosessin.

H1.2 Maatilat ovat yksittäistapauksia: tuotantosuunniltaan, tilakooltaan, henkilöstöltään, historialtaan, teknologiatasoltaan, teknologiaorientoitumiseltaan hyvin erilaisia. Kentällä on otettu digitaalisia työkaluja käyttöön hyvin vaihtelevasti. Osa viljelijöistä aktiivisesti etsii ja ottaa käyttöön uusia teknogioita toimintansa tehostamiseksi, osa taas ei ottaisi niitä käyttöön vaikka niitä tarjottaisiin valmiina ratkaisuina.

H1.3 Kotieläintuotannossa on jo laajasti käytössä pitkälle automatisoituja tehdasmaisia laitoksia, koska niiden tapauksessa ollaan voitu soveltaa olemassaolevan teollisuusautomatiikan ratkaisuja. Kasvihuoneet ovat myös samankaltaisia tehdasmaisia laitoksia, joihin automatiikan ja tietoverkkojen asennus ja käyttö on ollut verrattain helppoa. Tosin teollisuusautomaatiota on tässä tapauksessa jouduttu muokkaamaan käyttäjäystävällisemmäksi, jotta viljelijä voi hallita järjestelmää omalla osaamisellaan eikä hänellä tarvitse olla käyttöinsinöörin taitoja. 

H1.4 Automatiikan näkökulmasta kasvihuoneet ovat luonteeltaan samankaltaisia kuin monet teollisuuden tuotantolaitokset. Ne ovat kiinteitä rakennelmia joihin on helppo asentaa sähkö- ja tietoverkkoja sekä erilaisia sensoreita ja toimilaitteita ja tämä on yksi syy siihen, että lähiverkkotekniikalla toimivaa kasvihuoneautomatiikkaa on ollut käytössä jo pitkään.
Suomessa on pitkälle tutkittu suljettuja kasvihuoneita, jotka ovat myös hyvin pitkälle automatisoituja ja monikerrosviljelyratkaisuita. (Monikerrosviljelyllä tarkoitetaan useissa päällekkäisissä tasoissa tapahtuvaa viljelyä, mikä eroaa tavallisen kasvihuoneen yhdessä tasossa tapahtuvasta viljelystä.) Nämä ratkaisut voidaan rinnastaa tehdasautomaatioon ja useat monikerrosviljelyratkaisut perustuvat teollisuusautomaation ratkaisuihin.
Tällaisissa monikerrosviljelyratkaisuissa on yleensä teollisuusautomaatio muokattu viljelijän tarpeisiin ja niin helppokäyttöiseksi, että viljelijän oma asiantuntemus riittää sen käyttöön. Tällöin käyttäjä ei tarvitse käyttöinsinöörin osaamista järjestelmää käyttääkseen, vaikka lähtökohtana ollut automaatiojärjestelmä sitä vaatisi.
Samoin kuin muussa teollisuusautomaatiossa, nämä monikerrosviljelyjärjestelmät voivat (yleensä) havaita itse siinä ilmeneviä vikoja ja lähettää huoltokutsuja tarvittaessa. Tällä samalla periaatteella toimivat myös lypsyrobotit, jotka lähettävät havaintodataa robotin tilasta sen valmistajalle. Tällöin valmistajat käyttävät keräämäänsä dataa pääasiassa oman tuotekehittelynsä apuna, mutta tarjoavat myös käyttäjälle etätukea tarvittaessa.

H1.5 On tärkeää huomata, että tehdasmaisessa toimintaympäristössä yksi toimija on voinut valmistaa kattavan kokonaisratkaisun tai 2-3 toimijaa ovat voineet muodostaa pienen ekosysteemin, joiden tuotteet muodostavat keskenään vastaavan kokonaisratkaisun. Tämänkaltaisen ratkaisun ei tarvitse olla yhteensopiva tai toimia minkään muun toimittajan järjestelmien kanssa, mikä tekee kehitystyöstä paljon helpompaa.

H1.10 Täsmäviljelyssä pyritään asettamaan jokaiseen pellon neliöön vain sen tarvitsema panos eikä yhtään enempää, jolloin suurilla peltopinta-aloilla toimittaessa voidaan täsmäviljelyn vaatiman järjestelmähankinnan hankintakustannukset kattaa jo kolmessa vuodessa saavutettavilla lannoitesäästöillä. Tämä on tullut mahdolliseksi tarvittavien teknologioiden leviämisen ja hintojen alenemisen myötä, jolloin niistä on tullut ns. perusteknologiaa.

H1.11 Pienillä peltopinta-aloilla toimittaessa tulee täsmäviljelyn vaatima lisäinvestointi koneiden hinnassa kattaa työn tehostamisella. Työtehoa saadaan yleensä lisättyä työkoneiden automaattiohjauksella ja telemetriatoimintojen avulla toimivan ennakoivan huollon sekä vikadiagnostiikan avulla. Telemetriapalveluista saadaan myös analytiikan avulla tietoa paitsi koneiden myös tuotantoprosessien tilasta, jolloin toimintaa voidaan optimoida parempien tulosten saavuttaamiseksi. Tällaisia etuja on aikaisemmin saatu vain full-liner -järjestelmien avulla, mutta nyt vastaavia tietoja tuottavia järjestelmiä on tullut markkinoille myös full-liner -ratkaisuiden ulkopuolelle. Oman työn tehostumisen lisäksi säästöjä voidaan saavuttaa myös tehokkaammalla urakoitsijoiden käytöllä, kun töiden ohjeistaminen tehdään digitaalisesti esimerkiksi työtiedostoilla. 

H1.12 Pienillä tiloilla voidaan toteuttaa täsmäviljelyä viljelijän oman hiljaisen tiedon avulla ilman täsmäviljelyssä käytettäviä tietojärjestelmiä, mutta tehtäviä ulkoistettaessa täsmäviljelyn vaatimien ohjeiden määrä on suuri. Työkoneiden ja prosessien datan keräämisellä ja pilvipalveluun tallentamisella viljelijän omaa hiljaista tietoa voidaan hyödyntää myös urakoitsijan hoitaessa töitä.

H1.29 Tilojen määrän vähentyessä jäljelle jäävistä yhä suurempi osa tekee liiketoimintaa enemmän tosissaan, mikä voi alentaa uusien asioiden käyttöönoton kynnystä. Toisaalta suomalaiset viljelijät ovat tehneet investointeja hyvin harkiten ja välttämällä suuria kertainvestointeja. Samalla viljelijät ovat pyrkineet keskittämään hankintansa todistetusti toimivaan tekniikkaan ja sovittamaan toimintansa kulloinkin vallitseviin suhdanteisiin. ...

H1.33 ... Historiallisesti ollaan toteutettu täsmäviljelyä jo hevosaikaan talikolla ja hiljaisella tiedolla, vähäisin panoksin. Tehostumisen ja nyt pinta-alaperustaisen EU-tuen myötä maatilojen koon on pakko ollut kasvaa, yhden ihmisen tulee voida käsitellä yhä suurempi peltopinta-ala samassa aikaikkunassa kuin aiemmin. Tämä on tarkoittanut, että koneiden koko on suurentunut, lohkoista on tehty suurempia, lohkoja on käsitelty samoilla tasasäädöillä, jolloin ollaan menetetty tuntuma ja täsmä viljelystä. "Nyt otetaan takaisin sitä tarkkuutta, mitä talikolla levitettäessä aikanaan toteutettiin."

H1.36 Peltoviljelyssä ei tehdasmainen automaatioteknologioiden sovellus onnistu, toisin kuin kasvihuonetuotannossa. Kasvihuonetuotannossa voidaan soveltaa suoraan tehdasautomaatiota jo konseptitasolla.


##### H2

H2.5 Peltokasvintuotannon tavoitetila mihin pyritään on monien teknisten rajoitteiden takana. Dataa pystytään keräämään suuria määriä, mutta sen siirtämiseen ei ole infrastuktuuria.
Oman ymmärrykseni mukaan reaaliaikainen järjestelmien välinen (pellolta kerätyn) datan siirto ei suuren datamäärän takia vielä ole teknisesti mahdollista.
Nopeat tietoliikenneyhteydet edistäisivän näiden järjestelmien tuotekehitystä.
Tällä hetkellä keskitytään eri tahojen eri tarkoituksiin keräämien tietojen yhdistämiseen, tiedolliseen käyttämiseen ja jakamiseen eri toimijoiden kesken.

H2.6 ... Ollaan siirtymässä koko ajan lähemmäs kokonaisvaltaista tilanhallintajärjestelmää ja
Agritechnica -messuilla esiteltiin MyYara -viljelijäportaaliohjelmisto, jossa on esim. Saksan markkinoihin räätälöity viljelysuunnitteluohjelma, johon voi syöttää N-sensor-kartat ja N-tester-lukemat. ...

H2.30 Voin kuvitella, että tilakokojen kasvaessa ja tilojen määrän pienentyessä maanviljelystä tulee enemmän liiketoimintamaisempaa ja kustannusrakenteitakin lasketaan tarkemmin.


##### H3

H3.1 Hyvin sekava yleistilanne. Keskuskoneista tilakohtaisiin PC-mikroihin ja nyt takaisin verkkoon, samoin kuin yleisissä sovelluksissa.

H3.2 Uusi tilanne on, että laitteet ovat liittymässä tilan tuotantokoneisiin, mistä kerätään tuotantotietoa ja laitteita ohjataan kerätyn tiedon perusteella.
Verkottuminen on alussa mutta selkeä suunta.

H3.3 Laitteisiin on tulossa enemmän anturointia ja verkkoliikenne toimii muutoin kuin SMS-viesteillä.

H3.4 Tällä hetkellä käytössä olevat laitteet osaavat puhua toisilleen hyvin vähän.
Tätä tarkoitusta varten ei ole oikeastaan muita standardeja kuin ISOBUS.
Muitten kuin ISOBUS-standardia käyttävien laitteiden käytössä on ratkaisuja, jotka ovat sovelmia muista standardeista eivätkä ne ratkaisut ole millään tavalla toimialan de facto -standardeja.
Järjestelmien välisessä tiedonsiirrossa on käytössä jäsentymättömiä Comma Separated Value (CSV) -pohjaisia ratkaisuita.

H3.5 Nämä CSV-pohjaiset ratkaisut ovat joko laitevalmistajien itse kehittämiä ratkaisuita tai yleiseen käyttöön otettuja tapoja toimia, joita ei ole suunniteltu yleiseen käyttöön. Osa niistä on muodostunut ilman tuottamusta, ikään kuin tahattomasti toimijoiden omaksuessa ratkaisuita ottamatta huomioon ratkaisuiden elinkaarta.
Esimerkkinä peltoviljelyn maanäytetiedostojen tiedostoformaatti, jota käytetään tiedostojen siirrossa kentältä laboratorioon. Tiedostoformaatti kehitettiin joskus 80- ja 90-lukujen taitteessa ja oli tarkoitettu vain tietyn organisaation sisäiseen käytöön. Se on kuitenkin jäänyt alan standardiksi, vaikka sitä ei ole määritelty missään eikä kukaan ole kirjoittanut sitä auki.

H3.6 Toinen esimerkki on viljavuuspalvelun siirtotiedostoformaatti, jonka kehittäjät kuolivat kaikki samassa onnettomuudessa, eikä kehitystä enää saatu yhden tahon johdon alle.

H3.20 Myytävinä tuotteina maatalouden IoT-ratkaisuita on aika vähän. Tällä hetkellä kentällä on käytössä ratkaisuita, joissa saattaa olla joitain varsinaisten IoT-ratkaisuiden piirteitä ja toiminnallisuuksia.
Viljelysuunnittelun teko pellolla toimii PC-ohjelmana, mihin on kokeellisesti liitetty omia sääasemia mutta ei muita laitteita.
Traktoreiden automaatioteknologia tietokoneineen (vaihteisto-, moottori-, nostolaite-, ajotietokone) on integroitu itse traktoriin niin tiukasti, ettei käyttäjä edes huomaa käyttävänsä useita verkotettuja tietokoneita traktoria käyttäessään.

H3.21 Valtran huollon sovellus, jolla huolto voi havainnoida traktoreita ja tarvittaessa antaa etätukea ja ohjata kentällä olevia huollon työntekijöitä, on kyllä IoT-ratkaisu.
Meneillään olevasta IoT-buumista huolimatta sellaisia laitteita, jotka olisi alunperin suunniteltu IoT-laitteiksi joilla on oma nettiosoite, josta voidaan kerätä dataa ja jonka toimintaan voidaan vaikuttaa *verkon yli*, on aika vähän.
Laitteiden välillä liikkuu kyllä dataa, mutta muutenkin kuin IP-verkon kautta kuten muistilaitteilla siirrettynä paikasta toiseen.

H3.22 Olen itse lähestynyt IoT-asioita lähinnä laitelähtöisesti, ns. rautatasolla. Pidän IoT-laitteen ominaisuuksina sen tietoisuutta sen tietoverkkoon kytkeytymistä sekä sen kykyä lähettää ja vastaanottaa viestejä tietoverkkon yli.
Hyvin yksinkertainen esimerkki voisi olla lämpötilaa mittaava laite, johon voidaan viitata IP-osoitteella ja saada laitteesta vastauksena tiedon sen olemassaolosta, toiminnallisuudesta ja mittauslukemia.

H3.23 Tällä hetkellä on käytössä paljon lämpötila-antureita, mutta niistä laitteista saadaan ulos *jänniteviesti*/volttiviesti ja ne laitteet eivät voi viestiä verkon yli ja sitä voisin pitää jonkinlaisena rajana.
Sovelluksen voi rakentaa alemman layerin/*tason* päälle.
Johtamisen mielessä laitteeseen ja sen toimintaan pitää pystyä vaikuttamaan.
Sovellus voi käyttää yhtä tai useampaa IoT-laitetta, joista se voi tallentaa tietoa *ja*/tai lähettää ohjeita toteutettaviksi.

H3.24 Tällaiset laitteet ovat vielä harvassa, mutta niiden yleistymistä odotetaan tapahtuvaksi lähiaikoina.
Esimerkiksi navetan ilmastointilaitteen tilasta olisi hyödyllistä sekä saada tieto että sen toimintaan vaikuttaa verkon ylitse. Samoin ruokintalaitteen toimintaan olisi hyödyllistä voida vaikuttaa sekä sen tilaa ja toimintaa tarkkailla.
Viljakuivurin toimintaa olisi erityisen hyödyllista voida hallita etäisesti, koska sen käyttösesonki on lyhyt *mutta viljelijälle kiireinen*.

H3.25 Viljakuivureissa on sovellettu automatiikkaa 70-luvulta lähtien. Alkuun toiminnallisuus on ollut relepohjaista ja säädettävät anturit ovat ohjanneet automatiikan toimintaa.
Tällä hetkellä suurimmassa osassa viljakuivureiden automatiikoissa käytetään ohjelmoitavaa logiikkaa, mutta anturointi voi olla vielä voltti/jänniteviesteillä havaintoja välittävää johtojen päässä olevaa tekniikkaa, eikä IoT-tekniikkaa jossa tieto liikkuisi verkon yli. *?*

H3.26 Maatalousautomaatiossa on tällä hetkellä aika monissa laitteissa käytössä SMS-viestit, joiden avulla ollaan helposti saatu laite kommunikoimaan käyttäjille laitteen tilasta.

H3.27 Jokaisella laitteella on käytännössä tällöin oma liittymä.
Maatilalla navetassa voi helposti olla 10 eri valmistajien laitetta, joilla on jokaisella oma liittymä ja SIM-kortti, esimerkiksi ilmanvaihdolle on oma, palohälyttimelle oma, ruokinta-automaatille oma, lypsyrobotille oma, toiselle lypsyrobotille toinen jne.
Liittymien kuukausimaksujen ollessa 10 € kuukaudessa näiden laitteiden vuosikustannukset muodostuvat viljelijälle jo huomattaviksi, erityisesti verrattaessa yksittäisten SMS-viestien hintaa IP-verkossa liikkuvien viestien hintaan.
IP-verkossa hinta on käytännössä vain verkon rakentamisen kertakustannus, kun käytössä ei ole datamäärään perustuvaa veloitusta.


##### H4

H4.1 Maatalouden IoT:ssä ja digitalisaatiossa on tällä hetkellä jo valmiina useita kokonaisuuden osia ("leegopalikoita") joita voidaan ottaa käyttöön ja riippuen maatalouden osa-alueesta jossain määrin on otettu käyttöön.
*Osat ovat vielä erillään.*
"Vapaa, avoin, järjestelmien välinen yhteistyö ja dataintegraatio on vielä vaikeaa."

H4.2 Verrattuna tilanteeseen neljä vuotta sitten, nyt saadaan enemmän kytkettyä laitteita vapaasti toisiinsa.
On suuria ongelmia saada kiinteät laitteet, liikkuvat työkoneet, viljelysuunnitteluohjelmistot, sensorijärjestelmät ja ulkopuolisten tahojen tarjoamat datalähde tai -analyysipalvelut toimimaan yhdessä, jakamaan dataa ja tietoa niin, että sitä pystyisi helposti käyttämään maatilan toiminnan parantamisessa.

*ks. H4.3 teemassa "Ihmisen/käyttäjän rooli..."*

H4.4 Viljelijän toiminnan luonteen muuttumiseen tulee kiinnittää huomiota. Rooli peltotöiden suorittajasta on muuttumassa "manageriksi" ja tilan toiminnan hallinnoijaksi.
Tällöin viljelijä on aika kaukana itse pellosta ja pellolla vallitsevasta tilanteesta robotin suorittaessa peltotyön viljelijän puolesta. Tämä vaikuttaa pitemmällä tähtäimellä viljelijän ammattitaitoon ja lyhyellä aikavälillä viljelijän tilannetietoisuuteen pelloilla vallitsevasta tilanteesta.

*kehityksen aste voisi olla oma teemansa?*
H4.5 ISOBUS-standardi on ratkaissut pitkälle työkoneiden yhteenliitettävyyden ongelman ja nyt kehityskulku on menossa kohti seuraavaa vaihetta, missä työkoneet liitetään osaksi jotain isompaa järjestelmää.
Esimerkiksi Agrineuvoksen kehittämällä ratkaisulla saadaan Valtran traktorit kiinni Agrismart-järjestelmään. Agrismart-järjestelmän avulla traktorin tuottama data siirtyy automaattisesti viljelysuunnittelujärjestelmään ja toisin päin.

H4.17 *kasvitehtaat, kasvihuone-IoT*
Kasvihuonetuotannon ja kasvitehtaiden IoT-ratkaisuiden kehitys käy kuumana, mutta itse odotan muita kuin salaatin kasvatusta.


##### H5

H5.1 *yleiskuva, tilanne*
Maatalouden IoT-ratkaisuissa ollaan murroksen partaalla, jossa analogisista hevosvoimia tuottavista laitteista ollaan siirtymässä digitaalisiin *tietoa tuottaviin ja käsitteleviin* laitteisiin.
Asiakkailla on halu ymmärtää laitteiden toimintaa ja oppia käyttämään niitä.
Asiakkaat haluavat ymmärtää miten heidän omaa toimintaansa voidaan parantaa, miten nykyisestä peltopinta-alasta pystyttäisi hankkimaan enemmän, tehokkaammin, pienemmillä kustannuksilla ollen ensimmäisinä toimijoina uudella markkina-alueella.
Puhutaan kahdesta eri tavasta: 
1. Miten laitteen tuottamaa dataa voitaisiin hyödyntää, miten maanviljelystä on tehty sekä miten laitteita on käytetty.
2. Farm Management Software (FMS) missä voidaan päättelemällä miten toimintaa/prosesseja voitaisiin parantaa.
Eli miten tehdään enemmän tai miten tehdään tehokkaammin lopputuotetta. Nämä lähestymistavat ovat selkeästi esillä.
Maanviljelytoimintaan ollaan vaatimassa samankaltaista toiminnallisuutta kuin muualla on yleistynyt, kuten mobiilikäyttöliittymät, appit, sosiaalinen verkostoituminen laitteiden avulla/kautta. 
Uusiin vaatimuksiin ovat voimakkaasti panostamassa AGCO, Valtra-Fendt, Massey Ferguson, Challenger. Toiminnan digitalisaatioon, telemetriaan, Farm Managementiin, laitteiden käytön projekteja on yhtä aikaa menossa. Nämä osa-alueet edustavat uuden aallon huippua ja niiden on katsottu olevan tärkeitä.

H5.2 *pirstaleinen kenttä, täsmäviljelyn viipyminen, kehitysarvio*
AGCOn osalta Valtra on lähdössä kaupallistamaan ensimmäistä telemetria- ja IoT-ratkaisua, mikä on saanut todella hyvän vastaanoton. Asiakkaat ovat vaatimassa tätä ratkaisua käyttöönsä ja asiakkaiden arvioiden mukaan tämä ratkaisu ei ole vain hyödyllinen lisä vaan toiminnalle vastaisuudessa ehdottoman tarpeellinen.
Asiakkaiden havaittua telemetriaratkaisun hyödyt sellainen halutaan kaikkiin laitteisiin.
Viljelijälle pyritään tuottamaan ikään kuin sihteeri olkapäälle muistuttamaan tarvittavista toimenpiteistä, koska maanviljelijän työssä tulee ymmärtää biologiaa/kasvitiedettä, koneiden huoltoa ja operointia, meteorologiaa, liiketoimintaa jne. ja kaikkiin näihin liittyviä toimintoja tulee hallita päivittäisessä työskentelyssä, jolloin on tarvetta kaikille helpottaville ratkaisuille. Paitsi, että näillä ratkaisuillamme viljelijän työtä voidaan helpottaa, voimme AGCOna, laite- ja ratkaisutoimittajana päästä lähemmäs viljelijää partnerina jolloin voimme myös tehdä parempaa ja asiakaslähtöisempää tuotekehitystä. *IoT-teknologiaratkaisuilla voidaan tehdä tuotekehitystä myös datan perusteella, asiakaspalautteen ja oman työn lisäksi.*
IoT-ympäristön kehittymisestä on hyötyä koko maataloudelle, samoin kuin siitä on molemminpuolinen hyöty sekä meille että asiakkaillemme.

H5.3 *haasteena laiteintegraatio (?), farm mngmnt, päätöksenteon apu, datan perusteella*
... Tällä hetkellä ollaan murroskohdassa ja vasta harjoittelemassa ensimmäisten IoT-ratkaisuiden käyttöä maanviljejyksen alalla, jolloin laitteet ovat keskenään erilaisia *(epäyhteensopivia)* ja esimerkiksi telemetriatuotteet ovat selkeästi eri kategoriassa kuin FMS-tuotteet *eivätkä keskustele keskenään*. ...

H5.15 *mikä on omasta mielestäsi tärkeintä, entä mihin olet itse tutustunut/kohdannut*
Oman näkemykseni mukaan asiakkaiden tekemä harppaus digitaaliseen toimintaympäristöön ja siitä saadut kokemukset/palaute on tärkein osa tätä kokonaisuutta. Käyttöönotosta ja käytöstä saatujen kokemusten ja asiakaspalautteen pohjalta voidaan ohjata valmistajan omaa kehitystyötä oikeaan suuntaan. 
Maanviljelijöiden digitalisaatioharppaus etenee pienillä askelilla kunkin viljejijän oman harkinnan ja oman toiminnan yksilöllisten tarpeiden mukaisesti.
Tämä voi alkaa esimerkiksi yhden telemetriatuotteen käyttöönotolla josta he lähevät laajentamaan digitaalisten teknologioiden käyttöä omassa toiminnassaan. Samalla he kasvattavat omaa osaamistaan ja havaitsevat uusien teknologioiden hyötyjä ja millaisia etuja ne tarjoavat *juuri heille*.
...
Sitä mukaa kun markkinoille tuotetaan uusia IoT-ratkaisuita valmistajat oppivat miten asiakkaat haluavat niitä käyttää.
Asiakas- ja käyttäjälähtöisellä kehittämisellä voidaan päästä nyt nousevan ensimmäisen digitalisaation aallonharjan ylitse. 
Tämän aallonharjan ylitse pääsyn vaatimien ponnistelujen jälkeen voidaan jatkaa kehittämistä saatujen kokemusten ja näkemysten viitoittamaan suuntaan.

#### Holistinen FMS (3 5) 827

##### H1

H1.6 Järjestelmän hankkineen käyttäjän on aikaisemmin ollut vaikeaa saada tietoa omistamansa järjestelmän tuottamasta datasta, samoin tuotetun datan saanti omaa analyysiä varten on ollut vaikeaa. Jokin aika sitten oli käyttäjälle yleisesti mahdollista saada vain joitain valmistajan ennalta määrittelemiä graafeja, mutta nyt on enenevissä määrin tullut mahdolliseksi ladata tietoja esimerkiksi Excel-formaateissa. Yleisesti ollaan vielä kaukana siitä, että käyttäjä voisi saada järjestelmiensä tuottamaa dataa haluamassaan formaatissa tai ladata sitä itselleen suoraan rajapinnasta vaikka itselleen räätälöityyn järjestelmään. Samoin ollaa kaukana siitä, että käyttäjä pystyisi määräämään, että hänen omistamansa järjestelmän tuottama data siirrettäisiin vaikka kilpailijan vastaavaan järjestelmään. Tällä hetkellä järjestelmistä saadaan lähinnä monitorointitietoa tuotantotoiminnan tehostamista ja vahinkojen välttämistä varten, mitkä ovat järjestelmien yleisimmät hankintaperusteet ja myyntiargumentit. Käyttäjät ovat kuitenkin edelleen yhden toimittajan loukussa. Tämä on teollisuusautomaatiossa ollut täysin käypä ratkaisumalli koska yksi toimittaja tai vain muutaman toimittajan yhteenliittymä on voinut tuottaa kokonaisvaltaisen järjestelmäratkaisun, jonka avulla asiakas on voinut hallita koko tuotantoprosessinsa.

H1.7 Pääasiallinen ongelma peltoviljelyssä on, että yksittäinen toimija ei pysty toteuttamaan kokonaisvaltaista järjestelmää jolla peltoviljelyn toimintaympäristöä voitaisiin hallita. Peltoviljelylle tyypillisessä hajanaisessa käyttöympäristössä on käytössä eri valmistajien hyvin erilaisia ja pitkälle erikoistuneita laitteita. Tämän takia kokonaisvaltaisia peltoviljelyn järjestelmäratkaisuita on tuotettu niin sanottuihin full-liner -käyttöympäristöihin, joissa kaikki maatilan traktorit implementteineen/työkoneineen, puimurit ja muut koneet ja laitteet ovat saman valmistajan tuotteita. Tällaisen järjestelmän hankkineen viljelijän toiminta tapahtuu kokonaisuudessaan yhden valmistajan suljetussa ympäristössä, missä valmistaja on voinut varmistaa laitteiden yhteensopivuuden ja datan liikkuvuuden. Näin voidaan mahdollistaa viljelyprosessien kehittäminen ja sen myötä tehokkas täsmäviljely.

H1.20 Suomessa ei vielä ole peltoviljelyn alalla olemassa tuotantojärjestelmiä, joilla voitaisiin sensoreilla tuotettua ja pilveen kerättyä dataa analysoida ja sen perusteella vaikuttaa automaattisesti viljelyprosessien toimintaan. Minulla ei nyt ole tietoa, löytyisikö vastaavaa kansainvälisiltä markkinoilta. Tehdasautomaatiossa ja sitä hyödyntävissä kotieläintuotannon laitoksissa tämä saattaa jo olla mahdollista. Keinoälyn kehittyessä voitaisiin saada käyttöön järjestelmiä, jotka datasta suoraan päätelmiä tekevä AI voisi ohjata automaation toteuttamia toimenpiteitä. Toinen mahdollinen toimintamalli olisi ehdottaa käyttäjälle toimenpiteitä, jotka sitten annetaan automaation suoritettaviksi.
H1.22 Tällä hetkellä saatavilla järjestelmissä on älyä mukana, mutta ne rajoittuvat pienempiin operatiivisiin asioihin kuten työsyvyyden säätöön automaattisesti, pellolla havaittujen esteiden automaattiseen väistämiseen ja Yaran N-sensor:in kaltaiseen lannoittimen ohjaamiseen sensoridatan perusteella.

H1.24 Perusautomatiikka on siis jo olemassa mutta systeemiautomaation eteen on tehtävä vielä paljon töitä, jotta sitä voitaisiin käyttää keinoälyn kanssa työn ohjaamiseen ja ylemmän tason päätöksenteon avuksi tehtyyn analytiikkaan.


##### H2

H2.7 Ollaan kehittämässä ja hakemassa rajapintoja järjestelmien välille. Yara tekee yhteistyötä 365FarmNet:in kanssa [https://www.365farmnet.com/en/] ja Yaran laitteilla tuotettua dataa voidaan käsitellä heidän järjestelmissään.


##### H3

H3.8 Kokonaisvaltaisia Farm Equipment Systemeitä, joilla voidaan hallita kaikkia maatilan laitteita, on olemassa, mutta ne ovat kehityskaarensa ensimmäisellä neljänneksellä.
Agritechnica-messuilla oli jo useita yrityksiä, jotka pyrkivät tuomaan yhteen eri järjestelmien tietoja.
Peltoviljelyn järjestelmien yhdistävä tekijä messuilla olleissa järjestelmissä oli ISOBUS-järjestelmän käyttö pohjalla.
Integraatiota tekeviä yrityksiä on jo olemassa. Messuilla niitä ei aikaisemmin ollut, mutta nyt pelkästään integraatioratkaisuihin erikoistuneita yrityksiä oli useita.

H3.9 Nämä olivat ilmeisesti pitkällä kehityksessä ja niihin oli investoitu huomattavasti. Näiden järjestelmien myyntiin oli messuilla panostettu selkeästi, mistä voi päätellä että näihin ratkaisuihin ja markkinaan ollaan panostamassa tosissaan.


##### H4

H4.6 Integraatio on ollut *tähän asti ja luultavasti vastakin* paljon syvempää suurilla ns. full-liner laitetuottajilla, joilta voi hankkia kaikki toiminnassa käytettävät työkoneet, laitteet, ohjelmistot ja palvelut.
Ongelmana on, että vain harvoilla tiloilla on kaikki laitteisto samalta tuottajalta. Lisäksi siinä tapauksessa ollaan pahasti käytössä olevan merkin ja tuoteperheen talutusnuorassa.


##### H5

H5.3 *haasteena laiteintegraatio (?), farm mngmnt, päätöksenteon apu, datan perusteella*
Ollaan vääjäämättä menossa siihen, että FMS tulee antamaan suosituksia helpottamaan viljelijän *toimintaa ja* päätöksentekoa. Järjestelmät voivat laskea *johtopäätöksiä* monen muuttuvan tekijän perusteella ja datan perusteella ymmärtää miten viljejijän työtä voidaan helpottaa sekä millaisilla toimilla saadaan paras tulos juuri kyseisessä toimintaympäristössä.
FMS, laitteista kerätty data ja muu tieto tulevat varmasti yhdistymään ja niitä tullaan käyttämään yhdessä.
... Mutta ollaan jo siinä tilanteessa, että laitteilta saadaan tieto FMSlle missä ne ovat liikkuneet, polttoaineenkulutus jne. jolloin holistisesta järjestelmästä voitaisiin saada yleisnäkymä maatilan toiminnasta.

H5.9 *"ei kannata täsmäviljely", visiona järjestelmä työtapojen välittämiseen urakoitsijalle*
Ei ole minkäänlaista tietoa siitä, milloin sellainen holistinen järjestelmä voisi tulla käyttöön.
Voi olla, että tulevaisuudessa viljejijöiden käyttämä järjestelmä on kolmen tai neljän järjestelmän kokonaisuus, missä yhdistyvät halutut toiminnallisuudet.
IoT- ja telemetriaratkaisut yleistyvät hyvin nopealla tahdilla, samaan aikaan FMS-ratkaisut yleistyvät, täsmäviljelyratkaisut (ISOBUS) etenevät, näitä voi valita tarpeen mukaan.
Näitä kaikkia yhdistävää holistista järjestelmää ei tietääkseni ole kukaan tällä hetkellä markkinoilla oleva toimija rakentamassa.
Agrirouter ja erään suomalaisen toimijan ratkaisu pyrkivät yhdistämään dataa ja tekemään datan liikuttelun mahdolliseksi. Tässä on omat haasteensa ratkaistavana ennen kuin kaikkia näitä (?) tietoja pystyy yhdistelemään keskenään. *Tietoja? Jos ag.router yhdistää dataa, niin mistä tiedoista tässä on kyse?*
Jotta järjestelmä, joka on keskittynyt laitteiden telemetriadatan keräämiseen, voisi toimia johonkin muuhun keskittyneen järjestelmän kanssa, tulisi molempiin järjestelmiin kehittää samoja ominaisuuksia, jolloin kolmas osapuoli voisi tehdä käyttöliittymän jolla molempien järjestelmien tietoja voitaisiin analysoida.
Tämäkään ei ole vielä asiakaskohtaista *vaan yleinen tarpeeksi suurelle osalle tarpeeksi vähän huonosti sopiva*. Asiakkaan pitäisi voida määrittää mitä tietoja hän haluaa nähdä.
Ollaan siis vielä kaukana holistisesta järjestelmästä, johon kaikki osajärjestelmät olisivat yhteydessä.
Epäilen, että viljelijälle voi olla haasteellista kerätä tietoa useista järjestelmistä ja yhdistellä niitä kokonaiskuvan hahmottamiseksi. FMS-järjestelmät tulevat varmaan olemaan lähimpänä kokonaiskuvan tuottavaa tietojen esittämistä. *Tämä vaikuttaa vain yhden maatilan tilannetiedolta, mutta miten osana ruokaketjua ja globaalia ruokamarkkinaa?*

#### Datan omistajuus ja saatavuus (1 2 3 4 5) 344

##### H2

H2.12 Yarassa emme ole viljelijöiden kanssa toimiessamme ole kohdanneet kysymystä datan omistajuudesta. Asiakas omistaa tuottamansa datan ja käyttää sitä omiin tarkoituksiinsa, emmekä ole keränneet asiakkaiden dataa.

H2.13 On jo tapauksia, joissa joku toimija -laitevalmistajan lisäksi- haluaa määritellä miten laitteiden tuottamaa dataa käsitellään ja mihin järjestelmiin sitä siirretään.
Suurin osa toimijoista jotka pyrkivät hyödyntämään datan siirreltävyyttä eivät ole viljelijöitä, vaan yhteistyömahdollisuuksia hakevia järjestelmätoimittajia.
Nämä järjestelmätoimittajat ovat ohjelmistotaloja, jotka kehittävät FMS-järjestelmiä ja pyrkivät käyttämään satelliitti- tai NDVI-kuvantamispalveluita. Heille on eduksi mitä useamman järjestelmän kanssa heidän tuotteensa on yhteensopiva ja mitä enemmän heidän tuotteensa pystyy integroimaan itseensä, joko linkittämällä *rajapinnan kautta(?)* tai ilman *(?)*.
On myös yksittäisiä viljelijöitä , jotka käyttävät FMS-ratkaisuita ja jotka pohtivat voisiko dataa liikutella tai tuoda sitä jotenkin käytettäväksi eri järjestelmien välille.


##### H4

H4.9 Kun viljelysuunnitteluohjelmat siirtyvät yhä enemmän paikallisista ohjelmista pilvipalveluihin viljejijän toiminnassaan tuottaman datan omistajuudesta ei aina ole varmuutta.
En tiedä onko suomessa yleisessä käytössä olevasta Wisu-sovelluksesta enää edes saatavilla paikallista versiota.
Olen ymmärtänyt että kaikki merkittävät suomalaiset viljelysuunnitteluohjelmat ovat menossa kohti pilvimallia, jota käytetään verkkoselaimen tai vastaavan sovelluksen läpi. Tällöin datan omistajuuden kysymyksestä tulee yhä merkittävämmäksi.
Aikaisemmin käyttäjän omalle koneelle tallentannettu tieto oli täysin käyttäjän omassa hallinnassa, mutta palveluntarjoajan tietojärjestelmään tallennettuun tietoon käyttäjällä on vain pääsy. ...


##### H5

H5.4 *oman datan käsittely, rajapinnat, yleiskäyttöinen järjestelmä*
AGCO datan käsittelijänä tarjoaa asiakkaalle käyttöliittymän.
Käyttöliittymän avulla voidaan datasta jalostaa raportteja ja analyyseja.
Ilman käyttöliittymää datan hyödynnettävyys on nolla.
Asiakas omistaa kaiken datan, mitä järjestelmämme käsittelee.
Yksityisyyden suoja ja GDPR on otettu todella tarkasti huomioon.
Asiakas voi halutessaan ottaa datansa vaikka Exceliin itse käsiteltäväksi, mutta meidän käyttöliittymämme tarjoaa paremmat mahdollisuudet tiedon analysointiin niin pitkällä kuin lyhyellä aikavälillä sekä tietojen vertailuun.
En usko, että kellään maanviljelijällä olisi aikaa kehittää omaa analytiikkaa tuottamastaan datasta jos suinkin on saatavilla käyttöliittymä, josta tarvittavat asiat näkee helposti. Lisäksi käyttöliittymä voi ohjata käyttäjää tunnistamaan toiminnassaan olevat pullonkaulat ja näin ohjata viljelijää keskittämään resursseja toimenpiteisiin, joista on hänen omalle toiminnalleen suurimmat hyödyt.
Nykyään ihminen ei yksinkertaisesti halua rakentaa omaa analytiikkaa eikä siihen olisi aikaakaan.
IoT-ratkaisuiden tulisi tukea datan analytiikkaa/toiminnan kehittämistä/?, niiden tulisi olla helppokäyttöisiä ja tarvittava tieto tulisi tulla esille silloin kuin sitä tarvitaan.

#### Datan jakamisen ja välittämisen alustajärjestelmät, mahdollisuudet jne. 468

    - datan kerääminen erilaisista datalähteistä (2 5) ja järjestelmistä
    - työtiedostojen vienti urakoitsijoille (1 2)
    - dataa yhteisöllisesti jakavat palvelut/alustat (1 3 4 5)
    - datavirtoja ja dataa jakavia järjestelmiä/alustoja (1)

##### H1

H1.16 Toivoisin, että myös Suomeen tulisi käyttöön Farmobile:n [https://www.farmobile.com] kaltainen järjestelmä, jossa viljelijät voisivat varastoida ja halutessaan jakaa tai myydä toiminnastaan saatua dataa koska tilojen kannattavuus ja kilpailukyky eivät ole sitä luokkaa mitä ne voisivat olla. Toinen vastaava palvelu on Farmer's Business Network [https://www.farmersbusinessnetwork.com] jossa käyttäjä voi verkostoitua, jakaa täsmäviljelyn reseptejä, vertailla analyysidataa jne. Sosiaalisesta mediasta löytyy kyllä ryhmiä vinkkien ja tietojen vaihtoon, mutta datojen jakoon ei ole palvelua, eikä datoja ole sillä tavalla käyttäjien omassa hallinnassa että niitä voisi oman halunsa mukaan jakaa kenelle haluaa.

H1.27 Sekä Farmobile että Farmer's Business Network kilpailuttavat tuotantopanoksia kuten lannoitteita ja kasvinsuojeluaineita viljelijöiden puolesta yhteishankintana, tuoden useiden yksittäisten viljelijöiden hankinnat yhteen. Mtech Digital Solutions Oy [https://www.mtech.fi/fi], entinen Suomen Maatalouden Laskentakeskus Oy soveltaa samankaltaista toimintamallia FarmiDiili-palvelussaan [https://www.mtech.fi/fi/farmidiili].


##### H2

H2.41 Tällä hetkellä tiedossani ei ole järjestelmää, joka toimisi viljelijöiden tai muiden toimijoiden datasettien vertailun alustana ja osto- ja myyntikanavana. Visiona tämä on kuitenkin mahdollinen. ...


##### H3

H3.12 Keski-Euroopassa ja USAssa tehdään usein kevään täydennyslannoitus satelliittikuvien perusteella.
Suomessa sateliittikuvia käytetään vähemmän.
Kevään typpilannoituksen kohdentamisesta pyritään tekemään päätös satelliittikuvien perusteella. Vaikka kasvu ei ole vielä lähtenyt käyntiin niin ne voidaan kuitenkin jo kuvata.
Yleensä myydään palveluna, jossa kuvasta analysoimalla muodostetaan toimenpide.
Yara ja Kemira ovat yrittäneet tuottaa lentämällä otetuista kuvista vastaavaa palvelua, mutta ongelma on vasteaika, joka Suomessa pitäisi saada muutaman päivän pituiseksi nopeasti lumen sulamisen jäljeen alkavan kasvukauden takia. Keski-Euroopassa vastaava aika on muutamia viikkoja, jolloin ehditään hyvin odottaa hyvää pilvetöntä säätä sateliittikuvausta varten.

H3.17 Minulla ei ole tiedossa, että kaupallisena tuotteena olisi olemassa palvelua, jossa voisi jakaa tai omatoimisesti analysoida kasvintuotannossa/maataloudessa tuotettavaa dataa. Visioita tällaisesta palvelusta olen kyllä lukenut.

H3.18 Pohdittaessa datan myyntiä tällaisen palvelun/alustan kautta kannattaa arvioida, kuka olisi siitä valmis maksamaan.
Viljelijällä on usein sopimukseen kirjattu velvollisuus antaa viljelyyn liittyvä data mukaan. Tällöin datalla ei saa lisää hintaa vaan sen luovuttaminen on velvollisuus.
Ei ole selkeää kenelle myytävä data olisi tarpeellista ja miten tämä data voisi tuottaa taloudellista lisäarvoa niin, että sen ostaminen olisi perusteltua. Näiden puuttuessa ei ole muodostunut talousmekanismeja datan markkinoille.


##### H4

H4.12 *rajapinnat, oman datasetin jako, vertailu* 
Tiedän viljelijöitä, jotka jakavat kaiken viljelytoiminnassaan syntyneen datan johonkin palveluun, mutta he ovat yksittäistapauksia. 
Viljelytoiminnassa syntynytta dataa ei mitenkään systemaattisesti käytetä hyväksi.

H4.14 *sertifikaattien tarkkailu* 
Sovelluksena sertifikaattien tarkkailu voisi olla lähempänä toteutumista kuin kuluttajalle vietävä tuotantotieto.
Teollisuuden sisällä tieto voisi liikkua ja laatusertifikaatin toteutumisen valvonta jatkuvaa.
Kuluttajalle laadun viestiminen olisi helppoa.
Monet sertifikaatit ovat tällä hetkellä aika kömpelöitä, esimerkiksi päätös luomutuotannosta tulee tehdä ennen tuotantoa, koska byrokratia on raskas. Luomutuotantoa tarkkaillaan sitten tilan omalla kirjanpidolla ja pistokokeilla. Luomun tuottamiseksi voisi olla ketterämpi vaihtoehto siinä, että viljelijä havaitsee, ettei tänä kesänä tarvitsekaan ruiskuttaa kasvinsuojeluaineita ja jatkuvasti toimintaa seuraavilla laitteilla voitaisiin luomun vaatimusten toteutuminen näyttää toteen.
Datalähtöisellä sertifioinnilla voitaisiin saada erilaisten laatumerkkien toiminta joustavammiksi.


##### H5

H5.5 *tiedon vertaisjakoa, onko siihen järjestelmää kehitteillä*
Meneillään olevassa agrirouter -hankkeessa/projektissa pyritään yhdistämään erilaiset toimijat, FMSit, IoT-toiminnot, telemetriatoimittajat, ISOBUS-koneet sellaiseen muotoon missä asiakas saisi suurimman hyödyn. Agrirouteria ollaan edistämässä globaaliksi ratkaisuksi.

#### Tiedon liikkuminen tuotantoketjussa (mahd. kuluttajalle asti) 569

    - tuottajien ja kuluttajien yhteys (1)
    - dataperustainen hinnoittelu (1)
    - laatusertifikaattien valvonta (4)
    - tietoa kuluttajalle asti (4 5)

##### H1

H1.13 Kuluttajalle asti näkyvä tuotantoketju mahdollistuisi jos olisi standardit joiden mukaisesti datavirtaa käsiteltäisiin. Samalla mahdollistuisi tehokas tiedon jako ja verkostomainen toiminta erilaisten toimijoiden kesken, toisin kuin kahden toimijan välisissä järjestelyissä, missä kaksi toimijaa sopii miten dataa jaetaan ja ratkaisu on heille räätälöity. Tällainen kahdenvälinen sopiminen on hyvin hidasta ja tehotonta verkostotoimintaa. Tehokkaan verkostomaisen toiminnan edellyttyksenä olevat standardit ovat vasta kehitteillä. Näkemykseni mukaan kentällä on edelläjkävijöinä toimijoita, jotka soveltavat uusia toimintamalleja käytäntöön ja määrittelevät kehitettävien standardien toimintaa. Standardeja kehitetään liiketoiminnan lähtökohdista ja liiketoiminnan yhteyteen tarkoituksena kehittää toimintaa entistä kustannustehokkaammaksi ja sujuvammin toimivaksi.

H1.17 Prosesseista kerätyn datasta kertyyy tuotantotapatieto, joka voi käsittää mitä kylvetään, mihin paikkaan, mihin kellonaikaan, sääolosuhteet jne. Lisäksi sadonkorjuusta saadaan tieto mistä kohtaa peltoa sato on korjattu ja korjattuun satoon voidaan lisätä tunnistetieto ja tuotantotapatiedot. Tällöin voidaan laskea korjatulle erälle hiilijalanjälki, lisätä tieto miten, millaisia ja jos kasvisuojeluaineita on käytetty ja lopuksi myydä se omana arvoeränä. Osa tuotannosta voitaisiin edelleen myydä bulkkituotantona kuin ennenkin, mutta osalle sadosta voitaisiin tavoitella parmpaa hintaa.
H1.18 Ongelmaksi näin toimittaessa voi tulla paitsi logistiikka erän käsittelyssä sekä miten viljelijä voi löytää pienelle erikoistuneelle erälle ostajan. Jos viljelijät voisivat verkostoitua sopivan palvelun kautta, vertailla  tuottamiensa erien tietoja ja myydä samankaltaiset erät yhdistämällä ne suuremmaksi eräksi. Tällöin markkinoilta voitaisiin etsiä ostaja suuremmalle erälle, joka voisi olla koottu vaikka koko Suomen tai pohjoismaiden alueelta. Samalla tavalla ostajat voisivat verkostoitua palvelujen kautta hankkimaan yhdessä sovittujen määritelmien mukaisia eriä. Mutta tällaisia palveluita ei vielä ole saatavilla. 

H1.42 Viljelijät ovat nähneet tärkeäksi suoran yhteyden kuluttajiin. Lähiruoalla on kysyntää, samoin tiedolle ruoan alkuperästä ja tuotantomenetelmistä. Ruokaketju on suppilomainen, digitalisaation avulla voitaisiin kehittää keskusteluyhteyksiä *ja tiedonsiirtoa*.
On visioitu ja digitaalisia yhteiskehittämisalustoja kuten VTT:n Owela, missä viljelijät voivat kehittää toimintaansa suorassa vuorovaikutuksessa kuluttajien kanssa. Tämän avulla voidaan myös lisätä kuluttajien tietoisuutta tuotteiden kulurakenteesta ja siitä, millainen osa hinnasta päätyy viljelijälle. Kuluttajat voivat vaikuttaa ruokaketjun tasa-arvoisuuteen valinnoillaan.

H1.43 Tiedonvälityksen kanavia voisi käyttää myös viestimään millaisia lannoitteita ja kasvinsuojeluaineita, millaista työtä siihen on tehty. Tämä olisi oikeaa dataa eikä vain mielikuvia.
Vielä ei ole dataa. Voi olla hankalaa tuottaa kuluttajille ymmärrystä lannoituksesta lasketuille indikaattoreille, kun lannoitteiden käytöstä kuluttajilla yleensä ei ole ymmärrystä.
Pitäisi pystyä selkeään kommunikointiin indikaattoreilla missä tuote on hyvä ja missä ei.
Hinnoittelun pitäisi myös perustua dataan: laadulle laadun mukainen hinta.

H1.44 IoT-teknologian avulla voitaisiin mahdollistaa joustava mitattuun laatuun perustuva hinnoittelu. Jos data olisi jaossa, viljelijän prosessi voitaisiin viestiä tuotteeseen. Tällöin viljelijää ja hänen toimintaansa ei itse tarvitsisi tuntea, vaan sen saisi näkyville.


##### H3

H3.19 Datan ensisijainen tarvitsija on viljelijä itse, joka sen avulla pystyisi parantamaan päätöksentekoa omassa viljelyprosessissaan. 
Datan toissijainen tarvitsija on arvo-/tuotanto/ruokaketju, joka tarvitsee tuotantoinformaation pystyäkseen todistamaan tuotteen alkuperän ja tuotantoprosessin oikeellisuuden.

H3.41 Tuotantoketjun mittaroinnissa pyritään usein ympäristöystävällisempään ja/tai tehokkaampaan toimintaan. Tulee ottaa huomioon kokonaisuus eikä keskittyä vain tietyn mittarin seuraamiseen. 



##### H4

H4.13 *kuluttajalle asti näkyvä tuotantodata* 
Käytännössä kuluttajien toteutuva datan tutkinta voi jäädä vähäiseksi.
Suuren yleisön kiinnostus lähiruokaa ja REKO-ruokarinkejä kohtaan on hiipunut ja tämä sovellus voi olla samankaltainen ilmiö, joka toteutuessaan jäisi jonkin ajan kuluessa pienen harrastajapiirin käyttöön.
Jotta kuluttajat yleensä jaksaisivat tarkastella tuotantotietoa, tulisi se näyttää heille täysin vaivattomasti vaikka lisätyn todellisuuden avulla ja todennäköisesti Google Glass:in tapaisen laitteen avulla. Kännykän kaivaminen esille tiedon etsintää varten vaikuttaa liian vaivalloiselta.
Älypuhelinsovelluksena tälläinen voitaisiin toteuttaa, mutta universaalia sovellusta voi olla vaikea kehittää useiden eri toimijoiden kuten S- ja K-ryhmän sovellusten kilpaillessa keskenään. Vielä pirstaleisemmaksi tilanne menisi, jos sovellukset olisivat tuottajakohtaisia.
Itse arvioisin, että passiivinen kuluttaja voisi jaksaa lukea tuotteen pakkauksesta tiedot millä tilalla se on tuotettu, kuinka pitkä matka sitä kaikkiaan on kuljetettu, kokonaishiilijalanjälki, hiilidioksidijalanjälki ja vesijalanjälki.


#### Maatalouden alan laitevalmistajien välinen yhteistoiminta 694

    - eri valmistajien laitteet yhdessä (2 4)
    - standardien käyttöönoton levinneisyys (2)
    - laitevalmistajien asennemuutos (2) ja yhteistyö/kilpailu (1 3 5)

##### H1

H1.8 Full-liner -järjestelmät ovat hyvin kalliita investointeja joihin on varaa vain hyvin suurilla maatiloilla, minkä takia kokonaisvaltaisia peltoviljelyn järjestelmiä on käytössä harvoilla toimijoilla. Lisäksi full-liner -ratkaisut eivät sovi kaikkien käyttöön, esimerkiksi John Deeren valikoimassa ei ole kylvölannoitinta jota käytetään pohjoismaissa. Tällöin pohjoismaiset viljelijät eivät pysty toimimaan John Deeren full-liner -ratkaisun puitteissa, vaan joutuvat hankkimaan käyttöönsä myös muiden valmistajien työkoneita kuten kylvölannoittimen.

H1.13 Useiden eri valmistajien työkoneiden yhteistoiminnan varmistamiseksi on kehitetty ISOBUS-standardi, jonka kehittämistä AEF johtaa erilaisissa työryhmissä. Standardi takaa laitteiden käytännössä muiden standardin mukaisten laitteiden kanssa, mutta siirto työkoneen CAN-väylästä pilvipalveluun tai maatilan datavarastoihin on vielä työn alla. Voi vaikuttaa siltä, että maatalous olisi jäljessä muihin teollisuudenaloihin verrattuna mutta tämä johtuu osin alan pirstaleisuudesta ja ISOBUS-standardin kehittämisessä ollaan pitkään jouduttu keskittymään traktorien ja työkoneiden väliseen kommunikointiin.

H1.14 Koska maataloudessa toimintaympäristö on niin hajanainen, mikään yksittäinen toimija ei ole halunnut tehdä suurinvestointeja oman standardinsa kehittämiseen ja riskeerata niin suurta tappiota kilpailutilanteessa muiden toimijoiden kanssa. Kilpailun sijaan on päädytty lähtökohtaisesti kehittämään toimintaympäristön standardeja yhdessä ja jakaen kehitystyön kustannukset. 10 vuotta sitten uskottiin suljettujen järjestelmien luovan kilpailuetua ja lisäävän liiketoimintaa. Nyt toimijat ovat havainneet kentän olevan niin hajanainen, että liiketoiminta on mahdollista vain kun toimitaan avoimesti. Avoimesti kehitetty mahdollisimman toimiva standardi on näkemykseni mukaan tekninen alusta, jota kehittää ekosysteemi erilaisia toimijoita. Sitten kun standardin tekniset ongelmat on ratkottu ja pullonkaulat avattu sen ympärille kehittyy sitä hyödyntävä liiketoiminan ekosysteemi.

H1.15 Valmistajat voivat standardien mukaan toimiessaan rakentaa omia edistyneempiä tai erikoistuneempia ominaisuuksia, jotka toimivat heidän laitteissaan heidän määrittelemissä puitteissa, esimerkiksi tietyn merkin traktorin kanssa voidaan saman merkin työkoneesta saada käyttöön enemmän kuin jos työkonetta käytettäisiin toisen valmistajan traktorin kanssa. Käyttökohteita ja -tarpeita on niin suuri kirjo, että toiminnallisuuksia pitääkin räätälöidä ja näiden erikoistoimintojen sisällöllä voidaan erottua kilpailijoista. Kilpailussa ollaan siirtymässä yhä enemmän koneen fyysisistä ominaisuuksista palveluiden ominaisuuksiin ja siihen, millaista lisäarvoa käyttäjälle tulee palvelun tuottaman tiedon avulla. Avointen standardien avulla valmistajat, jotka eivät voi tarjota full-liner -ratkaisua, voivat tarjota samankaltaista lisäarvoa koneidensa hankkineille käyttäjille kuin suuret fill-liner:eiden valmistajat. Tällöin valmistajat voivat keskittyä tekemään parhaan mahdollisen koneen, joka on avoimien standardien avulla yhteensopiva modernien automaatio - ja pilvijärjestelmien kanssa ja jolle voidaan tällöin luvata full-liner:eiden kokonaisjärjestelmien edut. Esimerkiksi kylvökoneen arvolupaus on suurempi, jos se toimii osana urakoitsijan konevalikoimaa tai yrittäjien keskinäistä ketjua. Yksittäinen kylvökone voi tehdä mekaaniset toimintonsa hyvin, mutta se on vain se yksittäinen kylvökone ja sen arvolupaus rajoittuu siihen itseensä. Ollessaan kytketty suurempaan kokonaisuuteen kylvökone voi tuottaa enemmän liiketoimintaa, arvoa ja tuottoa.

H1.30 Avoimet standardit mahdollistavat liiketoimintalähtöisen valinnan investointien ajankohdalle, olosuhteiden otollisuuden mukaisesti.
Digitaalisaation ja IoT:n myötä on mahdollista nähdä liiketoiminta uudesta näkökulmasta, niiden mahdollistaessa uusia vaihtoehtoja.
Verkottuminen voi tuoda kilpailuttamiseen neuvotteluvoimaa.
Tällä hetkellä ollaan siirtymässä ruutupaperilta dataan. Seuraavaksi viljelijöiden tulisi saada tuottamansa data omiin käsiinsä ja palvelut, jotka mahdollistaisivat tiedon vaihdannan, analytiikan, vertailut ja yhteisen liiketoiminnan. Tämä toimisi lähtökohtana markkinaperusteisille investointipäätöksille.

H1.31 Uusia standardiperusteisia teknologioita voidaan ottaa käyttöön asteittain pienissä paloissa. Standardien kuten ISOBUS etu on, että niitä on kehitetty pitkään ja maatalouden teollisuus on niihin sitoutunut.
Voi tulla teknologioita, jolla asiat voi tehdä helpommin kuin CAN-väylää käyttäen, mutta omaksuminen tapahtuu hitaasti. *Laitteiden myyminen käyttöön on hidasta, koska käyttöikä on pitkä, yhteensopivuus pitäisi olla, investoinnin pitäisi oikeasti tuottaa paremmin juuri sillä tilalla ja tilat ovat valtavan erilaisia.* Tällä hetkellä tutkitaan standardisoinnissa teollista ethernettiä CAN-väylän sijaan. Jos uudet standardit tulevat käyttämään sitä, tulisi sen silti olla yhteensopiva ja käyttökelpoinen vanhojen laitteiden kanssa, esim. 30 vuotta vanha traktori.

H1.32 Standardien mukaiset laitteet ovat tietoturvallisempia teollisuuden kehittäessä myös sitä.
Teollisuus ymmärtää, että asiakkaat loppuvat jos tietoturvasta ei pidetä huolta.
Kun standardiin on sitoutunut koko teollisuus ja sitä on kehitetty 20-30 vuotta, niin myös viljelijät voivat siihen sitoutua *ja investoida standardin mukaiseen koneeseen*


##### H4

H4.7 Luultavasti merkittävin yritys avoimien tiedonkäsittelystandardien kehittämiseksi ja ns. vendor lockin välttämiseksi on AEF:n yritys saada tänä vuonna ISOBUS-standardilla kytketyt koneet yhdistettyä viljelysuunnitteluohjelmistoihin. Tästä integraatiosta on tulossa osa ISOBUS-standardia ja sitä valmistelemassa on 4 tai 5 keskieurooppalaista ohjelmistosuunnittelun yritystä. Suomalaisista toimijoista ainakin Agrineuvoksen kehittäjät ovat seuraamassa integraation kehittämistä. Luulen, että he seuraavat tilannetta ja kun standardista tulee riittävän stabiili he tekevät päätöksiä missä määrin ottavat standardin käyttöön omassa toiminnassaan.


##### H5

H5.10 *valmistajien konsortiotyö, ISOBUS*
Laite/työkone/traktorivalmistajien välisellä yhteistyöllä on tavoitteena esimerkiksi ISOBUS-standardin kehitystyössä *(oma, huono sanavalinta)* rakentaa toimintaympäristö *(tai ekosysteemi?)* jossa voidaan rakentaa digitaalisia ratkaisuita ja teknologiasovelluksia.
Etenemisen tilanteesta tai suunnitellusta aikataulusta ei minulla ole tietoa.

#### AIoT-teknologioiden vaikutukset (3) 927

    - tuotannon lisäarvon mahdollisuudet (1?)
    - käyttöönoton motiivit (1)
    - työmäärän vähentäminen (2)
    - arvoerillä lisäarvoa tuotannolle (1)
    - hiljaisen tiedon välittäminen ja taitojen korvaaminen teknologialla (1)
    - kannattavuudesta ei tietoa (4)

##### H1

H1.28 Pienet suomalaiset maatilat hyvin todennäköisesti hyötyisivät Farmobile:n ja Farmer's Business Network:in kaltaisista palveluista, koska tuotannon kannattavuutta voidaan parantaa juuri arvon tunnistamisella. Viljelijä voisi parantaa tuotteensa arvon tunnistamista kilpailuttamalla ostajia. Tähän asti monet maatilat ovat myyneet tuotteensa aina samalle toimijalle kuten Hankkijalle ilman kilpailutusta, eikä viljamarkkina ole ehkä halunnutkaan etsiä parasta hintaa. Jos viljelijät osaisivat tunnistaa laatuerät, niin näille erille voitaisiin kilpailuttamalla saada parempi hinta ja näin parantaa tuotannon kannattavuutta. Tämä parantaisi myös viljelijän asemaa myyntineuvotteluissa, sillä vaikka viljan laatujärjestelmiä on olemassa niin mittauksen ja laatuluokituksen tekee ostaja.

H1.45 Ongelmana on, että laatueriäkin myydään bulkkina ja suora yhteys kuluttajien ja viljelijöiden välillä tervehdyttäisi tilannetta. 
Virtuaalimarkkinat mahdollistaisivat vaikka pop-up -laatuerän markkinoille tuottamisen. 
Eikä suppilo voisi enää sanella ehtoja, kun vaihtoehtoisiakin reittejä olisi laatutavaran myymiselle parempaan hintaan. 
Silloin keskuskaupatkin joutuisivat kilpailemaan laatutavaran saannista. Tämä tervehdyttäisi kuvion.

H1.46 Tämä ei kuitenkaan saa vaarantaa elintarvikejärjestelmien turvallisuutta.
10-15 % tilojen tuotosta voisi olla oikeasti kilpailutettavaa laadukasta tuotantoa. Siitä viljelijät voisivat saada paremman tuoton.

H1.48 "Näen, että digitaalisuus tuo uusia liiketoimitamahdollisuuksia, jotta maatilat olisivat oikeasti kilpailukykyisiä ja kannattavia. Kannattavampia kuin tänä päivänä. Se olisi kaikin puolin tärkeätä."

H1.49 IoT-teknologioiden, digitalisaation, tietoon perustuvalla maanviljelyllä voidaan vastata joustavammin haasteisiin. "Pystytään reagoimaan kun on tietoa. Jos ei ole tietoa, ei voida reagoida."


##### H2

H2.16 Esimerkiksi teknologian käyttöönotosta Yaran N-sensorin avulla saadaan Saksassa 6 % suurempia satoja ja samalla säästöjä panoksissa, Ruotsissa saman lukeman ollessa 4 %. ...

H2.26 Sadonlisää on saatavissa, prosenttiluvut ovat lohkokohtaisia ja riippuvat lohkon sisäisistä vaihteluista, lannoitusstrategiasta. ...

H2.27 Sadonlisän lisäksi on mahdollista saavuttaa lannoitesäästöjä. ...

H2.38 Urakointina voidaan ulkoistaa täsmäviljelytyöt, jotka on aikaisemmin pitänyt tehdä oman hiljaisen tiedon varassa mutta jotka on uudella teknologialla saatu dokumentoitua ja tallennettua urakoitsijalle annettavaan työtiedostoon. ... Useamman vuoden historiatietoja voidaan myös vertailla ja pyrkiä selvittämään kasvuun liittyviä ongelmia, vaikka miksi juuri tuo kohta pellossa tuottaa aina huonoa satoa tai on muuten ongelmainen.


##### H4

H4.8 Maanviljelyn digitalisaation ja IoT-ratkaisujen tarjoamien hyötyjen/etujen tuomasta kannattavuudesta on vaikea sanoa mitään ja se on pitkään ollut ongelmana: yleisesti nähdään, että teknologiaratkaisuilla on paljon potentiaalia mutta mukaan lähtemisen riskit ovat olemassa ja siihen vaadittaisiin kohtuullisia investointeja.
Uuden teknologian integroiminen *omaan toimintaan* vaatii sekä rahaa että aikaa, varsinkin jos samalla konekantaa joudutaan uusimaan ja/tai ottamaan käyttöön uusia ohjelmistoja. 
Koska suomalaisten viljelijöihen taloudellinen tila ei tällä hetkellä ole mitenkään erityisen hyvä, eritysesti subscription-lisenssimallin ohjelmistojen käyttöönoton kynnys on aika korkea.

H5.15 *erilliset arvoerät*
Erillisten arvoerien tuottaminen voisi olla mahdollista, mutta vaatisi toiminta- ja ajattelutavoissa huomattavia muutoksia niin viljelijöillä, elintarvikevalvonnassa kuin elintarviketeollisuudessakin.
Tietenkin voisi olla *näiden teknologioiden avulla* yksittäiselle vijelijälle mahdollista näyttää toteen asiakkaalleen että tuotteet on viljelty tietyillä tavoilla ekologisesti, terveellisesti jne.
Laajempi käyttöönotto ja omaksuminen vaatii vähintään aikaa eikä välttämättä sittenkään ota tuulta purjeisiinsa, vaikka kyseinen innovaatio olisi kuinka edistyksellinen ja tarjoaisi huomattavia etuja. Vaikka teknologia on mahdollistaja, lopulta käyttöön jäävän ratkaisun valikoitumista ohjaavat liiketoiminta, käytettävyys ja muut vastaavat ominaisuudet ja olosuhteet.

H4.17 *kasvitehtaat, kasvihuone-IoT*
... Itse arvaan, että kasvatetaan korkean hinnan nopeasti kasvavia lajikkeita, esimerkiksi salaattia jota voi markkinoida steriilisti kasvatettuna ja josta voi saada korkeamman hinnan. ...

H4.18 Konttiviljelmistä on ollut kaikenlaisia kokeiluita ja sovelluksia, mutta niillä voitaisiin *ainakin teoriassa* mahdollistaa tuoreen ravinnon tuottamisen katastrofialueilla, missä tuoreiden elintarvikkeiden saatavuus on heikko ja niiden kuljettaminen paikan päälle voi olla vaikeaa mm. kylmäketjun puuttuessa.


H4.26 *uudet toimintatavat*
Maatilojen tekemä yhteistyö voisi saada uusia toimintamalleja.
Tällä hetkellä maatilat tekevät järjestäytymätöntä yhteistyötä niin, että edistyneemmän viljejijän toimintatapa voi levitä naapuritilojen käyttöön. Samankaltaista yhteistyötä voitaisiin tehdä teknologisilla alustoilla. ...


##### H5

H5.3 *haasteena laiteintegraatio (?), farm mngmnt, päätöksenteon apu, datan perusteella*
Ollaan vääjäämättä menossa siihen, että FMS tulee antamaan suosituksia helpottamaan viljelijän *toimintaa ja* päätöksentekoa. Järjestelmät voivat laskea *johtopäätöksiä* monen muuttuvan tekijän perusteella ja datan perusteella ymmärtää miten viljejijän työtä voidaan helpottaa sekä millaisilla toimilla saadaan paras tulos juuri kyseisessä toimintaympäristössä.
... Mutta ollaan jo siinä tilanteessa, että laitteilta saadaan tieto FMSlle missä ne ovat liikkuneet, polttoaineenkulutus jne. jolloin holistisesta järjestelmästä voitaisiin saada yleisnäkymä maatilan toiminnasta.

H5.12 *yleiskuva, swot per IoT-teknologiat, mitä hankaluuksia on*
Omasta mielestäni digitalisaatio tuo nykyiseen toimintaympäristöön pääasiallisesti vain parannuksia.
Viljelijälle voidaan tuottaa dataa, jonka avulla hän voi kasvattaa viljamääriä, tehostaa koneiden käyttöä, minimoida tiettyjen aineiden käyttöä. Nämä ovat kaikki parannuksia.
Lisäksi voidaan helpottaa viljelijän työskentelyä tai antaa hänelle aikaa keskittyä vaikka perhe-elämään.
Logistiikkaa voidaan parantaa, mikä on tärkeää Suomessa missä pellot sijaitsevat hajallaan, jolloin voidaan säästää polttoainetta ja vähentää liikenteen päästöjä.
Omasta mielestäni riskejä digitalisaatiossa on hyvin vähän. Järjestelmät voidaan suojata tietoturvauhkia vastaan ja riskit minimoida. Kunhan riskit minimoidaan tehokkaasti, ne jäävät loppujen lopulta aika pieniksi.

H5.14 *ruokaturva, ilmastonmuutos, väestönkasvu*
... Digitalisaation avulla voidaan tehostaa tuotantoa niin, että samalla työmäärällä tai resursseilla voidaan saada saman verran tai enemmän tuloksia. Selkeät tulokset todennäköisesti motivoisivat digitaalisten työkalujen käyttöön ottaneita toimijoita kehittämään toimintaansa edelleen. ...
Vaikka nykyisillä tuotantotavoilla ja ammattitaidolla yksittäinen viljelijä voi hyvinkin pärjätä vastaisuudessakin, tuotannossa voi silti olla huomaamattaa jääneitä pullonkauloja, jotka voitaisiin havaita datan analysoinnilla. Samoin voi olla, ettei tehtyjen viljelypäätösten todellista kausaliteettia voida hahmottaa.
Omasta mielestäni olisi hyödyllistä ohjata tuotettu tieto Suomessa ja EUssa päätöksiä tekevien ihmisten käyttöön, jolloin voitaisiin etsiä toimenpiteitä mitattuihin ja todellisiin tarpeisiin. *oikeassa mittakaavassa* *jolloin päätöksentekijät voisivat perustaa päätöksensä mitattuun dataan*
Datan perusteella voitaisiin tehdä siis maanviljelijöille parempia päätöksiä ainakin Suomen mittakaavassa.

H5.15 *mikä on omasta mielestäsi tärkeintä, entä mihin olet itse tutustunut/kohdannut*
... Tarjolla on monia erilaisia ratkaisuita ja oman näkemykseni mukaan lähes mikä tahansa digitalisaatio- tai IoT-ratkaisu tai -tuote tuottaa käyttäjälleen hyötyjä lähes välittömästi jo kokeilun perusteella, vaikka se maksaisikin joitain satoja euroja.
Sitä mukaa kun markkinoille tuotetaan uusia IoT-ratkaisuita valmistajat oppivat miten asiakkaat haluavat niitä käyttää.
Asiakas- ja käyttäjälähtöisellä kehittämisellä voidaan päästä nyt nousevan ensimmäisen digitalisaation aallonharjan ylitse.  ...

H5.16 *koneoppiminen, seuraava kehitysvaihe, toistuvan työn automatisointi, resurssien vapautus*
Tulevaisuudessa kehitystyön *(vai olisiko teknologiakehityksen?)* seuraavassa vaiheessa koneoppimisen ja keinoälyn avulla voidaan automatisoida yhä enemmän toistuvia työsuoritteita.
... Keinoälyn voisi myös antaa tehdä päätöksiä viljelyaikana ja antaa sen hoitaa toimintaa.
Nämä koneoppimisen ja keinoälyn avulla automatisoidut järjestelmät voivat olla hyvinkin lähitulevaisuuden maanviljelyn asioita.

#### AIoT-teknologioiden käyttöönoton laajuus (3 5) 250

    - osa ei ota käyttöön, huolimatta sadonlisästä (2)
    - teknologiset edistyksen tason vaihtelut (2)
    - eteneminen käyttöönotossa pienin askelin (1)

##### H1

H1.23 Pidemmälle viedyn tekoälyn ohjaaman automatiikan käyttöönoton mahdollistamiseksi sille pitäisi kehittää liiketoiminnallinen peruste, jossa sen hankintakustannukset voidaan näyttää mahdollisiksi kattaa sen käytön avulla saatavista lisätuloista. Nämä lisätulot tulisivat pääasiassa parantuneista sadoista, joita voidaan myydä joko parempaan hintaan tai suurempia määriä. 


##### H2

H2.23 Sensoriteknologia antaa mahdollisuuksia ulosmitata lohkolta saatavan satovasteen potentiaali tasaisesti. Tämä on menossa eteenpäin viljelijöiden keskuudessa.
Toisaalta jos ei ole omaksuttu aikaisempaa teknologiakehitystä eli jaettua lannoitusta *(onko tämä variable rate?)* niin ei todennäköisesti omaksuta sensoriteknologian mahdollistamaa jaetun lannoituksen hallintaakaan.

H2.24 Viljelijät eivät oman näkemykseni mukaan todennäköisesti tee suuria teknologiaharppauksia tai hyppäyksiä kehitysvaiheiden yli.

H2.25 Viljelijöiden ja teknologiatoimittajien tulisi keskustella enemmän vallitsevasta tilanteesta ja teknologioiden tuomista mahdollisuuksista.

H2.26 ... Kannattavuuden parantamista ja toiminnan kehittämistä tulisi tehdä pienissä paloissa. Kun on päätelty tuotannon suurimmat ongelmakohdat, voidaan niitä ryhtyä selvittämään ja korjaamaan, jolloin teknologiaa otetaan käyttöön tarvelähtöisesti.

H2.35 Suomessa Yaran N-sensorin käyttö on harvinaisempaa kuin Ruotsissa. Ruotsissa on noin 220-230 laitetta käytössä ja laskennallisesti 80 % vehnän pinta-alasta ajetaan N-sensorin kanssa.

H2.39 Viljelijät voivat käyttää sensoriteknologiaa lannoituksen jakoon mutta en itse ole tietoinen, että drooneilla tai satelliteilla tehdystä kuvantamistiedoista ja kartoista olisi vielä tehty levitystä tukevaa tehtävää.


##### H3

H3.42 Suomi ei ole maatalouden IoT-ratkaisujen omaksumisessa ihan edelläkävijä, mutta länsimaisen kulttuuriympäristön osana Suomessa on käytettävissä samat teknologiat kuin muuallakin.
Käyttöönoton nopeutta ja laajuutta ohjaavat teknologioiden soveltuvuus tähän ympäristöön.
Suomessa käytetään samoja traktoreita ja leikkuupuimureita kuin kaikkialla maailmassa, mutta Keski-Eurooppaan ja USA:han verrattaessa hieman pienikokoisempina.
Peltoviljelyssä sensoriverkkoja on käytössä oikeastaan vain tutkimuskäytössä ja tilatasolla sensorointi rajoittuu sääasemiin. 
Puutarha- tai perunanviljelyssä käytetään enemmän tilakohtaisia sääasemia kuin perusviljanviljelyssä. Erikoisviljelyssä taas sääasemien käyttöä on vähän enemmän.


#### AIoT-teknologioiden avoimet haasteet 2103

    - tietoliikenneyhteyksien merkitys ja haasteet (1 3 4 5)
    - järjestelmäintegraatio (2 3)
    - datan määrä, muoto, luotettavuus (2)
    - huollon haasteet (3)
    - protosta tuotteeksi (3)

##### H1

H1.25 Tehdasutomaatiossa ja kotieläintuotannossa voidaan saada sensoreilta tarpeeksi eheää dataa, jotta sitä voidaan käyttää koneoppimiseen, mutta peltoviljelyssä järjestelmäintegraation kanssa on jouduttu työskentelemään niin pitkään, että vasta nyt eri järjestelmät alkavat toimia yhdessä. Tämän jälkeen voidaan jatkaa kehitystyötä varsinaisen datan käsittelelmisen kanssa kun eheää dataa on saatavilla.

H1.34 Ilman dataa ei oikein voi säätää mitään.
Pienillä tiloilla ei ole ollut tähän asti mahdollisuuksia ottaa suuressa määrin käyttöön täsmäviljelyn ratkaisuita, jotka ovat olleet liian suuria investointeja ja liian vaikeakäyttöisiä.
Toivon, että digitalisoinnin, pilvi- ja IoT-teknologioiden avulla saadaan ratkaisuista niin helppokäyttöisiä, että voidaan saavuttaa lisää hyötyjä kuten työn tehostuminen uuden liiketoiminnan myötä jotta täsmäviljelystä tulee kannnattavaa ja normaalia.
Tämä on Smart Farming:ia, kutsutaan agriculture 4.0:ksi. Agriculture 3.0 jäi huonosti käytäntöön otetuksi välivaiheeksi ja on tarvittu nimenomaan tämä seuraava vaihe, missä smart/äly jotta myös edellisen vaiheen edut voidaan saada käyttöön.

H1.35 Viljelijät eivät lähde toteuttamaan täsmäviljelyä, koska sillä ei ole ollut juuri heille taloudellista perustetta.
Osa viljelijöistä on edelläkävijöitä täsmäviljelyssä, mutta laajaan käyttöönottoon tarvitaan agriculture 4.0:n älykkäiden järjestelmien tuomat edut.

H1.39 ... Suomessa ollaan lähtökohtaisesti perustettu telemetriaratkaisut matkapuhelinverkolle.
Drooneilla tehtävän kuvantamisen ja sen analytiikan kanssa on tarve saada kuvien analyysin käytännössä saman tien kun ollaan vielä pellolla. 5G-tekniikoista voisi olla hyötyä ison datamäärän viemisessä pilveen ja takaisin, jotta voitaisiin saada analyysi pellosta 10 minuutissa.

H1.40 3G ei sekään vielä kanna joka paikkaan mihin pitäisi, mikä on iso ongelma. Erityisesti suomalainen ongelma on maan pituus, peltojen pirstaleisuus ja sijainnit laaksopaikoilla, joissa kuuluvuus voi olla huono. Ukkoverkot voisi olla tähän potentiaalinen ratkaisu.


##### H2

H2.8 Järjestelmien rajapinnat, integraatiot ja datavirtojen standardointi on vielä työn alla.

H2.9 Laajamittainen yhteen toimivien järjestelmien käyttöönotto on riippuvainen alustojen kehityksestä ja saatavuudesta. Jos alustoja järjestelmien yhteistoiminnalle kehitetään ja tuodaan saataville niin niitä otetaan käyttöön.

H2.14 Suurin osa viljelijöistä on vielä aika kaukana esimerkiksi Yaran N-sensorilla tehtyjen karttojen ja muitten (pelto)lohkotietojen yhdistämisestä. Sensoritekniikkaa käytetään N-sensorissa lähtökohtaisesti lannoitustyökoneen suoraan ohjaamiseen.

H2.15 Muita käyttöönoton vaikeuksia, uhkia, heikkouksia:
Vaikka pieni joukko viljelijöitä ottaa käyttöön uutta teknologiaa matalalla kynnyksellä, kuten täsmäviljelylaitteita, niin suurempi joukko on sellaisia jotka eivät ota.
Joko he eivät näe sen etuja sellaisina, että hankinta ja käyttöönotto olisi juuri heidän tapauksessaan kannattavaa tai sitten he eivät ole täsmäviljelyteknologiasta tietoisia.
Jos suomalaisessa maanviljelyssä ei saada otettua käyttöön uutta teknologiaa, niin on olemassa riski, että suomalaiset viljelijät jäävät jälkeen teknologiakehityksessä.

H2.16 ... suomessa ei aina pystytä implementoimaan uusinta teknologiaa aikaisemman teknologisen kehitysvaiheen ollessa vielä kesken tai puuttuessa kokonaan.

H2.17 Teknologiakehittäjien haasteena on käytettävyys *ja käyttäjäystävällisyys*. Viljelijän tulee pystyä helposti käyttämään tuotetta tai järjestelmää *tehokkaasti ja saaden siitä täyden hyödyn* oman osaamisensa avulla. Käyttöliittymien tulee olla yksinkertaisia ja yksiselitteisiä sekä tuotetun tiedon oikeaa, jotta sitä voidaan käyttää päätöksenteon ja suunnittelun tukena.
Vaikka tarjolla on monenlaisia teknologioita, niiden tuottaman tiedon merkityksen tulisi olla tarjoajan tiedossa.

H2.18  ... Datasta tehdyt johtopäätökset ja niiden tekemisen metodit ovat tärkeämpi asia.
Kasvinviljelyssä on mahdollista kuvantaa erilaisia spektrejä ja saada tuloksena oikeaa dataa, mutta johtopäätöksien tekeminen ja niiden perusteella suositusten antaminen tuotantopanoksien käyttöön vaatii taustalle koetoimintaa tueksi (sekä erilaisia kalibrointeja).

H2.19 Johtopäätöksien tekeminen vaatii taustatyötä, mikä on vaikka N-sensorin tapauksessa muun muassa typpi- ja vaihtelualgoritmien kehittäminen. Ne perustuvat koetoimintaan, johon perustuvat johtopäätökset ja suositukset ovat testattuja.

H2.32 Tiedon liikkuminen tuotantoketjussa *(ruokaketjussa, arvoketjussa?)* kuluttajalle asti voisi toteutua jos siihen saataisiin alustajärjestelmä.

H2.36 Yaran N-sensorin hankintahinta nähdään Suomessa vielä korkeana ainakin yksittäisenä investointina tai eränä. *ei aina nähdä hyödyllisenä, vaikka olisi?*

H2.44 Liiketoiminnan ekosysteemin rakentuminen standardien ympärille vaatii vielä paljon työtä.

H2.45 Suuren datamäärän analysointi ja muuttaminen ohjelmistokäskyksi jollain tavoin vaatii vielä paljon työtä.




##### H3

H3.15 Käytännössä verkot eivät kanna droonien kuvauksien tuottamaa datan määriä, vaikka teoriassa se onkin mahdollista.
Valokuituverkoissa tämä kyllä onnistuu, mutta radioverkoissa verkot ovat ahtaat ja matkapuhelinverkon nopeuden kasvattaminen riittäväksi haja-asutusalueella on erittäin haastavaa. Mastoväli on suuri.

H3.16 Tulevat 5G-ratkaisut eivät lisää nopeutta pitkillä matkoilla vaan lyhyillä matkoilla.

H3.28 SMS-viestiratkaisu on ollut valmistajille tämän maan toimintaympäristössä luotettava valinta.
Aikaisemmin maatiloilla olleet verkot ovat olleet hyvin vaatimattomia, mutta valokuituyhteyksien myötä voidaan maatiloilla hypätä verkkoyhteyksissä kehityksen kärkeen.
Haasteena on verkkoyhteyksien hitausongelman ratkettua maatiloille rakennettujen verkkojen suunnittelematon rakenne. Verkkoja ollaan rakennettu ja laajennettu kulloisenkin tarpeen mukaan lisäämällä ominaisuuksia, mikä tekee verkoista vaikeasti turvattavia (ks. alkutuotannon kyberturvallisuus). Verkon komponenttien ollessa ilman ylläpitoa ja huonosti suunniteltuna verkko voi olla haavoittuva.

H3.29 Maatilolla käytössä olevan automatiikan haasteita on elinkaaren pituus/pitkäikäisyys ja luotettavuus.
Havaitsimme tutkimuksessamme uhaksi ylläpidon puutteen tai komponenttien vanhenemisen niin, ettei varaosia enää ole saatavilla.
Osassa ruokinta-automaatteja täytyy käyttää Windows 95:ttä, koska laite ei toimi millään muulla. Laitteissa voi olla emolevytason vaatimuksia riittävän hitaasta toiminnasta jotta ohjaustietokone voi palvella laitteen asiakasta. Tällöin eivät edes Windows 7:n yhteensopivuusominaisuudet riitä jos ja kun sovelluskehityksessä on oikaistu ja sivuutettu Microsoftin suunnitteluohjeet. Esimerkiksi käyttäjähallinta-asiat on voitu jättää pois sovelluksesta, jolloin sovellus ei ole yhteensopiva ja konkreettisesti ei toimi uudemman Windows-version kanssa.

H3.30 10 vuoden yleinen tuotevastuu on aika lyhyt ja käytössä oleva tuote on voinut jäädä ylläpidon ulkopuolelle.
Pitäisi herätä siihen, että 10 vuotta on tuotteen elinkaaressa lyhyt aika. Lainsäädännössäkin pitäisi velvoittaa valmistaja takaamaan varaosahuolto ja ylläpito.
Ohjelmistohuollossa tullaan myös tekijänoikeuskysymykseen. Mitä tapahtuu kun valmistaja lopettaa tai menee konkurssiin? Oikeudet ohjelmistoihin jäävät usein jollekin taholle kuten konkurssipesälle, jolla ei ole intressiä kehittää ohjelmistoja -niin mitä tehdään silloin itse tuotteelle? Jos tuote on ollut mekaaninen laite kuten akseli, niin niitä on voinut ruveta pyörittämään sorvissa mutta ohjelmistojen kanssa ei ole selkeää kuka voi aikaisempiin versioihin perustuen jatkokehittää siitä uusia versioita.

H3.31 Ohjelmistoalan kypsymättömyys kuuluu tähän ja jollakin tavalla tätä tulisi avata.
Tätä ollaan avattu nyt niin, että Ukrainassa tehdään John Deeren ohjelmistoista omia versioita omatoimisen huollon mahdollistamiseksi, kun Deere on ohjelmistolla pakottanut viljelijät käyttämään vain Deeren merkkihuoltoa.
On eräänlaista kiristämistä, että pakotetaan laitteen omistaja ostamaan laitteeseen jatkuvasti uusia päivityksiä. Esimerkiksi Deeren tapauksessa omistajan tulee ostaa varaosan lisäksi samalla myös ohjelmistopäivitys.
Lainsäädännöllisesti tulisi reilun pelin hengessä paitsi turvata tekijänoikeudet myös varmistaa, ettei tuotetta voisi käyttää kiristysvälineenä. Tällöin valmistajan lopettaessa ylläpidon voisi olla olemassa säädetty toimintatapa kolmannen osapuolen ylläpitoon ja kehittämistyöhön ryhtymiseen.
Samoin kuin patentit on julkaistava voimassaolon päätyttyä, voisi ohjelmistoissa olla samankaltainen toimintamalli.
En osaa sanoa, milloin nähdään ensimmäinen traktori, jonka ohjelmisto perustuu avoimeen lähdekoodiin, mutta kuka tahansa voisi sellaista ruveta rakentamaan.

H3.32 Prototyypeistä on vaikeaa edetä tuotteeksi asti osittain tuotevastuun takia. Tuotteen ja ohjelmiston elinkaaren kysymys tulee taas esille.

H3.33 Ohjelmistotuotanto on uusi tuotannon ala ja ohjelmistot muuttuvat ja niitä on helppo muuttaa, toisin kuin mekaanisia laitteita.
Nyt traktori on ohjelmistoalusta, jonka päällä tehdään asioita kun taas aikaisemmin se oli rautaa ja sähköjohtoja.

H3.43 ... Täsmäviljelylaitteistolle voi olla vaikea saada lisäarvoa EU-tukijärjestelmän pitäessä tuotteiden hintoja alhaalla. On aivan rajalla, voiko täsmäviljelylaitteiston investoinnin saada takaisin, maksamaan itsensä.
Viljanviljelyssä täsmäviljelylaitteiston hinta ei voi olla kovin kallis viljan ollessa halpaa, vaikka paljon puhutaankin että täsmäviljelyllä saataisiin enemmän ja laadukkaampaa viljaa.




##### H4

H4.9 ... Maatalouden näkökulmasta toinen merkittävä haaste on syrjäseutujen tietoliikenneverkkojen luotettavuus ja nopeus. Pilvipalveluiden yleistyminen asettaa kasvavia vaatimuksia tietoliikenneyhteyksien luotettavuudelle.

H4.10 UAV-laitteilla tuotetun datan määrä voi olla syrjäseutujen tietoliikenneverkkojen kaistanleveydelle liian suuri.
Olen itse keskittynyt datasta tehdystä ortomosaiikista tehdyn peltokartan hyödyntämiseen.
Tilanne monimutkaistuu otettaessa käyttöön tilan tarvitsemaa teknologista ekosysteemiä, johon kuuluvat mm. itse drooni, sen ohjelmisto(t) ja otetuista kuvista pellon kokonaiskartan koostava ohjelmisto tai palvelu.

H4.11 Oman ymmärrykseni mukaan ortomosaiikin rakentaminen on itsessään ratkaistu ongelma. 
Ortomosaiikin rakentamisessa käytettävät sovellukset toisaalta eivät ole vielä niin edistyneitä, että ne tekisivät sen automaattisesti tai melkein automaattisesti, eivätkä nämä sovellukset ole kaikille käyttäjille välttämättä kovin hyviä.
Ortomosaiikkikarttaa koostettaessa varsinkin isolta peltopinta-alalta kaikki kuvaukset eivät välttämättä ole keskenään vertailukelpoisia. Esimerkiksi 10 hehtaarin pinta-alan kuvaukseen menee droonilla aikaa niin paljon, että olosuhteet ovat voineet sen aikana muuttua aurinkoisesta puolipilviseen ja takaisin. Kun analyysiä tehdään kuvista vaikka jonkin tietyn vihreän sävystä niin valaistusolosuhteet ovat vaikuttaneet kuviin eivätkä kuvat enää ole suoraan vertailukelpoisia keskenään. Tällöin analyysin tekeminen vaikeutuu vähentäen sen perusteella tehtävien johtopäätösten luotettavuutta.
Aikasarjoja kuvatessa samalta pellolta voidaan aika varmoja että valaisuolosuhteet eivät ole olleet aika varmastikaan samanlaiset eri kerroilla.
Luultavasti on joitakin menetelmiä joilla tätä voidaan yrittää kompensoida, mutta ymmärtääkseni ne eivät vielä tällä hetkellä toimi parhaalla tavalla.
Referenssipisteitä voidaan asettaa pellolle, mutta ne ovat periaatteessa turhaa infrastruktuuria jos kuvien normalisointi pystyttäisiin ratkaisemaan jollakin tavalla.

H4.17 *kasvitehtaat, kasvihuone-IoT*
...
Teknologiaratkaisut ovat jännittäviä, mutta salaatilla ei voi ruokkia maailmaa.

H4.23 *tutkimus, uhat*
Tutkimme juuri nyt maatalouden tietoturvaa ja ylipäätänsä laitteistojärjestelmien kyberturvallisuutta, joka tulee olemaan maatiloilla kasvava ongelma.
Myös maatalouden verkkoon kytkettyjä laitteita koskevat samat tietoturvauhat kuin muitakin intertetiin kytkettyjä teollisia järjestelmiä.
Kiristyshaittaohjelmalla voi hyvinkin haitata maatilan toimintaa, samoin kuin Saksan rautateitä. Vaikka taloudelliset tappiot voivat olla yksittäisellä tilalla tuotannon keskeytymisestä olla pienemmät kuin rautatieliikenteen pysähtymiten vastaavat, eläinten jatkuvan hoidon lamaantuminen tarkoittaa välittömästi eläinsuojelu-uhkaa. Loppujen lopuksi se on jostakin näkökulmasta katsoen vakavampi asia kuin ihmisten pääsy ajoissa töihin.

H4.24 IoT-maailma on aika villi.
IoT-laite ei tyypillisesti itsessään ole minkään arvoinen ilman siihen kytkettyä palvelua. Palvelun ollessa laitteen valmistajan oma niin laitteista voi tulla käyttökelvottomia valmistajan tehdessä konkurssin. Esimerkiksi Juiceron mehupuristimilla ei voinut enää tehdä mitään yrityksen tehtyä konkurssin ja lopetettua puristimiin sopivia hedelmäpusseja toimittaneen palvelun. Toinen mahdollinen esimerkki on kodinhallintajärjestelmä, jonka palvelun kautta voi käynnistää vaikka saunan lämmityksen tai sytyttää valot. Kun se palvelu, jolla näitä toimintoja hallitaan, ajetaan alas niin voiko sen jälkeen ylipäätään kodissa sytyttää valoja?

H4.25 Ei ole varmuutta nyt hankittavan laitteen toiminnasta tulevaisuudessa, mikä on IoT-pöhinän systemaattinen uhka.
Jos ei ole varmuutta laitteen toimivuudesta sen elinkaaren ajan sitä ei voi käyttää toimintakriittisen järjestelmän osana, ei ainakaan niin, että järjestelmä ei enää toimi laitteen toiminnan lakatessa.
Maatalouden toimintaympäristössä on erityisiä haasteita laitteiden rakenteille, joiden tulisi kestää likaa ja kulutusta. Lato tai karjasuoja on paljon likaisempi paikka kuin asunto tai muut sisätilat yleensä. Lisäksi laitteiden tulee kestää lämpötilan ja kosteuden vaihteluita, rottia lehmiä. Rotat voivat pureskella laitteita ja johtoja, lehmä voi nuolaista laitetta.

H4.26 ... Alustaratkaisuiden kehittämisen haasteena on miten palvelusta voisi kehittää sellainen, että se oikeasti kiinnostaisi viljejijöitä. Periaatteessa tälläinen ratkaisu olisi viljejijöitä kiinnostava, koska he tekevät jo paljon yhteistyötä, tietojen vaihtoa jne.

H4.27 Palvelusta tulisi voida tehdä mukavampi käyttää kuin Whatsapp. Se on huono, mutta niin yleinen ja yleiskäyttöinen.
Yhtä asiaa kuten tautipaineen havainnointia ja siitä viestittämistä varten tehtyjä sovelluksia tulisi niin monta, että yhden huonon sovelluksen käyttö on käytännöllisempää kuin monien *hyvien (?)*. Muutamia esimerkkejä: tautipainepalvelu, *yleinen toiminnan*suunnittelupalvelu, viljanostopalvelu, viljanmyyntipalvelu, lannoitteidenostopalvelu, ruiskutuskemikaalienostopalvelu, ruiskutuskemikaaliensuunnittelupalvelu jne.
Järjestelmäintegraation lisäksi sovellusten ja palveluiden kirjo on muodostunut isoksi ongelmaksi, sekä miten nämä kaikki erilaiset toiminnallisuudet paketoitaisiin yhteen niin, että se olisi viljelijälle käytettävä. Tällä hetkellä tämän virkaa hoitaa maatalous- tai viljelyneuvoja, jolle voi soittaa. Se käyttöliittymä on edelleen hyvä ja älykäs monimuotoisiin asiantuntijajärjestelmiin ja monimuotoisiin tarpeisiin. Miten saataisiin kehitettyä käyttöliittymä, joka toimisi muutenkin kuin puhelinsoitolla asiantuntijapalveluun?


##### H5

H5.12 *yleiskuva, swot per IoT-teknologiat, mitä hankaluuksia on*
Omasta mielestäni digitalisaatio tuo nykyiseen toimintaympäristöön pääasiallisesti vain parannuksia. ... Omasta mielestäni riskejä digitalisaatiossa on hyvin vähän. Järjestelmät voidaan suojata tietoturvauhkia vastaan ja riskit minimoida. Kunhan riskit minimoidaan tehokkaasti, ne jäävät loppujen lopulta aika pieniksi.

H5.13 *verkkoyhteydet pellolla, maaseudulla*
Globaalin wifi- tai mobiiliverkon puuttuminen aiheuttaa ongelmia. Australiassa on useita peltoalueita, joilla ei ole minkäänlaista yhteyttä, samoin Brasiliassa on alueita, joilla ei ole yhteyttä.
Suomen ja Euroopan tietoliikenneyhteydet ovat yleisesti hyvät, mutta Euroopan ulkopuolella tietoliikenneyhteyksien haasteet tulevat nopeasti vastaan.
Brasilian viljelijät saattavat tuottaa jopa prosentin koko maailman tuotannosta jonkin tietyn (?) osalta, mutta heillä ei ole mahdollisuuksia päästä digitalisaatioon käsiksi internet- ja puhelinyhteyksien puutteen takia. *huomattavan osan maailman maataloustuotannosta tekevien viljelijöiden toimintaa ei ole mahdollista tehostaa tietoliikenneyhteyksien puutteen takia*
Tämä tarkoittaa huomattavia menetyksiä verrattuna siihen, mitä voitaisiin saavuttaa jos tietoliikenneyhteydet olisivat kyseisillä alueilla yhtä hyvät kuin Euroopassa.
Ratkaisevan tärkeää on saada kaikki laitteet toimimaan reaaliaikaisesti yhdessä ja sen mahdollistamiseksi haetaan ratkaisuita sateliitti- ja 5G-verkon avulla. Olemme tällä hetkellä digitalisaation murroksessa.

H5.18 *eri datalähteistä keräävä järjestelmä*
Tietääkseni sellaista järjestelmää, joka keräisi tietoa erilaisista datalähteistä kuten kuvantamistietoa drooneilta, traktoreilta, työkoneilta jne. ja yhdistäisi niitä, ei ole olemassa.

#### AIoT:n rooli ruokaturvan parantamisessa (1 2 3 4 5) 409

##### H1

H1.47 IoT-teknologiat ja digitalisaatio maataloudessa on tärkeässä roolissa ruokaturvan ylläpitämisessä. Smart Farming auttaa myös huoltovarmuuden parantamisessa.
Tietoisuuden kasvaminen millaista ruokaa missäkin varastossa on, auttaa ruokaturvasta vastaavaa viranomaista tekemään päätöksiä varsinkin kriisitilanteessa.
Paljon parempia ja nopeampia päätöksiä voidaan tehdä niukkojen resurssien allokoinnissa kun tieto on yksityiskohtaista ja digitaalisessa muodossa.

H1.48 Tietoon perustuvalla maanviljelyllä ilmastonmuutoksen aiheuttamiin muutostrendeihin päästäisiin kiinni. Esim. silmämääräisesti arvioituna satokoko voi muuttua huomaamatta.
Hyönteisinvaasion päästään nopeammin käsiksi, samoin se voitaisiin mahdollisesti myös taltuttaa tai rajata nopeammin, kun nähdään missä oloissa invaasio tapahtuu.
Väestönkasvuun voidaan vastata paremmin, kun olemme oman ruokamme tuottaja, emmekä kuluta muiden ruokaa, mikä on moraalinen velvollisuus. Jos oma tuotantomme on kannattamatonta, ei sitä enää jatketa, mikä vähentää ruoan tuotantoa. ...



##### H2 

H2.33 Ruokaturvan parantamiseen nämä teknologiat voivat osallistua vähentämällä viljantuotannossa viljelijän toiminnassa ilmeneviä riskejä, jolloin sadoista saataisiin varmempia. Samoin voidaan viljelijän toiminnassa saada järjestelmistä tarkkaa tietoa lohkojen historiasta ja nykytilanteesta, mikä parantaa tilannehallintaa kasvintuotannossa.
Tiedon avulla voidaan tehdä parempaa lajikevalintaa, tunnetaan typen vapautumisen määrät, kasvien tuleentumisen eteneminen ja tämän kautta parantamaan sadon määrää ja laatua ja sitä kautta ruokaturvaa.
Ruokaturvan varmistaminen on viljelijän toiminnassa mukana, mutta vielä merkittävämpi rooli toiminnassa on sellaisen viljan tuottaminen, mistä hän saa parhaan hinnan ja mitä häneltä halutaan ostaa.

H2.34 Viljanviljelyn riskiarvioita tehdessä voidaan arvioida sadon epäonnistumisen riski ja siitä johtuvat taloudelliset riskit. Silloin voidaan arvioida onko kannattavampaa ottaa näitä teknologioita käyttöön kuin olisi olla käyttämättä, koska näillä teknologioilla voidaan vähentää tuotannon tehon laskun riskiä, myös ilmastonmuutoksen aiheuttaessa muutoksia.


##### H3

H3.39 Ruokaturvasta puhuttaessa tulisi määritellä, onko meillä ruokaturvassa ongelmaa, kuinka vakava ongelma on ja millaista ongelmaa ylipäätään ollaan näillä IoT-teknologioilla ratkaisemassa.
Ruokaturvassa ongelma on ruoan liikkumat pitkät matkat, jolloin ruoalle tarvitaan identiteetti jolloin voidaan seurata mistä mikäkin ruokaerä on tullut.
Samalla kun valvontaa rakennetaan, tulisi arvioida todellinen valvonnan tarve ja syyt.
Ruokaketjun valvonnan tarvetta on lisännyt ruoan hinnan halpeneminen, koska ruokaa käsiteltäisiin todennäköisesti paremmin jos se olisi arvokkaampaa jolloin valvonnan tarve olisi pienempi.


##### H5

H5.14 *ruokaturva, ilmastonmuutos, väestönkasvu*
Suomen osalta kaikki mikä parantaa maatalouden tuottavuutta parantaa myös omavaraisuutta ja sitä kautta omaa ruokaturvaamme.
Jotta voisimme varmistaa ruokaturvamme oman ruoantuotantomme tulee olla yksittäisille toimijoille kannattavaa ja työn sellaista, että se motivoi maanviljelijää kehittämään omaa toimintaansa. Tällöin ruokatuotantomme kehittyisi jatkuvasti, voisimme vastata tuleviin ja nykyisiin haasteisiin paremmin/tehokkaammin ja sitä kautta oma ruokaturvamme paranisi.
Digitalisaation avulla voidaan tehostaa tuotantoa niin, että samalla työmäärällä tai resursseilla voidaan saada saman verran tai enemmän tuloksia. Selkeät tulokset todennäköisesti motivoisivat digitaalisten työkalujen käyttöön ottaneita toimijoita kehittämään toimintaansa edelleen.
jos suurin osa viljelijöistä ottaa käyttöön uusia digitaalisia työkaluja voimme nähdä hyvinkin suuria muutoksia maanviljelyksessä.
...

#### Ihmisen/käyttäjän rooli AIoT-järjestelmien ohjaamisessa ja päätöksenteossa 135

##### H2

H2.40 Ihminen on toiminnassa vahvasti mukana ja tulkitsee indeksin arvoa. Tässä tulkinnassa tarvitaan asiantuntijuutta jonka avulla tiedostetaan lukujen merkitykset ja tarkoitukset. Ilman sitä kokeisiin, tutkimukseen ja kokemukseen perustuvaa asiantuntijuutta *koneellisesti tulkittuna* voidaan mennä jopa huonompaan suuntaan.


##### H4

H4.3 Vaikka IoT-ratkaisun/järjestelmän määrittelyssä ollaan joissain tapauksissa korvattu ihmisen tekemä valvonta, päätöksenteko ja toimeenpano automaattisilla koneiden toiminteilla, niin suuri osa IoT-ratkaisuiksi *merkityistä/määritellyistä* järjestelmistä on käytännössä sensoridatan lukemista ja ihmisten vastuulle on jäänyt ainakin lähes, jos ei kaikki päätöksenteko ja toiminta.
Tämä johtuu juuri järjestelmien välisen kommunikaation puutteesta.
Toisaalta ihmiselle jäävä päätösvalta ei ole pelkästään huono asia.
Toisaalta mitä enemmän käytetään dataa ja mitä enemmän kone tekee ihmisen puolesta päätöksiä, niin sitä enemmän pitää kiinnittää huomiota käyttäjän oman asiantuntemuksen ylläpitoon. Käyttäjän nojautuminen täysin automaattisen järjestelmän varaan voi helposti aiheuttaa käyttäjän oman asiantuntemuksen puutteen ja sitä kautta kokonaisprosessin ymmärryksen vähenemisen tai häviämisen.



#### AIoT-teknologioiden tavoitetila, tulevaisuuskuvat (1 3 4) 1181

##### H1

H1.33 Yleensä maatalousteknologian tutkimuksessa on 15 vuoden aikajänne, ehkä pidempikin.
Laajaan käytäntöön tulee hitaasti, koska ratkaisujen pitää sopia ja toimia niin monelle.
Poikkeuksia voi ilmetä, mutta ne eivät ole kokonaisuuden kannalta merkittäviä. Vain yksittäisten tiettyjen yritysten saavutuksia.
Oman näkemykseni mukaan pyritään datan töihin laittamiseen: datan kerääminen, hyödyntäminen ja prosessien haltuunottoon.
Prosessien tulee olla samaan tapaan hallussa peltotuotannossa, kasvihuonetuotannossa kuin tehtaissa.
Prosessista tulisi tietää mihinkin kohtaan peltoa laitetaan ja paljonko siitö jäi käyttämättä, emissioriskit, saavutetut määrä ja laatu. Lisäksi meillä on tuotteen tarina sille nimenomaiselle tuotteelle mikä siitä kohtaa peltoa tuli. 
Tarinalla voidaan saada lisäarvoa markkinoilla.
Elintarvikeverkkoihin kytkeyessä tuote voi saada lisäarvoa.
Sivuvirtojen paremmalla hallinnalla, johon liittyvät myös kierrätyslannoitteet ja muut kierrätysprosessit maataloudessa.
Tuotteita voidaan käyttää myös energiatuotannossa, peltotuotteita tekstiiliteollisuudessa.
Tuotteista voidaan saada myös eliksiirejä kemian tuotannossa.
Oman näkemykseni mukaan prosessien paremmalla hallinnalla tuotannossa tarvittavia panoksia osataan säätää paremmin ja tarkemmin. 
Mahdollisesti myös ekologian ymmärrys paranee, kuten maaperän mikrobien roolin huomioon ottaminen kestävyydelle, satoisuudelle ja riskien minimoinnille. Hyväkuntoisesta pellosta tulee aina jotain säästä huolimatta.
Tämä prosessien hallinta olisi myös varautumista lmastonmuutoksen myötä uhkaaviin tauti- ja hyönteisinvaasioihin. Silloin tilannehallinta olisi paljon parempi. Prosesseja osattaisiin hallita ja riskejä torjua, jolloin tuotanto olisi paljon kestävämpi. ...

H1.41 Varmaankin ollaan menossa siihen, että tilojen määrän vähentyessä yksi tila hoitaa yhä suuremmalla alueella olevia peltoja automaation avulla. Sinne voisi tulla varastoja ja pientä prosessointia peltokeskittymän lähelle.
Valvonnan telemetriapalveluille voi tulla vielä suuri kysyntä.


##### H2

H2.11 Tavoitetila on kuitenkin ihmisen toteuttamien työvaiheiden vähentäminen tietojenkäsittelyssä, mutta en osaa sanoa millä aikavälillä täysin automatisoitu järjestelmä tulee yleiseen käyttöön. Sellaisen toteutus on ilmeisesti lähellä.

H2.30 ... Pienillä tiloilla, joiden keskiarvoinen hehtaarikoko 40-50, täsmäviljelyn teknologiaratkaisut on erilaisia kuin tiloilla joissa on 200-400 hehtaaria. *Taas se pirstaleisuus.* Tulevaisuudessa käytettävät laitteistot ja järjestelmät voivat poiketa toisistaan huomattavasti tilakoon *ja tilatyypin ja muiden tilan ominaisuuksien* mukaan.
Samoin käytetyn teknologian saavutetut hyötysuhteet voivat vaihdella huomattavasti käyttöympäristöjen vaikutusten mukaan.

H2.31 Jos ajatellaan millainen maatalouden yleiskuva voisi olla, niin viljelijä voisi saada käyttöliittymäänsä kehotuksia toimista ja niiden perustelut. Esimerkiksi sensorien antaman tiedon analyysin perusteella tarvitaan lisälannoitusta tiettynä ajankohtana.
Lisäksi järjestelmä voisi myös kommunikoida muiden järjestelmien kuten tilanhallinnan FMS, viljelysuositusjärjestelmän ja muiden erilaisten ohjelmistojen kanssa.
Tällaisiin järjestelmiin on vielä vähän matkaa, mutta mallinnuksen, datan keruun ja niiden perusteella tehtävien viljelysuositusten ja niiden ajankohtien määrittelyjen kanssa tehdään paljon työtä. Nämä järjestelmät voivat hyvinkin toteutua.
Kauemmaksi tulevaisuuteen voisi visioida itsenäisesti pelloilla toimivia traktoreita.

H2.42 Jos tahtoa toteuttaa viljelijöiden ja muiden datasettien vertailualusta löytyy, sitä tullaan jollain aikavälillä rakentamaan pala kerrallaan aloittaen luultavasti rajapintojen ja tietojen siirtämisen ratkaisuista.

H2.43 Todennäköisesti viiden vuoden kuluttua tällaiset järjestelmien väliset ja dataa kokoavat järjestelmät ovat jo yleisessä käytössä.

H2.46 Tilakoot ovat kasvamassa ja rakennemuutos on menossa yhä suurempien tilakokojen suuntaan. Tullaan näkemään ajosuunnittelun ja urakointipalveluiden käytön yleistymistä.
Suomelle tyypilliset pirstaleiset lohkot *(ja muut olosuhteet?)* antavat meille syitä kehittää tehokkuutta parantavia ratkaisuita, jotta voimme pysyä muun maailman tahdissa mukana.


##### H3

H3.35 IoT toimii lähinnä välineenä taustalla maatalouden automatisoinnissa.
Automaation lisäämiseksi tarvitaan ennen kaikkea sensoreita: tietokone ei voi tehdä päätöksiä ilman tietoa.
Mittausverkon rakentaminen maatilan toimintaa mittaroimaan on haaste, johon vastaamista IoT-laitteet voisivat helpottaa. Tähän tarpeeseen voisi olla anturipaketteja, joita on kehitetty teollisuudessa. Niillä voitaisiin mitata tiettyjä asioita ja niihin voitaisiin viitata verkko-osoittella, jonka avulla sensorien tieto voitaisiin lukea.
Tällaista sensoripakettia odotan ehkä eniten komponenttipuolelta (?).

H3.36 Sensoripaketteja tai tiettyyn mittaukseen kehitettyjä sensorilaitteita. Ei tiettyyn tarkoitukseen, vaan tiettyyn mittaukseen niin, että antureita olisi saatavilla hyllytavarana, niiden hinta laskisi massatuotannon avulla ja niitä valmistettaisi vielä 30 vuoden kuluttuakin.
*Eikä niin, että tiettyyn tarkoitukseen kuten juuri tämän järjestelmän osana toimimiseen.*

H3.37 Maatalouden tulisi tutkia mitä on tehty teollisuudessa ja soveltaa siellä jo kehitettyjä, yleisessä käytössä olevia ratkaisuita.

H3.38 Maatalouden laitteissa on komponentit tehty ainoastaan tiettyjä laitteita varten, esimerkiksi ruokintarobotin piirilevyn varaosahinta on 4000 €, mikä on sen sisältämään toiminnallisuuteen verrattuna hirvittävän paljon rahaa. Yleisessä käytössä olevista teollisuuskomponenteista, vaikka paperikoineissa käytetyistä, rakentamalla hinnaksi tulisi luultavasti alle 1000 €.

H3.43 Tällä hetkellä on meneillään teknologia-aalto, missä haetaan parhaiten sopivia teknologiasovelluksia ja ylilyöntejäkin on odotettavissa.
Käyttöön jäävät karsiutumisen jälkeen merkityksellisimmät ratkaisut kunhan ensin löydetään niille sopivat käyttökohteet.
Traktoreissa automaatiota on jo ja seuraavaksi se on leviämässä työkoneisiin, missä suuremmat koneet ja monipuolisimmat säädöt tullaan automatisoimaan traktorin yhteyteen. ...




##### H4

H4.19 *kasvatusresepteillä toimiva kasvihuone tms. MIT Food Computer*
Kasvihuonetuotanto on nykyään hyvin automatisoitua, mutta optimointivaraa voi vielä olla.
Itse odotan kerrosviljelyratkaisuita, joissa voisi viljellä peruselintarvikkeita kannattavasti.
Jos joku jossakin vaiheessa onnistuu tuottamaan viljaa tai perunoita kerrosviljelmässä  taloudellisesti kannattavalla tavalla niin se voi merkitä huomattavaa muutosta ruokatuotannon kehityksen suunnalle.
Perunan tuotanto voisi onnistua hydroponisella viljelyllä, ainakin siemenperunan viljelyä tehdään jo niin.
Kuluttajaperunan viljely taloudellisesti kannattavalla tavalla olisi huomattava edistysaskel, joka voisi olla käännekohta maatalouden historiassa.
Erikoistuotteita voi kyllä tulla, olen itse pitkään odottanut suomalaisen mansikan kasvihuoneviljelyn alkamista ja olisiko ympärivuotisesti saataville mansikoille kysyntää.

H4.20 *maaseudun tulevaisuus, 20-30 vuotta*
Järjestelmäintegraation, datan käsittelyn ja alustojen yhteisten ekosysteemien onnistunut toteutuminen tulisi muuttamaan maataloustyön luonnetta suorittavasta työstä suunnitteluun, ylläpitoon ja automatiikan ylläpitotyöhön.
Järjestelmäylläpitotyön osuus kasvaa automaatiojärjestelmien monimutkaistuessa ja koon kasvaessa. Järjestelmien toimintaa pitää valvoa, rikkoutuvia laitteita korjata ja korvata usilla.
Tällöin hehtaaritehokkuus per työntekijä kasvaa edelleen, mutta työn luonne muuttuu.
En ole miettinyt miten tämä voisi vaikuttaa maatalouteen ja maaseutuasumiseen laajemmin.
"Voi olla, että 50 vuoden kuluttua stereotypia tyhmästä maajussista pitää vielä vähemmän paikkansa kuin nykyään --koska sen tyhmän maajussin pitää siinä vaiheessa huoltaa ja ylläpitää omaa ruokatehdastaan."

H4.22 Hajautetut suuret tilat eivät tuskin olisi kannattavia. 


##### H5

H5.3 *haasteena laiteintegraatio (?), farm mngmnt, päätöksenteon apu, datan perusteella*
Ollaan vääjäämättä menossa siihen, että FMS tulee antamaan suosituksia helpottamaan viljelijän *toimintaa ja* päätöksentekoa. Järjestelmät voivat laskea *johtopäätöksiä* monen muuttuvan tekijän perusteella ja datan perusteella ymmärtää miten viljejijän työtä voidaan helpottaa sekä millaisilla toimilla saadaan paras tulos juuri kyseisessä toimintaympäristössä.
FMS, laitteista kerätty data ja muu tieto tulevat varmasti yhdistymään ja niitä tullaan käyttämään yhdessä. ...

H5.7 *tulevaisuudenkuva/visio, aikavälillä mikä*
Yksittäiset asiakkaat saattavat ottaa agrirouter:in käyttöön jo tänä vuonna (2018).
Kaupallistumisen aste ja omaksumisen/käyttöönoton nopeus tulee luultavasti olemaan hyvin nopea, mutta kaikki toimijat tuskin koskaan tulevat ottamaan agrirouteria *tai vastaavaa järjestelmää* käyttöön.

H5.8 Kuvittelisin, että suurin osa, korkea prosenttiosuus ammattimaanviljelijöista pohjoismaissa/Euroopassa tulee ottamaan agrirouterin *(tai vastaavan järjestelmän)* käyttöönsä.
Pienemmille tilallisille ja harrastemaanviljelijöille tällaisesta järjestelmästä ei ole niin suurta hyötyä, että järjestelmä olisi tarpeellinen ja käyttöönotto kannattaisi. 
Maanviljelijöitä on hyvin erilaisia, eikä kannata yleistää heitä yhtenäiseksi joukoksi.

H5.15 *mikä on omasta mielestäsi tärkeintä, entä mihin olet itse tutustunut/kohdannut*
... Asiakas- ja käyttäjälähtöisellä kehittämisellä voidaan päästä nyt nousevan ensimmäisen digitalisaation aallonharjan ylitse. 
Tämän aallonharjan ylitse pääsyn vaatimien ponnistelujen jälkeen voidaan jatkaa kehittämistä saatujen kokemusten ja näkemysten viitoittamaan suuntaan.

H5.16 *koneoppiminen, seuraava kehitysvaihe, toistuvan työn automatisointi, resurssien vapautus*
Tulevaisuudessa kehitystyön *(vai olisiko teknologiakehityksen?)* seuraavassa vaiheessa koneoppimisen ja keinoälyn avulla voidaan automatisoida yhä enemmän toistuvia työsuoritteita.
Eteneminen voisi hyvinkin lähteä liikkeelle itseajavista pellolla toimivista koneista.
Autoteollisuudessa on kehitetty pitkälle itse ajavia autoja. Pellolla työkoneiden ei tarvitse liikkua muun liikenteen seassa, mikä teke toimintaympäristöstä huomattavasti yksinkertaisemman.
Keinoälyn voisi myös antaa tehdä päätöksiä viljelyaikana ja antaa sen hoitaa toimintaa *(suorittavalla tasolla?)*.
Nämä koneoppimisen ja keinoälyn avulla automatisoidut järjestelmät voivat olla hyvinkin lähitulevaisuuden maanviljelyn asioita *(jos eivät ihan arkipäivää?)*.

H5.17 *kestääkö kauemmin saada koneoppimista pellolle kuin kasvihuoneeseen?*
Teknologia koneoppimisen ja keinoälyn soveltamiseen peltotuotannossa on jo sinänsä olemassa.
Ainoa syy, että sen käyttöönotossa ollaan varovaisia *(ja hitaita?)* on päättäjien, kuluttajien ja yleisesti ihmisten kokema pelko, kun kohdataan keinoälyn ajama kone.
Ajan kuluessa teknologia saavuttaa ihmisten hyväksynnän *ja sen käyttöönotto leviää alkuun päästyään kuin huomaamatta*.
Digitaalisuus on tullut jäädäkseen ja sen vaikuttaa *kaikkeen toimintaan maataloudessakin* jatkuvasti voimakkaammin.

H5.19 *ohjelmistoratkaisuiden pirstaleisuus, muuta, mitä maataloudessa tapahtuu*
IoT on voimakkaasti tulossa toimintaan ja kaikki merkittävät laitevalmistajat ovat kehittämässä omia IoT-ratkaisuitaan.

#### Muut teemat 277

##### H2

H2.28 Vaikka viljelijä tekisi kaiken samoin joka vuosi, maasta voi vapautua ohrakasvustolle tietystä kohtaa peltoa 100 kiloa typpeä yhtenä vuonna ja toisena vuonna 60-70 kiloa.

H2.29 Koska olosuhteet ja kasvukaudet vaihtelevat, tarvitaan osaamista, datan louhintaa ja algoritmien kehitystyötä aikaisemman tiedon pohjalta.
Koska lannoitussuositus vaikuttaa sekä sekä satotasoon että kannattavuuteen, tulee suosituksia tehdessä tietää mitä vaikka 40 kilon muutos tarkoittaa ja mihin kaikkeen se vaikuttaa.
Toisaalta muistaakseni noin puolet viljelijöistä ei laske viljatonnin tuotantokustannuksia, joten kustannusrakenteen tietoisuuteen tuomisessa on vielä paljon tehtävää työtä.


##### H3

H3.10 ISOBUS-standardin haasteena on task:in *toimikäskyn?* muodostuminen reaaliaikaisesti ja vaikka teknisiä mahdollisuuksia tällaiseen toiminnallisuuteen on, niin ISOBUSia ei alun perin ole suunniteltu tällaiseen. Suunniteltu toimintamalli oli task-tiedoston kerralla siirtäminen, eikä jatkuvasti muuttuva ohjaus.

H3.11 Tästä esimerkkinä reaaliaikaisesti kasvustoja mittaava Yaran N-sensori, jonka kaltaisia laitteita on muillakin kuten Claasilla.

H3.44 Automaatiolaitteistojen hinnoissa on vielä aika paljon kehityskuluja ISOBUS-standardin 20 vuoden kehittämiskustannuksista, mitkä ovat vielä maksamatta.

H3.45 ISOBUS-kehitystyöhön on investoitu, eikä ole varmaa saavatko yritykset niitä rahoja takaisin. Massatuotannon avulla ISOBUS-laitteistojen hintojen pitäisi tulla alas, samaan tapaan kuin autoteollisuudessa ECU-laitteet.
Nyt pitäisi maatalousyksiköidenkin hintojen tulla alas, tai ottaa maataloudessa käyttöön samoja yksiköitä kuin autoissakin.

H3.46 Hintojen on oikeastaan tultava alas, samalla kun yritysten on saatava tutkimus- ja kehityskulut katettua. Tuotantosarjojen pituus on tässä avainasemassa.
ISOBUS-kehitystyössä tehdään yhteistyötä niin, että yksi taho valmistaa standardin mukaisia laitteita joille useat ohjelmistokehitystä tekevät toimijat tekevät sovelluksia.

H3.47 Konsortiotyöllä on mahdollista saada fyysisten laitteiden hintaa alas.


##### H4

H4.28 *urbaaniviljely*
Loppujen lopuksi viljelyssä syötteitä tulisi olla vähemmän kuin samaa tuotetta tehtäisiin muualla ja tuotaisiin se paikan päälle.

H4.29 Salaatti tarvitsee sähköllä tuotettua valoa, vettä ja ravinteita. Ravinteita tarvitaan salaattiin vähemmän kuin tuotetussa salaatissa on, koska syötteitä tulee muualtakin *(?)*.
Kasvihuone- ja urbaaniviljelyssä ongelma on saada toiminnasta kannattavaa lopputuotteen vaatimilla syötteillä.


## Haastatteluista saatujen tulosten vertailu kirjallisuuskatsauksen tuloksiin

## Tutkimuskysymyksien vastaukset

I) Millaista tutkimusta IoT-teknologioiden soveltamisesta kasvintuotantoon on julkaistu?

* Millaisia teknologiasovelluksia tutkimuksissa on esitelty?
* Minkä tyyppiset sovellukset tulevat tutkimusmateriaalissa selkeimmin esille, eli millaisista sovelluksista ja teknologioista kirjoitetaan ja tehdään tutkimusta tällä hetkellä?
* Muut kysymykset? Vaikuttavuus, mitä tilanne kertoo ylipäänsä, jne.

II) Miten kasvintuotannossa hyödynnetään IoT-teknologioita?

### Puutarhatuotannon AIoT-ratkaisut

*Miksi tämä on tässä? Ei mitään käryä -> siirrettävä*

Pyritään antamaan kokonaiskuva lukijalle löydetyistä teknologiaratkaisuista, niiden tyypeistä, tutkimuksesta ja käytöstä.

Kirjallisuuskatsauksissa (ja kirjallisuudessa?) tyypittelyt menevät miten?

Haastatteluissa mainitut asiat?

Tieteellisissä lähteissä/tutkimuksessa on löydetty nämä?

Muissa julkaisuissa on löydetty nämä? (Tämä on mehukkain ja luultavasti uutisoiduin kohta koko opparissa. Pitäisikö käsitellä ensin?)

Yhteenvetona: tässä on kaikki. :)


# POHDINTA

## Haastattelutuloksista

H1.31 Uusia standardiperusteisia teknologioita voidaan ottaa käyttöön asteittain pienissä paloissa. Standardien kuten ISOBUS etu on, että niitä on kehitetty pitkään ja maatalouden teollisuus on niihin sitoutunut.
Voi tulla teknologioita, jolla asiat voi tehdä helpommin kuin CAN-väylää käyttäen, mutta omaksuminen tapahtuu hitaasti. *Laitteiden myyminen käyttöön on hidasta, koska käyttöikä on pitkä, yhteensopivuus pitäisi olla, investoinnin pitäisi oikeasti tuottaa paremmin juuri sillä tilalla ja tilat ovat valtavan erilaisia.* Tällä hetkellä tutkitaan standardisoinnissa teollista ethernettiä CAN-väylän sijaan. Jos uudet standardit tulevat käyttämään sitä, tulisi sen silti olla yhteensopiva ja käyttökelpoinen vanhojen laitteiden kanssa, esim. 30 vuotta vanha traktori.
*Ei voi tehdä isoja investointeja -> pala kerrallaan -> pitää olla taaksepäin yhteensopiva -> käyttöikä voi olla 30 vuotta ja silti sen pitää toimia yhteen uusimman tekniikan kanssa -> standardin laatiminen on aikaavievää ja vaikeaa!*

H1.33 ... Prosesseja osattaisiin hallita ja riskejä torjua, jolloin tuotanto olisi paljon kestävämpi.
*Vaikka uudet teknologiat voivat alkuvaiheen käyttöönotto- ja kokeiluvaiheissa näyttää herkästi rikkoutuvilta ja epäluotettavilta, niillä voidaan saavuttaa kestävämpi tuotanto. Kunhan kokemuksia kertyy ja ratkaisuista kehitetään luotettavia.*

H2.12 Yarassa emme ole ... kohdanneet kysymystä datan omistajuudesta. ... *Datan keruu voi siis olla tulevaisuudessa kysymys johon toimijoiden on otettava kantaa.*

H2.14 Suurin osa viljelijöistä on vielä aika kaukana esimerkiksi Yaran N-sensorilla tehtyjen karttojen ja muitten (pelto)lohkotietojen yhdistämisestä. Sensoritekniikkaa käytetään N-sensorissa lähtökohtaisesti lannoitustyökoneen suoraan ohjaamiseen. *Onko tämä suora ohjaus ilman tiedon tallennusta, analytiikkaa jne. missä määrin yleisempää toimintaa? Ainakin kirjallisuuskatsausten mukaan havainnointi ja kontrollointi ovat huomattavasti yleisempiä kuin analytiikka. Voisiko tutkimusten määrää ja aikaa verrata Big Data-katsausten vastaaviin?*

H2.15 ... Jos suomalaisessa maanviljelyssä ei saada otettua käyttöön uutta teknologiaa, niin on olemassa riski, että suomalaiset viljelijät jäävät jälkeen teknologiakehityksessä *ja menettävät markkinaosuuksiaan muualta tuoduille tuotteille*.

H2.17 ... teknologioita, niiden tuottaman tiedon merkityksen *ja kausaliteettien* tulisi olla tarjoajan tiedossa *mutta näin ei aina taida olla?* 
*Ilmeisesti tällä hetkellä järjestelmät voivat tuottaa tietoa päätöksenteon tueksi, mutta eivät vielä oppia toiminnasta, eivätkä ehdottaa viljelypäätöksiä, eivätkä tehdä päätöksiä autonomisesti?*

H2.26 ... jolloin teknologiaa otetaan käyttöön tarvelähtöisesti. *Tällöin on ilmeisesti hyvin harvinaista, että tehtäisiin suuria harppauksia, vaan pienin askelin edetään, jolloin teknologioiden täytyy sopia yhteen sekä vanhojen että tulevien laitteiden kanssa.*

H4.9 Kun viljelysuunnitteluohjelmat siirtyvät yhä enemmän paikallisista ohjelmista pilvipalveluihin viljejijän toiminnassaan tuottaman datan omistajuudesta ei aina ole varmuutta.
...
Maatalouden näkökulmasta toinen merkittävä haaste on syrjäseutujen tietoliikenneverkkojen luotettavuus ja nopeus. Pilvipalveluiden yleistyminen asettaa kasvavia vaatimuksia tietoliikenneyhteyksien luotettavuudelle *varsinkin tilojen toimintakriittisille sovelluksille ja palveluille. Kuinka moni viljejijä haluaisi ottaa riskin sijoittamalla omalle yritykselleen toimintakriittisiä tiedonhallinnan sovelluksia epäluotettavan ja hitaan verkkoyhteyden taakse?*

H4.10 ... Tilanne monimutkaistuu otettaessa käyttöön tilan tarvitsemaa teknologista ekosysteemiä, johon kuuluvat mm. itse drooni, sen ohjelmisto(t) ja otetuista kuvista pellon kokonaiskartan koostava ohjelmisto tai palvelu. *Arvelisin, että mitä useampi sovellus, analyysi ja palveluntarjoaja, sitä vikaherkempi järjestelmä on.*

*Haastatteluissa teemoihin, jotka käsittelivät tulevaisuudenkuvia ja mahdollisuuksia, tuli enemmän materiaalia kuin teemoihin, jotka käsittelivät tämän hetken AIoT-ratkaisujen tilannetta. Voi olla, että niin kuin haastatteluissa ilmeni tilanne on vasta kehittymässä ja varsinaisten AIoT-ratkaisujen käyttöönotto on vasta alkamassa.*

H4.27 ... Tällä hetkellä tämän virkaa hoitaa maatalous- tai viljelyneuvoja, jolle voi soittaa. Se käyttöliittymä on edelleen hyvä ja älykäs monimuotoisiin *jos koodarille pitää speksata tarkkaan mitä pitää toteuttaa, monimuotoista järjestelmää on äärettömän kallis ja vaikeaa toteuttaa. Ehkä koneoppimisella?* asiantuntijajärjestelmiin ja monimuotoisiin tarpeisiin. Miten saataisiin kehitettyä käyttöliittymä, joka toimisi muutenkin kuin puhelinsoitolla asiantuntijapalveluun?

H5.4 ... Exceliin itse käsiteltäväksi, mutta meidän käyttöliittymämme tarjoaa paremmat mahdollisuudet *laitevalmistajien käyttöliittymät/palvelut toimivat ilmeisesti paremmin kuin jos viljelijä tekisi omaa analyysiä, mahdollisesti analytiikan opetteluun ja säätämiseen kuluisi liikaa omaa aikaa ja vaivaa?* ... IoT-ratkaisuiden tulisi tukea datan analytiikkaa/toiminnan kehittämistä/?, niiden tulisi olla helppokäyttöisiä ja tarvittava tieto tulisi tulla esille silloin kuin sitä tarvitaan *voisiko olla myös datan esilletuontia järjestelmän aloitteesta, sellaista mitä käyttäjä ei ole osannut kuvitella tarvitsevansa?*

H5.6 http://www.dke-data.com/en/der-agrirouter-kommt/ esiteltiin Agri Technica -messuilla 2017 ja voitti hopeamitalin, FENDTin sivuilla 2017-09-08 Press release https://www.fendt.com/int/software-solutions.html kotisivu https://my-agrirouter.com/en/

H5.9 ... FMS-järjestelmät tulevat varmaan olemaan lähimpänä kokonaiskuvan tuottavaa tietojen esittämistä. *Tämä vaikuttaa vain yhden maatilan tilannetiedolta, mutta miten osana ruokaketjua ja globaalia ruokamarkkinaa?*

H5.13 *verkkoyhteydet pellolla, maaseudulla*
... Brasilian viljelijät saattavat tuottaa jopa prosentin koko maailman tuotannosta jonkin tietyn (?) osalta, mutta heillä ei ole mahdollisuuksia päästä digitalisaatioon käsiksi internet- ja puhelinyhteyksien puutteen takia. *huomattavan osan maailman maataloustuotannosta tekevien viljelijöiden toimintaa ei ole mahdollista tehostaa tietoliikenneyhteyksien puutteen takia*

H1.31 ... Voi tulla teknologioita, jolla asiat voi tehdä helpommin kuin CAN-väylää käyttäen, mutta omaksuminen tapahtuu hitaasti. *Laitteiden myyminen käyttöön on hidasta, koska käyttöikä on pitkä, yhteensopivuus pitäisi olla, investoinnin pitäisi oikeasti tuottaa paremmin juuri sillä tilalla ja tilat ovat valtavan erilaisia.* ...

## Luotettavuus

## Hyödynnettävyys

# LÄHTEET

# LIITTEET




---------------------------------------------------------------------------------------------------

Kenttä on pirstaleinen ja parhaat prototyypit, pilottitoteutukset ja pitkälle viedyt kokeilut ovat vieläkin erillään, eivätkä muodosta yhtenäistä kokonaisuutta, järjestelmien järjestelmää tai siitä seuraavia kehitysvaiheita.

Löytyykö vielä parhaan tavoitetilan kuvauksia edes spekulointeina, tulevaisuudenkuvina lähteistä? Miten IoF:n esimerkkitapaukset, entä IBM, Accenture jne.?

---------------------------------------------------------------------------------------------------

Kaikissa näissä on sensori-, tiedonsiirto-, pilvi- ja analytiikkateknologioiden halventuminen ollut keskeinen tekijä niiden tuonnissa kasvituotannon alalle, jossa suuri osa tuottajia on pienehköjä yrityksiä joilla on kaikille hankinnoille oltava selkeä liiketaloudellinen peruste. Läheskään aina ei vielä näin ole IoT-teknologioiden kanssa, vai?

Peltokasvituotannossa
ei todennäköisesti tulla viljelypäätöksien tekoa luovuttamaan tietojärjestelmien tehtäväksi, mutta integroitu ja yhdistetty FMS tai vastaava voisi antaa hyviä suosituksia, jotka voitaisiin lähettää työkoneille toteutettaviksi, joko urakoitsijalle tai omille koneille, jotka voivat nekin olla osa viljelijöiden keskinäistä "konekantaa" ja niiden käyttöä valvoisi älykäs Fleet Management System, joka osaisi puhua valmistajien huoltojen ja vastaavien kanssa.
Lisäksi olennainen osa järjestelmää -tai järjestelmien järjestelmää tai sitä seuraavaa ekosysteemiä (?)- on sen yhteys markkinoille, koko arvo- ja tuotantoketjuun ja muihin tuottajiin, koko kasvituotannon ekosysteemiin, mistä saadaan älykästä tietoa siihen mitä halutaan tuotannosta, milloin ja missä. Samoin voidaan antaa tarjolle arvoeriä. Miten tämä eroaa maanviljelyksen Alibabasta? Älykkäällä analysoinnilla, koneoppimisella ja optimoinnilla sekä sillä, että ihmiset eivät enää tekisi kauppaa keskenään, edes organisaatioiden edustajina vaan koneet tekevät sen automaattisesti, ihmisille jää korkeamman tason päätösten teko, luova ajattelu ja ohjaus.

Puutarhatuotannossa sama, mutta työkalut ovat itse puutarhoissa enemmän kiinteästi asennettuja tekniikkaratkaisuita kuin peltokasvituotannossa. ...

Kasvihuonetuotannossa
on tehdasmaisin, kiintein ja suojatuin ympäristö, johon on helpompi soveltaa teollisuuden kehittämiä ratkaisuita automatiikassa ja tietoverkoissa. ...

---------------------------------------------------------------------------------------------------

*Tämän voisi ehkä laittaa yhteenvetoon loppuun? Vai jaetaanko havainnot per kirj.katsaukset, paperit, muut, valmistajat, muut organisaatiot*
Kävi ilmi että:
	* Maatalouden ala -uusien teknologioiden omaksumisen ja käyttöönoton näkökulmasta- on pirstaleinen.
	* Kasvihuonetuotannossa on ollut kohtuullisen helppoa soveltaa teollisuuden muilla aloilla kehittämää valmista tuotantoautomatiikkaa ja käyttää vastaavia tietojärjestelmiä mallina.
    * Kasvihuonetuotannossa on voitu rakentaa yhden - kolmen toimittajan kehittämiä kokonaisratkaisuita koko tuotantoprosessin hallintaan.
	* Kasvihuonetuotannossa on myös ollut mahdollista soveltaa uutta teknologiaa ja kehittää kasvitehtaita, jotka toimivat pitkälle ympäristöstä eristettyinä.
    * Puutarhatuotannossa ollaan voitu soveltaa peltokasvituotantoa enemmän kiinteästi asennettavia laitteita sensoroinnissa, tiedonsiirrossa ja -käsittelyssä.
	* Peltoviljelyssä on ollut vaikeaa kehittää IoT-teknologioita käyttäviä tuotteita jotka toimisivat tarpeeksi laajassa käyttöympäristöjen ja olosuhteiden kirjossa, jotta tuote olisi kannattava ottaa käyttöön niin monelle viljelijälle että tuotetta kannattaisi kehittää.
	* Suuret maatalouskonevalmistajat ajattelivat pitkään, että omien IoT- ja IT-järjestelmien eristäminen omiksi siiloikseen, ns. walled garden -mallin mukaisesti, toisi heille enemmän liiketoimintaa kuin avoin malli, jossa tieto olisi vapaasti ja sovittujen yleisten standardien mukaan saatavilla ja käytettävissä.
	* Viime vuosina tämä ajatusmalli on ilmeisesti muuttunut ja on sanottu, että koko ala on huomannut, ettei yhden toimittajan ole mahdollista tuottaa yleiskäyttöistä järjestelmää, jolla kaikki maatilan toiminnot voitaisiin toteuttaa. Vastaava järjestelmä voidaan kyllä rakentaa tarkasti tyypitettyyn toimintaympäristöön jossa kaikki koneet on hankittu yhdeltä valmistajalta, mutta käytännössä tällainen tilanne on harvinainen.
    * ...

---------------------------------------------------------------------------------------------------