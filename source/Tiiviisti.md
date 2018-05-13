# JOHDANTO

*<13-05-2018  12:09> Tämä on nyt vain yleistä lätinää eikä mikään johdanto! Uusiks.*

Lähti liikkeelle kysymyksestä: "Sitä dataa ei siis saa siitä koneesta ulos?"
Tämä hämmästytti, joten asiaan tutustuttiin pintapuolisesti ja havaittiin, ettei mitään tiedetä mutta tilanne vaikuttaa mielenkiintoiselta: on tulossa uusia teknologioita ja toimintatapoja. Saman tien ei tullut esiin selkeää kokonaiskuvaa alan standardeista ja käytänteistä esineiden internetin (Internet of Things, IoT) käytössä, joten asiaa päätettiin tutkia tarkemmin. 
Lähtökohtaisesti määriteltiin IoT:n olevan järjestelmiä/ratkaisuita, joissa toteutui jatkuvasti kiertävä tiedon tuottamisen, siirtämisen, tallennuksen, analytiikan, päätöksenteon ja aktuoinnin/ohjaamisen/kontrolloinnin täysautomaattinen ketju ilman ihmisen puuttumista ja ohjausta prosessissa.

Aluksi tiedon hankkiminen oli hankalaa ja hyvät lähteet olivat harvassa. Käytetyn IoT-määrittelyn mukaisten ratkaisujen löytäminen alkoi vaikuttaa lähes mahdottomalta.  Ajan kuluessa, kontaktien karttuessa ja hakumenetelmiä opetellessa parempia lähteitä alkoi löytyä. Omat hakutulokset paranivat, kontakteilta saatiin hyviä lähteitä sekä hyviksi todettujen lähteiden viittauksien kautta löytyi yhä enemmän tietoa.
Kokonaiskuva alkoi hitaasti hahmottua samojen asioiden/analyysien/mielipiteiden tullessa vastaan useista eri lähteistä.
Aiheeseen tutustumisen jälkeen tehtiin systemaattisempi tiedonhaku löydettyjen kirjallisuuskatsausten pohjalta.

Kirjoittajan tietämyksen mukaan kasvintuotannossa käytettävistä IoT-ratkaisuista on viime vuosien (2010 - 2018) aikana julkaistu runsaasti tutkimuksia ja erilaisia artikkeleita. Kirjoittajalla ei ole kovin vahvaa ymmärrystä tai kokemusta maataloudessa käytettävistä IoT-ratkaisuista. Koska maatalouden esineiden internet (Agricultural Internet of Things, AIoT) on voimakkaasti kasvava teollisen esineiden internetin (Industrial Internet of Things, IIoT) osa **(LÄHDE???)** ja se voi vaikuttaa huomattavasti ruoantuotannon kehitykseen **(LÄHDE???)** tekijä arvioi, että AIoT:n tilanteesta kannattaa olla tietoinen. Lisäksi tekijä arvelee, että AIoT:n teknologiaratkaisuiden kehittämisessä tullaan tarvitsemaan asiantuntijoita joilla on sekä maatalouden että ICT-alan ymmärrystä.

## Yleisjohdanto (sis. Tavoitteet, tutkimusongelma, rajaus, käsitteet)

Maatalouteen kohdistuu jatkuvasti kovenevia tehokkuusvaatimuksia, samalla kun teknologinen kehitys mahdollistaa tehokkaampia viljelyprosesseja. Lisäksi maataloudelle ja ruokaturvalle asettaa haasteita ilmastonmuutos ja väestönkasvu. Näihin vaatimuksiin ja haasteisiin pyritään osaltaan vastaamaan digitalisoimalla maatalouden prosesseja kuin muilla teollisuuden aloilla.

*IIoT Industry 4.0:sta sivut 2-5*  *Sitten miten maatalous liittyy IIoT:hen*

"Ilmastonmuutos, ekosysteemipalvelujen heikkeneminen, resurssien niukkeneminen, ruoan ja energian lisääntyvä tarve, nopea sosiaalinen eriarvoistuminen, maahanmuutto ja ihmisten etääntyminen ruoan alkuperästä"
*(Evernote: Abstract: Hyvin sanottu! Parasta ruokaa - hyvää elämää)*
--Samalla kuluttajien vaatimukset lähiruoalle, läpinäkyvälle tuotantiketjulle ja luomulle-- lähde?

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

## Puutarhatuotanto-johdanto

Yleistä lätinää puutarhatuotannosta. Määrittely, luonne.

## Peltotuotanto-johdanto

Yleistä lätinää peltotuotannosta. Määrittely, luonne.

*Perustuen Joona Elovaaran "Aggregating OPC UA Server for Remote Access to Agricultural Work Machines" diplomityön osioon 1.1 Background:*
Työkoneiden kehityksen myötä maatilojen toiminnan hallinta on monimutkaistunut. Viljelijän tulee tehdä päätöksiä viljelytoimien laadusta, sisällöstä, ajankohdasta ja järjestyksestä ottaen samalla huomioon sekä ympäristönsuojelun että maataloustukien säädökset, lisäksi huolehtien liiketoiminnastaan ja tilansa työkoneista ja muusta infrastruktuurista. Tätä toimintaa ja päätöksentekoa tukemaan on kehitetty erilaisia tiedonhallinnan järjestelmiä, joita kutsutaan Farm Management Information System:eiksi (FMIS). (@elovaaraAggregatingOPCUA2015) FMIS on määritelmällisesti järjestelmä, joka kerää, käsittelee, tallentaa ja välittää dataa tiedon muodossa, jota tarvitaan maatilan operatiivisten toimintojen suorittamisessa **(Sørensen et al. 2010a)-Elsevier, ei pääsyä**.

Useimpien traktorien ja työkoneiden ollessa sähköisesti hallittuja ja niihin asennettujen sensorien tuottaessa dataa, voitaisiin tämä data kerätä ja jalostaa tiedoksi esimerkiksi koneiden huollosta, rikkoutumisista ja työsuorituksista. Tämän tiedon avulla voitaisiin parantaa täsmäviljelyn ja työkoneiden hallinnan käytänteitä.

# TEORIATAUSTA
## Kasvintuotanto


### Kasvintuotannon määrittely
### Kasvintuotannon historia (aiheeseen liittyen)
### Kasvintuotannon ...
## Internet of Things, esineiden internet
### IoTn määrittely
### IoTn historia
### Industrial Internet of Things, teollinen esineiden internet
### Agricultural Internet of Things, maatalouden esineiden internet
#### AIoT kasvintuotannossa
#### AIoT peltokasvituotannossa
#### AIoT puutarhatuotannossa (& muu kasvintuotanto)
# TUTKIMUS

Kuvaileva kirjallisuuskatsaus valittiin [metodin/tutkimusotteen?] mahdollistaessa:
1. Paitsi tieteellisten julkaisujen myös ammattilehtien, valmistajien omien julkaisujen ja muiden vastaavien aiheeseen liittyvien lähteiden käsittelyn.
2. Ilmiöihin liittyvien yhteyksien vapaan kuvailun ja haastatteluista saatujen tietojen kanssa dialogiin asettelun.

Koska opinnäytetyön tarkoituksena on tehdä laadullinen yleiskatsaus rajatulla työmäärällä,  yksilöteemahaastattelu valittiin metodin [?] mahdollistaessa:
1. Erilaisten informanttien haastattelun saman haastatteluprotokollan mukaan.
2. Kunkin informantin oman erityisosaamisen ja kokemusten käsittelyn.
3. Haastattelijan ja informantin keskinäisen yhteistyön ennen haastattelua sekä itse haastattelutilanteessa.

## Tutkimuksen tavoitteet
### Tutkimusongelmat

Tässä opinnäytetyössä tutkimusongelmana on jäsennellyn tiedon puute kasvintuotannon IoT-ratkaisuista. Tutkimusongelma pyritään ratkaisemaan etsimällä vastaukset tutkimuskysymyksiin. Vastauksia pyritään löytämään sekä kuvailevan kirjallisuuskatsauksen että teemahaastattelujen avulla.

### Tutkimuskysymykset

*tähän miten tutkimuskysymykset valittiin*

Tutkimuksessa haetaan vastauksia -kahteen- kolmeen tutkimuskysymykseen, jotka alakysymyksineen ovat:

*1. What are the main technological solutions of the Internet of Things in agro-industrial and environmental fields?*
*2. Which infrastructure and technology are using the main solutions of IoT in agro-industrial and environmental fields?*

I) Millaista tutkimusta IoT-teknologioiden soveltamisesta kasvintuotantoon on julkaistu?

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

Aineiston keruumenetelmiä oli useita. Varsinaista tutkimustyötä edelsi ilmiöön tutustuminen erilaisia keruumenetelmiä testattaessa, keräämällä kontakteja, käyden asiantuntijakeskusteluja, vierailemalla alan tapahtumissa ja haastatteluja tehden. Varsinaisen tutkimustyön aluksi haettiin IoT:tä yleistasolla ja ilmiönä käsittelevää kirjallisuutta. Seuraavaksi käytettiin sateenvarjokatsausta, jolla haettiin ilmiötä käsitteleviä kirjallisuuskatsauksia. Valittujen kirjallisuuskatsausten pohjalta muotoiltiin omat hakumetodit ja valittiin osa lähteistä. Omien hakumetodien tuloksista on valittu tekijän harkinnan mukaan aihetta parhaiten kuvaavat. Lisäksi ollaan käytetty aiheeseen tutustuttaessa löydettyjä lähteitä jos ne ovat tekijän harkinnan mukaan olleet tähdellisiä aiheen käsittelylle ja ymmärryksen luomiselle.

Tutkimuksen luotettavuutta pyritään parantamaan käyttämällä aineistotriangulaatiota: kirjallisuuskatsauksen tuloksia vertaillaan haastattelujen tuloksiin sekä tuodaan esille ammattijulkaisuissa, laitevalmistajien sekä muiden toimijoiden tiedotteissa, lehtiartikkeleissa jne. ilmestyneitä asiaan liittyviä asioita.

Lisäksi tutkimuksen luotettavuutta pyritään parantamaan luettamalla haastatteluista tehdyt johtopäätökset muistiinpanoineen haastateltavalla.

Haastattelujen litteroinnissa käytetään yleiskielistä litterointia. Yleiskielistä litterointia tarkempaa sanatarkkaa litterointia on käytetty, jos sanojen poistamisella litteroinnista on arvioitu olevan tarkoitusta mahdollisesti muuttava vaikutus.

Tutkimuksen alustavassa vaiheessa ilmiöön tutustuttaessa tehtiin useita hakuja aiheeseen liittyvillä asiasanoilla, selattiin erilaisten organisaatioiden ja julkaisujen verkkosivuja, haettiin asiantuntijakontakteja eri tapahtumista jne. Löydöt merkittiin muistiin mahdollista myöhempää käyttöä varten.

Haastateltavia etsittiin tapahtumista saatujen kontaktien, aineistosta löytyneiden asiantuntijoiden ja omien verkostojen kautta.  Lisäksi käytettiin "snowballing" -menetelmää, jossa keskusteluissa informanttia pyydettiin suosittelemaan muita asiantuntijoita haastateltaviksi tai muutoin kontaktoitaviksi.

### Kirjallisuuskatsaus *mallina KYAMK Lonka Karoliina: LAPSEN DIABETEKSEN... 2014*
#### Kirjallisuuskatsauksen vaiheet

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

*AIoT kirjallisuuskatsaukset*
*AIoT muut katsaukset ja vastaavat*
*AIoT tutkimukset, tieteelliset julkaisut -ovatko konferenssipaperit tieteellisiä julkaisuja?*
(*mahd. Harmaa kirjallisuus*)
*AIoT Järjestöt, organisaatiot esim. Luke ja IoF2020*
*AIoT Valmistajat, yhtiöt*
*AIoT muut julkaisut*

## Haastattelujen tulokset
## Haastatteluista saatujen tulosten vertailu kirjallisuuskatsauksen tuloksiin
## Tutkimuskysymyksien vastaukset
# POHDINTA
## Luotettavuus
## Hyödynnettävyys
# LÄHTEET
# LIITTEET







-tähän hakumenetelmät, valintaperusteet jne.

---------------------------------------------------------------------------------------------------

## Tiedon hankinta
Opinnäytetyön toteuttamisessa valittiin tutkimuskysymyksiin

...tietoa hankittiin yksilöteemahaastatteluilla ja kuvailevalla kirjallisuuskatsauksella.
 

---------------------------------------------------------------------------------------------------

## Kirjallisuuskatsaukset:

#### Talavera: Review of IoT applications in agro-industrial and environmental fields @talaveraReviewIoTApplications2017

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

### Verdouw: Internet of Things in agriculture @verdouwInternetThingsAgriculture2016a

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




---------------------------------------------------------------------------------------------------

*Tämän voisi ehkä laittaa yhteenvetoon loppuun? Vai jaetaanko havainnot per kirj.katsaukset, paperit, muut, valmistajat, muut organisaatiot*
Kävi ilmi että:
	* Maatalouden ala -uusien teknologioiden omaksumisen ja käyttöönoton näkökulmasta- on pirstaleinen.
	* Kasvihuonetuotannossa on ollut kohtuullisen helppoa soveltaa teollisuuden muilla aloilla kehittämää valmista tuotantoautomatiikkaa ja käyttää vastaavia tietojärjestelmiä mallina.
    * Kasvihuonetuotannossa on voitu rakentaa yhden - kolmen toimittajan kehittämiä kokonaisratkaisuita koko tuotantoprosessin hallintaan.
	* Kasvihuonetuotannossa on myös ollut mahdollista soveltaa uutta teknologiaa ja kehittää kasvitehtaita, jotka toimivat pitkälle ympäristöstä eristettyinä.
    * Puutarhatuotannossa ollaan voitu soveltaa peltotuotantoa enemmän kiinteästi asennettavia laitteita sensoroinnissa, tiedonsiirrossa ja -käsittelyssä.
	* Peltoviljelyssä on ollut vaikeaa kehittää IoT-teknologioita käyttäviä tuotteita jotka toimisivat tarpeeksi laajassa käyttöympäristöjen ja olosuhteiden kirjossa, jotta tuote olisi kannattava ottaa käyttöön niin monelle viljelijälle että tuotetta kannattaisi kehittää.
	* Suuret maatalouskonevalmistajat ajattelivat pitkään, että omien IoT- ja IT-järjestelmien eristäminen omiksi siiloikseen, ns. walled garden -mallin mukaisesti, toisi heille enemmän liiketoimintaa kuin avoin malli, jossa tieto olisi vapaasti ja sovittujen yleisten standardien mukaan saatavilla ja käytettävissä.
	* Viime vuosina tämä ajatusmalli on ilmeisesti muuttunut ja on sanottu, että koko ala on huomannut, ettei yhden toimittajan ole mahdollista tuottaa yleiskäyttöistä järjestelmää, jolla kaikki maatilan toiminnot voitaisiin toteuttaa. Vastaava järjestelmä voidaan kyllä rakentaa tarkasti tyypitettyyn toimintaympäristöön jossa kaikki koneet on hankittu yhdeltä valmistajalta, mutta käytännössä tällainen tilanne on harvinainen.
    * ...

---------------------------------------------------------------------------------------------------

Maatalous/kasvituotanto ja IoT ovat yhdistymisen alkuvaiheessa, vaikka kaikki tarvittavat teknologiat ovat jo saatavilla.
On sanottu (?) että ollaan maatalouden vallankumouksen reunalla. Vaikka tällä odotetulla vallankumouksella voi olla huomattavat vaikutukset ruoantuotantoon sekä koko arvo- ja tuotantoketjuun pellolta lautaselle asti, niin tekijällä ei ollut ennen työn aloitusta siitä minkäänlaista havaintoa. Teollisesta esineiden internetistä (Industrial Internet of Things, IIoT) on uutisoitu, mutta maatalouden esineiden internetistä ei ilmeisesti olla laajasti tietoisia. Tämä voi johtua siitä, että laajamittaista käyttöönottoa ei ole vielä tapahtunut ja näin ollen asiasta ei juuri uutisoida alan ulkopuolella.

Miksi tämä kasvintuotannon IoT on kiinnostava -ja ajankohtainen aihe?
Useissa lähteissä viitattu FAO:n raportti! Muut perusteet IoF2020.
Tällä teknologiakehityksellä voi olla todella merkittävät vaikutukset
-tähän haasteet ja saavutukset
-tähän yhteys IIoT:hen, IIoT:n saavutukset

Jotta lukija ymmärtäisi ilmiön kokonaisuudessaan, käydään lyhyesti läpi IoT:n, IIoT:n, AIoT:n ja kasvintuotannon historiaa.

---------------------------------------------------------------------------------------------------

-tähän IoT:n historia ja määritelmä

International Telecommunication Union, “Overview of the Internet of things,” Ser. Y Glob. Inf. infrastructure, internet Protoc. Asp. next-generation networks - Fram. Funct. Archit. Model., p. 22, 2012.
[Y.2060 : Overview of the Internet of things](https://www.itu.int/rec/T-REC-Y.2060-201206-I) 21.4.2018

International Telecommunication Union:in (ITU) suosituksen Y.2060 Overview of the Internet of things määrittelyn mukaan *IoT* on globaali tietoyhteiskunnan infrastruktuuri, joka mahdollistaa edistyneitä palveluita yhdistämällä (interconnecting) sekä fyysisiä että virtuaalisia esineitä (things); perustuen tieto- ja viestintäteknologioihin jotka ovat yhteentoimivia ja voivat olla joko olemassaolevia tai vasta kehittyviä. 

Lisäksi määrittelyssä on huomautettu, että:
1. IoT voi tarjota palveluita kaikenlaisille sovelluksille käyttämällä hyväkseen esineiden tunnistamisen, tiedon tuottamisen (data capture) ja käsittelyn antamia mahdollisuuksia; samalla varmistaen että tietoturvan ja yksityisyyden suojan asettamat vaatimukset täyttyvät.
2. IoT voidaan laajemmasta näkökulmasta katsoen nähdä visiona, jolla on sekä teknologisia että yhteiskunnallisia vaikutuksia.

Samassa suosituksessa IoT:n kontekstissa *laitteen* määrittelyssä on laitteella vähintään kyky kommunikaatioon ja mahdollisesti kyky havainnointiin (sensing), toimintaan (actuation), tiedon tuottamiseen, tallentamiseen ja käsittelyyn (capture, storage, processing).

Suosituksen määrittelyyn *esine*eksi  IoT:n kontekstissa on merkitty vaatimukset esineen fyysisestä tai virtuaalisesta olemassaolosta, tunnistettavuudesta ja integroitavuudesta tietoverkkoihin.

Tämän suosituksen määrittelyyn perustuen IoT koostuu sekä *laitteista* että *esineistä*, jotka yhdessä olevat tunnistettavia, integroitavissa tietoverkkoihin joiden ylitse ne pystyvät kommunikoimaan ja mahdollisesti  havainnoimaan ympäristöään (sensing), toimimaan (actuation) sekä tiedon tuottamiseen, tallentamiseen ja käsittelyyn (capture, storage, processing).


---------------------------------------------------------------------------------------------------

-tähän IIoT:n historia 

---------------------------------------------------------------------------------------------------

-tähän AIoT:n historia

---------------------------------------------------------------------------------------------------

-tähän kasvintuotannon/maatalouden vallankumoukset, miksi viimeisin "green revolution" on osoittautumassa kestämättömäksi (mahd. viittaus FAO-raporttiin ja muualle, tästä oli puhetta ööh jossain). Täsmäviljelyn kehitys ja vaatimukset sensoreille ja sitten datalle, analytiikalle, Farm Management System:eille
-tähän kuvaus kentän hajanaisuudesta, hankkeista, uudet ja vanhat toimijat

Miten nämä IoT ja kasvintuotanto tulevat yhteen?
IoT:n ja kasvintuotannon konvergenssi alkoi tapahtua teollisuusautomaation kehityksen myötä niin, että kasvihuoneiden automatiikassa voitiin ottaa käyttöön sensorien keräämän tiedon siirto tallennettavaksi. Tätä dataa voitiin sitten analysoida ja analyysien tuloksia ottaa käyttöön 

---------------------------------------------------------------------------------------------------
Motivaatio: Merkittävät vaikutukset ruoantuotannon koko arvoketjuun ja sitä kautta kaikkien elämään. Tästä ei kuitenkaan ole tietoa maatalouden alan ulkopuolella. Maataloudessa voi olla osaamisvaje IoT- ja IT-taidoista, kun maatalous digitalisoituu. Digitalisaation on sanottu etenevän ja muuttavan alan toimintaa räjähdysmäisesti, eikä hiljakseen. Tämä voi olla merkittävä työllistäjä lähivuosina IT-alan osaajille ja varsinkin IoT-erikoisosaajille.