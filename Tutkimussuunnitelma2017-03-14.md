---
Title: IoT-teknologioiden käytännön sovellukset kasvintuotannossa
Author: Tatu Polvinen
Tags: IoT, IIoT, AIoT, maatalous, kasvintuotanto, kasvitehdas
Category: IT
Date: 2017-03-15 22:45
Template: /pohja/pohja.docx
bibliography: /bib/MaatalousIoT.bib
csl: harvard1.csl
...

# TUTKIMUSSUUNNITELMA
# IoT-teknologioiden käytännön sovellukset kasvintuotannossa
## Kansilehti
## Tiivistelmä
Kasvintuotannossa laajasti käytössä olevat digitaaliset teknologiaratkaisut ovat pitkään olleet korkeintaan M2M –periaatteella toimivia (Machine to Machine, laitteelta laitteelle) jolloin tuotettu raakadata jää yleensä esimerkiksi traktorin tai puimurin tietokoneelle. IoT –teknologioiden mahdollistaman laitteiden välisen tiedonsiirron ja sensorien tuottaman raakadatan analysoinnin ja hyödyntämisen nähdään yleisesti tuottavan huomattavaa lisäarvoa - paitsi viljelijälle parantuneina satoina ja tuotannon tehokkuutena - myös koko arvoketjulle tuotannosta kuluttajille asti.

Tämän tutkimuksen tavoitteena on selvittää I) millaisia IoT –teknologioita (Internet of Things, esineiden internet) on sovellettu ja tutkittu kasvintuotannon alalla sekä II) millaisia kokemuksia ja näkemyksiä kasvintuotannossa toimivalla suomalaisella yrittäjällä on IoT –teknologioiden hyödyntämisestä ja mahdollisuuksista.

Tutkimus toteutetaan kahdella tutkimusmenetelmällä: kirjallisuuskatsauksena ja yksilöteemahaastatteluna. Kirjallisuuskatsauksessa perehdytään kasvintuotannossa käytettäviin IoT –teknologioihin joiden sovelluksista on saatavilla joko tutkimustietoa tai muuten luotettaviksi arvioitavia lehtiartikkeleja tai valmistajan tiedotteita. Yksilöteemahaastattelussa pyritään hahmottamaan millaisia henkilökohtaisia kokemuksia ja näkemyksiä IoT –teknologioiden hyödyntämisestä haastateltavalla maatalousalan toimijalla itsellään on.

Tutkimuksen toteutus ajoitetaan vuoden 2017 keväälle viikoille 13 – 19, jonka jälkeen se esitetään työpajassa viikolla 21.

Tutkimuksen tuloksia voidaan käyttää hyväksi tekijän myöhemmin toteutettavassa samasta tai sitä sivuavasta aiheesta kirjoitettavassa opinnäytetyössä.

## Johdanto
Maatalouden esineiden internet (Agriculture Internet of Things, AIoT) on teollisen esineiden internetin (Industrial Internet of Things, IIoT) merkittävänä osana viimeaikaisen edullisten ja tehokkaiden  pilvipalveluiden, sensori- ja verkkoteknologioiden kehityksen myötä mahdollistunut tavalla joka on saanut monet tahot ennustamaan ennennäkemätöntä tuottavuuden kasvua seuraavan vuosikymmenen aikana (@gilchrist2016industry, 2). Koska AIoT:tä pidetään yleisesti IIoT:n osana, käsittelen tässä työssä myös IIoT:tä soveltuvin osin.

Globaalissa mittakaavassa tuottavuuden kasvun yhdistyessä kasvintuotantoon kohdistuvien vaatimuksien kasvuun väestön lisääntyessä ja ilmastonmuutoksen edetessä AIoT -teknologioiden kehittämistä ja käyttöönottoa voisi omasta mielestäni pitää jopa kriittisen tärkeänä ihmisten hyvinvoinnille. Aineiston keräämisen alkuvaiheessa huomioni kiinnitti lehtiartikkeli, jossa G. Monbiot kirjoitti sensaatiomaiseen tyyliin YK:n julkaisemista laskelmista viljelysmaan eroosiosta. Artikkelissa hän väittää, että viljelyskelpoinen maa kulutetaan nykyisillä maata kuluttavilla viljelystekniikoilla loppuun keskimäärin maailmanlaajuisesti 60:ssä vuodessa, Englannissa saman lukeman ollessa 100 vuotta. (@monbiot_were_2015) Vaikka kyseinen lukujen tulkinta ja esitetyt väitteet osoittautuisivat tarkemmin tutkittaessa puutteellisiksi, tarve uusille ja tehokkaammille viljelytekniikoille on mielestäni selkeä: FAO:n vuoden 2012 raportissa “World agriculture towards 2030/2050” arvioidaan vuoteen 2050 mennessä tarvittavien tuotannon kasvuksi 940 miljoonaa tonnia viljakasvien osalta (@alexandratos_n._world_2012, 17).

Erityisesti viljelytekniikoissa IoT-teknologioita hyödyntävää kasvintuotantoa toteutetaan kasvihuoneissa ja kasvitehtaina tunnetuissa laitoksissa, joissa täysin kontrolloiduissa olosuhteissa käytetty pinta-ala, lannoitteet ja kasvuaika on tehokkuudeltaan saatu moninkertaistettua. Suomessa ollaan ottamassa kaupallista kasvitehdasta tuotantoon vuonna 2017 Fujitsu Greenhouse Technology Finland Oy:n ja Robbes Lilla Trädgård Ab:n yhteishakkeena @_fujitsu_2016 @_fujitsun_2016.

Tutkittavaksi ilmiöksi on näin materiaaliin tutustuttaessa muodostunut IoT-teknologioiden hyödyntäminen kasvintuotannossa viljelyn tehostamiseksi ja samalla viljelyn aiheuttaman ympäristökuormituksen minimoimiseksi. IoT-teknologioiden käytöstä pyritään tuomaan esille keskeisimmät edut, havaitut erityiset piirteet sekä käyttöönoton esteet ja ongelmat. Uutta tietoa odotetaan syntyvän tässä tutkimuksessa vain vähän tehtävässä yksilöteemahaastattelussa ja käytettävissä olevan ajan rajallisuuden myötä, mutta tutkimuksen tuloksia voidaan käyttää apuna päätettäessä jatkotutkimuksen tarpeellisuudesta ja toteutuksen mahdollisuuksista.

## Teoriatausta
### Taustaa
FAO:n vuoden 2012 raportissa arvioidaan väestönkasvun myötä tarvittavan globaalin ruoantuotannon kasvun olevan saavutettavissa mutta vaativan investointeja. Raportissa käsiteltyjen Maailmanpankin ennusteiden mukaan köyhyys ei ole katoamassa maailmasta vuoteen 2050 mennessä vaan tuloerot maiden välillä tulevat olemaan huomattavat, jolloin ruoantuotantoon tehtävät investoinnit tulevat jakautumaan  epätasaisesti. (@alexandratos_n._world_2012, 37) Tämä puolestaan asettaa vaatimuksia kustannustehokkaampien viljelytekniikoiden kehittämiselle —erityisesti ilmastonmuutoksen todennäköisten vaikutusten vaikeuttaessa maanviljelyä suuressa osassa maailmaa. 

Ilmastonmuutoksen aiheuttama lämpötilojen nousu lisää kasteluntarvetta mutta saattaa samalla rajoittaa kasteluveden saatavuutta, jolloin tarvitaan entistä tarkempaa tietoa kastelun todellisesta tarpeesta sekä tarkempaa kastelun hallintaa — myös kotimaisessa kasvintuotannossa. Ruokakaupan jatkuvan hintakilpailun ja kasvavan luomuruoan kysynnän myötä on myös tarve kehittää viljelytekniikoita joilla voidaan säästää lannoituksessa ja saada silti enemmän irti samasta kasvatuspinta-alasta.

Valtiollisille toimijoille IIoT:n ja sen mukana AIoT:n kehityksen tukemisen nähdään olevan kannattavaa niiden mahdollistaessa tehokkaamman kotimaisen tuotannon. Tämän tehokkuuden lisäyksen ennustetaan kääntävän halvempien tuotantokustannusten maihin kohdistuvan teollisen tuotannon ulkoistamisen. Lisäksi tehostuneen tuotannon ennustetaan johtavan ennennäkemättömään taloudellisen kasvuun seuraavan vuosikymmenen aikana. (@gilchrist2016industry, 2, 222) 

Elinkeinoelämän tutkimuslaitoksen (ETLA) raportissa Suomalaisen teollisen internetin taustoista kerrotaan Valtioneuvoston kanslian (VNK) nimenneen teollisen internetin yhdeksi kärkiteemoistaan (@juhanko_suomalainen_2015, 3). Hallituksen kärkihankkeeseen “Digitaalisen liiketoiminnan kasvuympäristön rakentaminen” ensimmäisenä toimenpiteenä on “Edistetään esineiden internetiä” (@_karkihanke_2016, 2). 

Tämän kärkihankkeen vaikutuksia suomalaisella maataloussektorilla käsitellään tarkemmin Kimmo Tammen opinnäytetyössä Digitalisaatio maatalouden B2B-liiketoiminnassa, missä kerrotaan hallitusohjelman huomioivan entistä datalähtöisempien toimintatapojen kehittämisen, tukien hakemisen helppouden sekä erilaiset kokeiluhankkeet rahoituksineen uusien liiketoimintamallien kehittämisessä. (@tammi_digitalisaatio_2016, 17)

Suomessa valtiollisten toimijoiden lisäksi IoT -teknologioiden hyödyntämiseen suuntautuvia tuotteita ja palveluita on tarjolla ainakin Soneralla @_iot-ratkaisut_2017 ja Digitalla @_internet_2017, joiden tarjoamat tietoliikenneratkaisut ovat sovitettu IoT -teknologioiden vaatimuksiin. Molemmat toimijat kannustavat asiakkaitaan kehittämään uusia IoT -ratkaisuita ja tarjoavat niiden tueksi laajaa osaamistaan ja tietoliikenneverkkoaan. Juuri verkkoyhteydet ovat haasteellisia monissa peltokasvintuotannon IoT -hankkeissa, mikä tekee tarjotuista palveluista mielenkiintoisia niiden tarjoaman kattavan langattoman tietoliikenneverkon takia. Kattava verkko mahdollistaa ja helpottaa osaltaan kokeiluhankkeiden kasvua prototyypeistä tuotantojärjestelmiksi.

### Käytännön sovelluksia ja tutkimustuloksia
#### Täsmäviljely peltokasvituotannossa
Täsmäviljelyn kokeiluhankkeilla ollaan yleiseti saavutettu hyviä kokemuksia. Erityisesti parantuneen resurssienhallinnan myötä käyttöönoton kustannukset saadaan yleensä katettua kohtuullisessa ajassa. Kokeiluhankkeet ovat edistäneet täsmäviljelyn sovelluksia niin pitkälle, että monet viljelijät ovat voineet ottaa ne laajamittaiseen käyttöön omassa tuotannossaan. /@buyya2016internet, 137) Tärkeä osa peltokasvituotannon tehostamista on traktorien automaattiohjaus, joka tehostaa käytetyn peltopinta-alan käyttöä (@dubravac2015digital, 133). 

Samankaltaisista hyvistä kokemuksista sekä viljelytekniikoiden tehostamisesta automatisoinnilla kerrotaan lyhyesti Luonnonvarakeskuksen tiedotteessa jonka mukaan traktorin automaattiohjauksen avulla on saatu peltopinta-ala tehokkaampaan käyttöön ja kuljettajan työtaakkaa kevennettyä (@luonnonvarakeskus_asiakkaan_2015). Samankaltaista työnjaosta mainitaan kirjassa "Industry 4.0: The Industrial Internet of Things", jossa tutkijoiden hahmottelemassa tulevaisuudenkuvassa ihmisten työtä ei ole korvattu robottien tekemällä työllä vaan ihmisten ja robottien yhteistyöllä (@gilchrist2016industry, 11). 

Peltokasvituotannossa sovellettavista mittausteknologioista on aineistoa kerättäessä löytynyt J. Tiusasen väitöskirja “Langattoman Peltotiedustelijan maanalainen toimintaympäristö ja laitesuunnittelu”, jossa kehitettiin peltoon kaivettavien langattomien sensorilaitteiden käytännön toteutus ja testattiin niitä vuoden ajan (@tiusanen_langattoman_2008, 4).  Tämän kaltainen ratkaisu mahdollistaa maaperän tilan jatkuvan tarkkailun ilman erikseen tehtävää näytteidenottoa. Peltotiedustelijan kaupallinen sovellus on julkaistu PocketVenture -joukkorahoitusalustalla rahoitettavaksi @_soil_2015.

Toisenlainen jo laajassa käytössä oleva ratkaisu pellon maaperän tutkimiseen on maaperän EM-skannaus esim. Veris Technologies:in kehittämillä laitteilla. Skannaus tehdään ennen kasvukautta pellon maaperän koostumuksen selvittämiseksi ja skannauksessa tuotettua tietoa voidaan käyttää hyödyksi lannoituksen ja kastelun suunnittelussa, mutta mittauksia ei voida tehdä kesken kasvukautta sen vaatiessa ajoa työkoneella pellon yli @_what_2017.

#### Täsmäviljely puutarhatuotannossa
Peltokasvituotantoa paremmin IoT-teknologioiden käyttöönottoon on soveltunut puutarhatuotanto, jonka toimintaympäristöissä sensoreita voidaan asentaa helpommin ja jossa ympäristö on usein tarkemmin kontrolloitua kuin avoimilla pelloilla, esimerkiksi kasvihuoneissa. Puutarhakasvien tuotannossa 
markkinahintainen tuotto viljelypinta-alaa kohti on huomattavasti suurempi kuin peltokasvituotannon vastaava (@pajula_selvitys_2003, 36).  Tästä voi päätellä, että automatisoidulla ja tarkemmin hallitulla kastelulla sekä lannoituksella voidaan saavuttaa kilpailuetua.  

Puutarhatuotannossa selkeitä esimerkkejä uusien teknologioiden hyödyntämisestä ovat automatisoidut kasvihuoneet sekä ns. kasvitehtaat, joissa kasvien kasvatus tapahtuu mahdollisimman tarkasti kontrolloidussa ympäristössä ja yleensä keinovalossa. Luonteeltaan kasvitehtaat vastaavatkin yleistä käsitystä tehtaasta automaatiolinjoineen ja tarkkoine hallintalaitteineen ja ne sopivatkin tuotantoon tiheästi asutuissa kaupungeissa joissa on pulaa viljelysmaasta mutta tarpeeksi kysyntää ruokakasveille energiankulutuksen hinnan kattamiseksi. Esimerkkinä tällaisistä kasvihuonetoteutuksesta on New Yorkissa toimiva Gotham Greens:in suomalaisen Green Automationin kasvatustekniikalla toimiva kasvihuone (@ohrnberg_30-kertainen_2016-1) (@ohrnberg_suomalaistekniikka_2016).

Näissä laitoksissa maatalouden esineiden internetin ja teollisuuden esineiden internetin käsitteiden raja on mielestäni käytännössä hävinnyt. Kasvitehtaista on rakennettu monenlaisia prototyyppilaitoksia, joista yksi tunnettu esimerkki on avoimen lähdekoodin periaatteella toimiva MIT Media Lab:issa (Massachusetts Institute of Technology) alkunsa saanut MIT Open Agriculture Initiative (OpenAG):n päätuote “Food Computer” jonka kehitys alkoi osana MIT City FARM projektia. Termillä “Food Computer” tarkoitetaan kasvitehtaan omaista tietokoneohjattua ja kasvatusympäristöä jossa kasvien kasvua tarkkaillaan hyvin tarkasti. Kasvatusympäristön ominaisuuksia kuten hiilidioksidin määrää ilmassa, ilman lämpötilaa, sähkönjohtavuutta, kosteutta, juurialueiden lämpötilaa ja liuenneen hapen määrää voidaan tarkkailla ja säätää. Lisäksi kasteluveden / ravinneliuoksen tasoa, energian ja mineraalien kulutusta tarkkaillaan erilaisilla sensoreilla ja mittareilla. Mikä tahansa käyttökelpoiseksi havaittu ympäristömuuttujien yhdistelmä voidaan ottaa ns. kasvureseptiksi/ilmastoreseptiksi (climate recipe) tietylle kasville ja jakaa vapaasti käytettäväksi internetissä. Asiasta kiinnostuneille on tarjolla kirjasto standardireseptejä joita kasvattaja voi muunnella omiin tarpeisiinsa sopiviksi. (@goyal_hydrobase:_2016, 22)

#### Kasvitehtaiden kaupallisia sovelluksia
Materiaalia etsittäessä on löytynyt uutisartikkelien kautta muutamia mielenkiintoisia kaupallisia toimijoita. Aiemmin mainittua MIT:n “Food Computer”:ia vastaavan kaltaisia kaupallisia tuotteita on tullut markkinoille useampien kasvuyritysten toimesta, esimerkkinä Freight Farm @_leafy_2017 ja Square Roots @_square_2017. Näiden yritysten tuotteet ovat kontteihin rakennettuja pienikokoisia kasvitehtaita. Samantyyppisiä teknologiaratkaisuja myyvän ZipGrow:n tuotteet taas voidaan asentaa kasvihuoneisiin tai muihin sopiviin tiloihin @_appropriate_2017. Suuremmassa teollisessa mittakaavassa toimivat mm. amerikkalainen AeroFarms @_aerofarms_2017 sekä japanilaiset Spread @_spread_2017 ja Mirai @_mirai_2017, jotka operoivat suuria kasvitehtaita. Belgialainen Urban Crop taas toimii teknologiatuottajana, joka tarjoaa ratkaisuja sekä kontteihin rakennettaviin että tehdaskokoisiin kasvitehtaisiin @_urban_2017. Muita saman kaltaisia toimijoita on tullut jatkuvasti esille aineistoa etsittäessä ja vaikuttaa siltä, että kasvitehtaat tulevat nousemaan puutarhatuotannossa perinteisen kasvihuoneviljelyn rinnalle. 

Suomalainen esimerkki tällaisesta kehityksestä on lapinjärveläisen Robbe’s Lilla Trägård Oy:n ja Fujitsu Greenhouse Technology Finland Oy:n yhteishankkeena toteuttama kasvitehdas @_fujitsu_2016 @_fujitsun_2016, josta uutisoitiin mm. Maaseudun tulevaisuus -lehden verkkosivuilla @_fujitsu_2016-1 @_fujitsun_2016. 

Aamulehden jutussa ‘Erikoistutkija vesiviljelystä: “Kasvitehdasbuumi käy maailmalla kuumana”’ kasvitehdas -konseptia tutkinut erikoistutkija, dosentti Kari Jokinen kertoo “Kasvitehdasbuumi käy maailmalla kuumana. Japanissa on satakunta tehdasta. Mittakaava on maaseudun isoista laitoksia tokiolaisen ravintolan omaan salaattituotantoon.” @_erikoistutkija_2016.

#### Uusia teknologiasovelluksia kirjallisuuskatsauksista
Koska AIoT:n tutkimuskenttä on hyvin laaja ja uusia tutkimuksia erilaisista teknologiasovelluksista julkaistaan jatkuvasti, olen valinnut alustavasti kaksi kirjallisuuskatsausta läpikäytäviksi tässä suunnitelmassa kuvaillun teoriataustan lisäksi. Katsausten viittaamiin tutkimuksiin ei ole tutkimussuunnitelman kirjoittamisen aikana tutustuttu kunnolla, mutta nopealla silmäilyllä niistä löytyy useita mielenkiintoisia aiheita joita voidaan hyödyntää teoriataustan tarkentamisessa ja syventämisessä yleistasolta spesifisiin sovelluksiin.

Kirjallisuuskatsaukset ovat “Agricultural crop monitoring using IOT - a study” @_agricultural_2017 jonka sisältämiä viitteitä voidaan käyttää peltokasvituotannon sovellusten keräämiseen sekä “Editorial: Advances and Trends in Development of Plant Factories” @luna-maldonado_editorial:_2016 joka nimensä mukaisesti keskittyy kasvitehtaiden teknologiasovelluksien tutkimuksiin. Esimerkkinä jälkimmäisestä kirjallisuuskatsauksesta poimin kaksi mielenkiintoni herättänyttä tutkimusta:
“Plant Weight Measurement -Chen et al. developed an automated measurement system to measure and record the plant weight during plant growth in plant factory. They found that plant weights measured by the weight measurement device are highly correlated with the weights estimated by the stereo-vision imaging system” sekä:
“Growth Prediction CF -Moriyuki and Fukuda devised a novel high-throughput diagnosis system using the measurement of chlorophyll fluorescence forming an image of 7200 seedlings acquired by a CCD camera and an automatic transferring machine. They used machine learning in order to extract biological indices and predict plant growth”.

## Tutkimuksen tavoitteet
### Tutkimusongelmat
Tutkimuksessa haetaan vastauksia kahteen tutkimusongelmaan, jotka alaongelmineen ovat:
I) Miten kasvintuotannossa hyödynnetään IoT-teknologioita?
	* Miten peltotuotannon ja puutarhatuotannon erot vaikuttavat IoT -teknologioiden sovelluksiin?
	
II) Millaisia IoT-teknologioita haastateltavalla toimijalla on käytettävissään?
	* Mitä vaikutuksia niillä on tuotantoon ja/tai työntekoon?

### Työhypoteesit:
Tutkimusongelman I vastaukseksi odotan saavani teoriaosuudessa käytettyjen materiaalien mukaisen kuvailun.
Tutkimusongelman II vastaukseksi odotan saavani aikaisempien keskustelujen perusteella vastaukseksi Valtran tuotevalikoiman mukaisia teknologiaratkaisuita, joissa hyödynnetään ainakin automaattiohjausta ja maaperän rakenteen kartoitusta viljelyn suunnittelussa. Todennäköistä on, että näillä teknologioilla saavutetut hyödyt ovat linjassa teoriaosuudessa käsiteltyjen löydösten kanssa. Epävarmaa on voidaanko työkoneista saada tietoa analysoitavaksi ja hyödynnettäväksi muualla eli voidaanko niitä edes pitää IoT-teknologioina.

## Tutkimusmenetelmät
Tutkimusmenetelmiksi on valittu kummallekin tutkimusongelmalle omansa niiden soveltuvuuden perusteella:
Tutkimusongelma I:een perehdytään kirjallisuuskatsauksella ja tutkimusongelma II:een yksilöteemahaastattelulla.

Kirjallisuuskatsaus soveltuu jo olemassaolevasta materiaalista kokonaiskuvan ja yleisten ominaisuuksien hahmottamiseen ja raportointiin, kun taas yksilöteemahaastattelulla voidaan kohtuulisen vapaamuotoisesti hahmottaa kuva sekä haastateltavan yleisitä kokemuksista että tarkemmin tutkimuksen aiheeseen liittyvistä seikoista.

## Tutkimusaikataulu
Tutkimusaikataulu etenee kurssin viikko-ohjelman puitteissa. Jokaiselle vaiheelle on annettu kaksi viikkoa limittäin edellisten ja jälkeisten tehtävien kanssa aikataulun joustavuuden ylläpitämiseksi.
Aineiston keräämisen tehtävät toteutusjärjestetyksessä ovat:
Viikot 13 ja14
1	Teoriataustassa käytetyn materiaalin läpikäynti analyyseineen
2	Analyysin ja kerätyn tiedon pohjalta haastattelukysymyksien ja -teeman muodostaminen
Viikot 14 ja15
3	Haastattelun järjestäminen
4	Haastattelu
5	Haastattelun tulosten kirjaaminen ja analysointi
Viikot 15 ja 16
6	Tulosten ja johtopäätösten kirjoittaminen
Viikot 16 ja 17
7	Raportin kirjoittaminen, visualisointi

## Tuloksen hyväksikäyttömahdollisuudet
Tutkimustuloksia ja tutkimuksen aikana kertyneitä kokemuksia voidaan hyödyntää arvioitaessa aiheen soveltuvuutta tekijän opinnäytetyön aiheeksi. 

Jatkotutkimukselle on todennäköisesti löydetyn materiaalin laajuuden ja AIoT:n mielenkiintoisen kehitysvaiheen perusteella tarvetta ja motivaatio, mutta tutkimuksen rajaus ja tutkimuksen sovittaminen koulutusohjelmaan tavoitteisiin tulee tehdä huolella.

## Lähdeluettelo
