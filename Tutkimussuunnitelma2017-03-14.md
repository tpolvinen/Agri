---
Title: TUTKIMUSSUUNNITELMA IoT-teknologioiden käytännön sovellukset kasvintuotannossa
Author: Tatu Polvinen
Tags: IoT, IIoT, AIoT, maatalous, kasvintuotanto, kasvitehdas
Category: IT
Date: 2017-03-15 22:45
Template: /pohja/pohja.docx
bibliography: /bib/MaatalousIoT.bib
csl: harvard1.csl
...


# Tiivistelmä

Kasvintuotannossa laajasti käytössä olevat digitaaliset teknologiaratkaisut ovat pitkään olleet korkeintaan M2M –periaatteella toimivia (Machine to Machine, laitteelta laitteelle) jolloin tuotettu raakadata jää yleensä esimerkiksi traktorin tai puimurin tietokoneelle. IoT –teknologioiden mahdollistaman laitteiden välisen tiedonsiirron, sensorien tuottaman raakadatan analysoinnin ja siitä saatavan tietämyksen hyödyntämisen nähdään yleisesti tuottavan huomattavaa lisäarvoa.

Tämän tutkimuksen tavoitteena on selvittää I) millaisia IoT –teknologioita (Internet of Things, esineiden internet) on sovellettu ja tutkittu kasvintuotannon alalla sekä II) millaisia kokemuksia ja näkemyksiä kasvintuotannossa toimivalla suomalaisella yrittäjällä on IoT –teknologioiden hyödyntämisestä ja mahdollisuuksista.

Tutkimus toteutetaan kahdella tutkimusmenetelmällä: kirjallisuuskatsauksena ja yksilöteemahaastatteluna. Kirjallisuuskatsauksessa perehdytään kasvintuotannossa käytettäviin IoT –teknologioihin joiden sovelluksista on saatavilla joko tutkimustietoa tai muuten luotettaviksi arvioitavia lehtiartikkeleja tai valmistajan tiedotteita. Yksilöteemahaastattelussa pyritään hahmottamaan millaisia henkilökohtaisia kokemuksia ja näkemyksiä IoT –teknologioiden hyödyntämisestä haastateltavalla maatalousalan toimijalla itsellään on.

Tutkimuksen toteutus ajoitetaan vuoden 2017 keväälle viikoille 13 – 21. Viikolla 21 tutkimussuunnitelma esitellään työpajassa jonka jälkeen toteutetaan haastattelu. Haastattelun jälkeen kirjoitetaan tutkimusraportti ja palautetaan se arvioitavaksi kesäkuun alussa.

Tutkimuksen tuloksia voidaan käyttää hyväksi tekijän myöhemmin toteutettavassa samasta tai sitä sivuavasta aiheesta kirjoitettavassa opinnäytetyössä.

# Johdanto
Maatalouden esineiden internet (Agriculture Internet of Things, AIoT) on teollisen esineiden internetin (Industrial Internet of Things, IIoT) merkittävänä osana viimeaikaisen edullisten ja tehokkaiden  pilvipalveluiden, sensori- ja verkkoteknologioiden kehityksen myötä mahdollistunut tavalla joka on saanut monet tahot ennustamaan ennennäkemätöntä tuottavuuden kasvua seuraavan vuosikymmenen aikana (@gilchrist2016industry, 2). Koska AIoT:tä pidetään yleisesti IIoT:n osana, käsittelen tässä työssä myös IIoT:tä soveltuvin osin.

Aineiston keräämisen alkuvaiheessa löytyi lehtiartikkeli, jossa G. Monbiot kirjoitti sensaatiomaiseen tyyliin YK:n julkaisemista laskelmista viljelysmaan eroosiosta. Artikkelissa hän väittää, että viljelyskelpoinen maa kulutetaan nykyisillä maata kuluttavilla viljelystekniikoilla loppuun keskimäärin maailmanlaajuisesti 60:ssä vuodessa, Englannissa saman lukeman ollessa 100 vuotta. (@monbiot_were_2015) Vaikka kyseinen lukujen tulkinta ja esitetyt väitteet osoittautuisivat tarkemmin tutkittaessa puutteellisiksi, tarve uusille ja tehokkaammille viljelytekniikoille on selkeä: kirjallisuuskatsauksessa "Internet of Things in agriculture" Verdouw et al. mainitsevat ruokaturvan kriittisyyden korostuvan lähivuosikymmeninä väestönkasvun ja kehittyvillä markkinoilla tapahtuvan elintason nousun myötä (@verdouw_internet_2016). Samoin FAO:n vuoden 2012 raportissa “World agriculture towards 2030/2050” arvioidaan vuoteen 2050 mennessä tarvittavien tuotannon kasvuksi 940 miljoonaa tonnia viljakasvien osalta (@alexandratos_n._world_2012, 17).

Lisäksi Verdouw et al. mainitsevat ruokaturvaa heikentävänä seikkana maapallon kantokyvyn ylittymisen nykyisin köytössä olevilla maatalouden tuotantomenetelmillä. Globaalin ruokaturvan ja ympäristönsuojelun erityisiksi haasteiksi he kuvaavat globalisaation, ilmastonmuutoksen, polttoaineperusteisesta bioperusteiseen talouteen siirtymisen sekä maan, makean veden ja työvoiman käytön kilpailun vaikutukset. IoT-teknologioiden odotetaan auttavan näihin haasteisiin vastaamisessa entistä tarkemmalla tuotannon ja tuotantoympäristön seuraamisella, tuotannon etäohjauksella, tuotteiden laadun tarkkailulla sekä kuluttajien ymmärryksen lisäämisellä. (@verdouw_internet_2016)

Erityisesti IoT-teknologioita hyödyntävää kasvintuotantoa toteutetaan kasvihuoneissa ja kasvitehtaina tunnetuissa laitoksissa, joissa täysin kontrolloiduissa olosuhteissa kasvatukseen käytettyjen resurssien kuten pinta-alan, lannoitteiden ja kasvuajan tehokkuus on saatu moninkertaistettua. Suomessa ollaan ottamassa kaupallista kasvitehdasta tuotantoon vuonna 2017 Fujitsu Greenhouse Technology Finland Oy:n ja Robbes Lilla Trädgård Ab:n yhteishakkeena @fujitsu_fujitsu_2016 @schafer_fujitsun_2016.

Tutkittavaksi ilmiöksi on näin materiaaliin tutustuttaessa muodostunut IoT-teknologioiden hyödyntäminen kasvintuotannossa viljelyn tehostamiseksi ja samalla viljelyn aiheuttaman ympäristökuormituksen minimoimiseksi. Uutta tietoa odotetaan syntyvän tässä tutkimuksessa vain vähän toteutettavassa yksilöteemahaastattelussa ja tutkimukseen käytettävissä olevan ajan rajallisuuden myötä, mutta tutkimuksen tuloksia voidaan käyttää apuna päätettäessä jatkotutkimuksen tarpeellisuudesta ja toteutuksen mahdollisuuksista.

# Teoriatausta
Tässä osassa käsitellään AIoT:n taustaa sekä sen käytännön sovelluksia ja tutkimustuloksia.

## Taustaa
FAO:n vuoden 2012 raportissa arvioidaan väestönkasvun myötä tarvittavan globaalin ruoantuotannon kasvun olevan saavutettavissa mutta vaativan investointeja. Raportissa käsiteltyjen Maailmanpankin ennusteiden mukaan köyhyys ei ole katoamassa maailmasta vuoteen 2050 mennessä vaan tuloerot maiden välillä tulevat olemaan huomattavat, jolloin ruoantuotantoon tehtävät investoinnit tulevat jakautumaan  epätasaisesti. (@alexandratos_n._world_2012, 37) Tämä puolestaan asettaa vaatimuksia kustannustehokkaampien viljelytekniikoiden kehittämiselle —erityisesti ilmastonmuutoksen todennäköisten vaikutusten vaikeuttaessa maanviljelyä suuressa osassa maailmaa. 

Ilmastonmuutoksen aiheuttama lämpötilojen nousu lisää kasteluntarvetta ja saattaa samalla rajoittaa kasteluveden saatavuutta. Tällöin tarvitaan entistä tarkempaa tietoa kastelun todellisesta tarpeesta sekä tarkempaa kastelun hallintaa — myös kotimaisessa kasvintuotannossa. Ruokakaupan jatkuvan hintakilpailun ja kasvavan luomuruoan kysynnän myötä on myös tarve kehittää viljelytekniikoita joilla voidaan säästää lannoituksessa ja saada silti enemmän irti samasta kasvatuspinta-alasta.

Täsmäviljelyn kehityksellä ollaan aikaisemmilla vuosikymmenillä saavutettu säästöjä lannoituksessa ja tehostettu viljelypinta-alan käyttöä. IoT-teknologioiden nähdään mahdollistavan täsmäviljelyn eteneminen ns. Smart Farming:iin, missä maatilasta muodostuu älykäs, keskenään toimivien laitteiden verkko. Tällöin voidaan yhdistää tosiaikainen sensorien tuottama havaintodata, datan automaattinen älykäs analysointi ja tuotantosuunnittelu sekä tuotantoprosessien kontrollointi. Täsmäviljelyn käyttöönotto ei ole kuitenkaan mainittavasti edennyt pienen innovatiivisen viljelijäjoukon ulkopuolelle ja täsmäviljelyssä tuotetun datan älykäs käyttö on edelleen hyvin vähäistä. (@verdouw_internet_2016) 

Valtiollisille toimijoille IIoT:n ja sen mukana AIoT:n kehityksen tukemisen nähdään olevan kannattavaa niiden mahdollistaessa tehokkaamman kotimaisen tuotannon. Tämän tehokkuuden lisäyksen ennustetaan kääntävän halvempien tuotantokustannusten maihin kohdistuvan teollisen tuotannon ulkoistamisen trendin. Lisäksi tehostuneen tuotannon ennustetaan johtavan ennennäkemättömään taloudellisen kasvuun seuraavan vuosikymmenen aikana. (@gilchrist2016industry, 2, 222) 

Elinkeinoelämän tutkimuslaitoksen (ETLA) raportissa Suomalaisen teollisen internetin taustoista kerrotaan Valtioneuvoston kanslian (VNK) nimenneen teollisen internetin yhdeksi kärkiteemoistaan (@juhanko_suomalainen_2015, 3). Hallituksen kärkihankkeeseen “Digitaalisen liiketoiminnan kasvuympäristön rakentaminen” ensimmäisenä toimenpiteenä on “Edistetään esineiden internetiä” (@berner_karkihanke_2016, 2). 

Tämän kärkihankkeen vaikutuksia suomalaisella maataloussektorilla käsitellään tarkemmin Kimmo Tammen opinnäytetyössä Digitalisaatio maatalouden B2B-liiketoiminnassa, missä kerrotaan hallitusohjelman huomioivan entistä datalähtöisempien toimintatapojen kehittämisen, tukien hakemisen helppouden sekä erilaiset kokeiluhankkeet rahoituksineen uusien liiketoimintamallien kehittämisessä. (@tammi_digitalisaatio_2016, 17)

Suomessa IoT -teknologioiden hyödyntämiseen suuntautuvia tuotteita ja palveluita on tarjolla ainakin Telialla @telia_iot-ratkaisut_2017 ja Digitalla @digita_iot-ratkaisut_2017, joiden tarjoamat tietoliikenneratkaisut ovat sovitettu IoT -teknologioiden vaatimuksiin. Molemmat toimijat kannustavat asiakkaitaan kehittämään uusia IoT -ratkaisuita ja tarjoavat niiden tueksi laajaa osaamistaan ja tietoliikenneverkkoaan. Laitteiden väliset verkkoyhteydet ovat haasteellisia monissa peltokasvintuotannon IoT -hankkeissa, mikä tekee tarjotuista palveluista mielenkiintoisia niiden tarjoaman kattavan langattoman tietoliikenneverkon takia. Kattava verkko mahdollistaa ja helpottaa myös osaltaan kokeiluhankkeiden kasvua prototyypeistä tuotantojärjestelmiksi.

Verkkoyhteydet kuvaillaan "Internet of Things in agriculture"-kirjallisuuskatsauksessa myös yhtenä kolmesta IoT-arkkitehtuurien tasoista, muiden tasojen ollessa laitetaso sekä sovelustaso. Laitetasolla tapahtuvan sensorien, havaintolaitteiden ja ohjattavien laitteiden käyttöön tarvittavan verkkoliikenteen tapahtuessa verkkotasolla, lopuksi kokonaisuuden hallinnan ja tiedon analysoinnin tapahtuessa vastaavasti sovellustasolla. Katsauksessa eritellään myös AIoT:n tulevaisuuden haasteiksi hyvin erilaisten laitteiden yhteiskäytettävyys, tosielämän käytön skaalautuminen aikaisten omaksujien joukon ulkopuolelle, teknologiaratkaisujen kehittäminen sopimaan toimialan erityistarpeisiin sekä oikeiden käyttöympäristöjen olosuhteisiin, luotettavien verkkoyhteyksien toiminnan varmistaminen myös etäisillä käyttöpaikoilla, energiatehokkaiden IoT-teknologioiden kehittäminen, kolmannen osapuolen tuottaman datan yhdistäminen data-analytiikkaan ja luotettavien tietoturvapalveluiden sekä datan omistajuuden varmistavien palveluiden kehittäminen. (@verdouw_internet_2016) 


## AIoT:n käytännön sovelluksia ja tutkimustuloksia
Tässä osassa käsitellään AIoT:n teknologiasovelluksia peltokasvituotannossa ja puutarhatuotannossa.


### AIoT-täsmäviljely peltokasvituotannossa
AIoT-täsmäviljelyn kokeiluhankkeilla ollaan yleiseti saavutettu hyviä kokemuksia. Erityisesti parantuneen resurssienhallinnan myötä käyttöönoton kustannukset saadaan yleensä katettua kohtuullisessa ajassa. Kokeiluhankkeet ovat edistäneet täsmäviljelyn sovelluksia niin pitkälle, että monet viljelijät ovat voineet ottaa ne laajamittaiseen käyttöön omassa tuotannossaan. (@buyya2016internet, 137) Tärkeä osa peltokasvituotannon tehostamista on traktorien automaattiohjaus, joka tehostaa käytetyn peltopinta-alan käyttöä (@dubravac2015digital, 133). 

Samankaltaisista hyvistä kokemuksista sekä viljelytekniikoiden tehostamisesta automatisoinnilla kerrotaan lyhyesti Luonnonvarakeskuksen tiedotteessa jonka mukaan traktorin automaattiohjauksen avulla on saatu peltopinta-ala tehokkaampaan käyttöön ja kuljettajan työtaakkaa kevennettyä (@luonnonvarakeskus_asiakkaan_2015). Samankaltaista työnjaosta mainitaan kirjassa "Industry 4.0: The Industrial Internet of Things", jossa tutkijoiden hahmottelemassa tulevaisuudenkuvassa ihmisten työtä ei ole korvattu robottien tekemällä työllä vaan ihmisten ja robottien yhteistyöllä (@gilchrist2016industry, 11). 

Yksi sovellus peltokasvituotannossa sovellettavista AIoT-teknologioista on J. Tiusasen väitöskirjassa “Langattoman Peltotiedustelijan maanalainen toimintaympäristö ja laitesuunnittelu” kehitetty peltoon kaivettavien langattomien sensorilaitteiden toteutus jota testattiin käytössä vuoden ajan (@tiusanen_langattoman_2008, 4).  Tämän kaltainen ratkaisu mahdollistaa maaperän tilan jatkuvan tarkkailun ilman erikseen tehtävää näytteidenottoa. Peltotiedustelijan kaupallinen sovellus on julkaistu PocketVenture -joukkorahoitusalustalla rahoitettavaksi @skelly_soil_2015.

Toisenlainen jo laajassa käytössä oleva ratkaisu pellon maaperän tutkimiseen on maaperän EM-skannaus esim. Veris Technologies:in kehittämillä laitteilla. Skannaus tehdään ennen kasvukautta pellon maaperän koostumuksen selvittämiseksi ja skannauksessa tuotettua tietoa voidaan käyttää hyödyksi lannoituksen ja kastelun suunnittelussa, mutta mittauksia ei voida tehdä kesken kasvukautta sen vaatiessa ajoa työkoneella pellon yli @veris_technologies_what_2017.

Kirjallisuuskatsauksessa "Internet of Things in agriculture" peltotuotantoa (arable farming) käsittelevistä tutkimuksista suurin osa käsitteli kasvatusympäristön tarkkailua ja säätelyä edistyneiden IoT-laitteiden avulla. Toinen merkittävä aihealue oli yleinen informaation kerääminen pelloista kolmannen aihealuuen ollessa ennakoivat kasvumallit. Näitä lähestymismalleja käyttäen tutkittiin erityisen usein ekologiaan, luonnon monimuotoisuuteen ja luonnonvaroihin kuten veteen liittyviä aiheita. (@verdouw_internet_2016)

### AIoT-täsmäviljely puutarhatuotannossa
Peltokasvituotantoa paremmin IoT-teknologioiden käyttöönottoon on soveltunut puutarhatuotanto, jonka toimintaympäristöissä sensoreita voidaan asentaa helpommin ja jossa ympäristö on usein tarkemmin kontrolloitua kuin avoimilla pelloilla kuten kasvihuoneissa. Puutarhakasvien tuotannossa markkinahintainen tuotto viljelypinta-alaa kohti on huomattavasti suurempi kuin peltokasvituotannon vastaava (@pajula_selvitys_2003, 36).  Tästä voi päätellä, että automatisoidulla ja tarkemmin hallitulla resurssien käytöllä voidaan saavuttaa kilpailuetua erityisesti puutarhatuotannossa.

Puutarhatuotannossa selkeitä esimerkkejä uusien teknologioiden hyödyntämisestä ovat automatisoidut kasvihuoneet sekä ns. kasvitehtaat, joissa kasvien kasvatus tapahtuu mahdollisimman tarkasti kontrolloidussa ympäristössä ja yleensä keinovalossa. Luonteeltaan kasvitehtaat vastaavatkin yleistä käsitystä tehtaasta automaatiolinjoineen ja tarkkoine hallintalaitteineen ja ne sopivatkin tuotantoon tiheästi asutuissa kaupungeissa, joissa on pulaa viljelysmaasta mutta tarpeeksi kysyntää ruokakasveille investointien kattamiseksi. Esimerkkinä tällaisistä kasvihuonetoteutuksesta on New Yorkissa toimiva Gotham Greens:in suomalaisen Green Automationin kasvatustekniikalla toimiva kasvihuone (@ohrnberg_30-kertainen_2016-1) (@ohrnberg_suomalaistekniikka_2016).

Näissä laitoksissa maatalouden esineiden internetin ja teollisuuden esineiden internetin käsitteiden raja on käytännössä hävinnyt. Kasvitehtaista on rakennettu monenlaisia prototyyppilaitoksia, joista yksi tunnettu esimerkki on avoimen lähdekoodin periaatteella toimiva MIT Media Lab:issa (Massachusetts Institute of Technology) alkunsa saanut MIT Open Agriculture Initiative (OpenAG):n päätuote “Food Computer” jonka kehitys alkoi osana MIT City FARM projektia. Termillä “Food Computer” tarkoitetaan kasvitehtaan omaista tietokoneohjattua ja kasvatusympäristöä jossa kasvien kasvua tarkkaillaan hyvin tarkasti. Kasvatusympäristön ominaisuuksia kuten hiilidioksidin määrää ilmassa, ilman lämpötilaa, sähkönjohtavuutta, kosteutta, juurialueiden lämpötilaa ja liuenneen hapen määrää voidaan tarkkailla ja säätää. Lisäksi kasteluveden / ravinneliuoksen tasoa, energian ja mineraalien kulutusta tarkkaillaan erilaisilla sensoreilla ja mittareilla. Mikä tahansa käyttökelpoiseksi havaittu ympäristömuuttujien yhdistelmä voidaan ottaa ns. kasvureseptiksi/ilmastoreseptiksi (climate recipe) tietylle kasville ja jakaa vapaasti käytettäväksi internetissä. Asiasta kiinnostuneille on tarjolla kirjasto standardireseptejä joita kasvattaja voi muunnella omiin tarpeisiinsa sopiviksi. (@goyal_hydrobase:_2016, 22)

"Internet of Things in agriculture"-kirjallisuuskatsauksen viittaamista tutkimuksista kasvihuonetuotannon osalta suurin osa käsittelee kasvuympäristön tarkkailua ja säätelyä, samaan tapaan kuin peltotuotannon alueella. Muita tutkimusaiheita olivat kasvihuoneen hallintajärjestelmät, energiankulutuksen hallinta ja Big Data. (@verdouw_internet_2016)

Kokonaan kasvitehtaisiin keskittyneessä kirjallisuuskatsauksessa "Editorial: Advances and Trends in Development of Plant Factories" käsitellään uusia tutkimustrendejä kuten älykkäitä kasvatusympäristön mittausjärjestelmiä, kasvatusympäristön hallintaa ja optimointia, lääkeaineiden tuotantoa, geenitekniikkaa ja bakteerilannoitteita. Näistä selkeimmin IoT-teknologioihin perustuvat mittausjärjestelmät sekä kasvuympäristön hallinta ja optiminti, joista useissa tutkimuksissa ollaan saavutettu hyviä tuloksia erilaisilla valon hallinnan keinoilla. Tutkimuksissa ollaan kokeiltu muun muassa valon vuorokausirytmitystä, valaisun suuntaamista kasveihin myös kasvin alapuolelta, valon aallonpituuden säätelyä ja eri aallonpituudellisten valojen rytmitystä. Lisäksi on tutkittu yhdenväristen (monochromic) LEDien valaisun, korkean hiilidioksidipitoisuuden ja voimakkaan lannoittamisen yhdistelmää kasvatusympäristössä.
(@luna-maldonado_editorial:_2016)

Materiaalia etsittäessä on löytynyt pääasiassa uutisartikkelien kautta muutamia mielenkiintoisia kaupallisia toimijoita. Aiemmin mainittua MIT:n “Food Computer”:ia vastaavan kaltaisia kaupallisia tuotteita on tullut markkinoille useampien kasvuyritysten kuten Freight Farm:in @freight_farms_leafy_2017 ja Square Roots:in @square_roots_square_2017 toimesta. Näiden yritysten tuotteet ovat kontteihin rakennettuja pienikokoisia kasvitehtaita. Samantyyppisiä teknologiaratkaisuja myyvän ZipGrow:n tuotteet taas voidaan asentaa kasvihuoneisiin tai muihin sopiviin tiloihin @bright_agrotech_appropriate_2017. Suuremmassa teollisessa mittakaavassa toimivat mm. amerikkalainen AeroFarms @aerofarms_aerofarms_2017 sekä japanilaiset Spread @spread_spread_2017 ja Mirai @mirai_mirai_2017, jotka operoivat suuria kasvitehtaita. Belgialainen Urban Crop taas toimii teknologiatuottajana, joka tarjoaa ratkaisuja sekä kontteihin rakennettaviin että tehdaskokoisiin kasvitehtaisiin @urban_crop_solutions_urban_2017. 

Suomalainen esimerkki tällaisesta kehityksestä on lapinjärveläisen Robbe’s Lilla Trädgård Oy:n ja Fujitsu Greenhouse Technology Finland Oy:n yhteishankkeena toteuttama kasvitehdas @fujitsu_fujitsu_2016 @schafer_fujitsun_2016, josta uutisoitiin mm. Maaseudun tulevaisuus -lehden verkkosivuilla @ala-siurua_fujitsu_2016 @schafer_fujitsun_2016. 

Aamulehden jutussa ‘Erikoistutkija vesiviljelystä: “Kasvitehdasbuumi käy maailmalla kuumana”’ kasvitehdas -konseptia tutkinut erikoistutkija, dosentti Kari Jokinen kertoo “Kasvitehdasbuumi käy maailmalla kuumana. Japanissa on satakunta tehdasta. Mittakaava on maaseudun isoista laitoksia tokiolaisen ravintolan omaan salaattituotantoon.” @suojanen_erikoistutkija_2016.

# Tutkimuksen tavoitteet
Tässä osiossa kuvaillaan tutkimusongelmat ja työhypoteesit.

## Tutkimusongelmat
Tutkimuksessa haetaan vastauksia kahteen tutkimusongelmaan, jotka alaongelmineen ovat:
I) Miten kasvintuotannossa hyödynnetään IoT-teknologioita?
	* Miten peltotuotannon ja puutarhatuotannon erot vaikuttavat IoT -teknologioiden sovelluksiin?
    * Minkä tyyppiset sovellukset tulevat tutkimusmateriaalissa selkeimmin esille, eli millaisista sovelluksista ja teknologioista kirjoitetaan ja tehdään tutkimusta tällä hetkellä?
	
II) Millaisia IoT-teknologioita haastateltavalla toimijalla on joko käytettävissään tai millaisista hän on tietoinen?
	* Mitä vaikutuksia niillä on tuotantoon ja/tai työntekoon?
    * Millaisia kokemuksia niistä haastateltavalla on?
    * Millaisia muita sovelluksia haastateltava tuntee tai tietää?
    * Millainen käsitys haastateltavalla on edelllä mainituista sovelluksista (sekä käyttämistään että tietämistään)?
    * Millaisia toiveita tai tarpeita haastateltavalla on IoT-teknologioille?

## Työhypoteesit:
Tutkimusongelman I vastaukseksi odotetaan saatvaksi teoriaosuudessa käytettyjen materiaalien mukaisen kuvailun.
Tutkimusongelman II vastaukseksi odotetaan saatavaksi aikaisempien keskustelujen perusteella vastaukseksi Valtran tuotevalikoiman mukaisia teknologiaratkaisuita, joissa hyödynnetään ainakin automaattiohjausta ja maaperän rakenteen kartoitusta viljelyn suunnittelussa. Todennäköistä on, että näillä teknologioilla saavutetut hyödyt ovat linjassa teoriaosuudessa käsiteltyjen löydösten kanssa. Epävarmaa on voidaanko työkoneista saada tietoa analysoitavaksi ja hyödynnettäväksi muualla eli voidaanko niitä edes pitää IoT-teknologioina. Ei ole tiedossa, millaisia tarpeita tai toiveita haastateltava on tiedostanut IoT-teknologioita kohtaan.

# Tutkimusmenetelmät
Tutkimusmenetelmiksi on valittu kummallekin tutkimusongelmalle omansa niiden soveltuvuuden perusteella:
Tutkimusongelma I:een perehdytään kirjallisuuskatsauksella ja tutkimusongelma II:een yksilöteemahaastattelulla.

Kirjallisuuskatsaus soveltuu jo olemassaolevasta materiaalista kokonaiskuvan ja yleisten ominaisuuksien hahmottamiseen ja raportointiin, kun taas yksilöteemahaastattelulla voidaan kohtuulisen vapaamuotoisesti hahmottaa kuva sekä haastateltavan yleisitä kokemuksista että tarkemmin tutkimuksen aiheeseen liittyvistä seikoista.

# Tutkimusaikataulu
Tutkimusaikataulu suunniteltiin aluksi etenemään kurssin viikko-ohjelman puitteissa. Haastateltava joutui kevätkylvöjen aiheuttamien kiireiden takia lykkäämään haastattelua lopuksi useilla viikoilla toukokuun lopulle, joten kurssin työpajassa esitellään tämä tutkimussuunnitelma ja tutkimusraportti palautetaan arvioitavaksi myöhemmin.


# Tuloksen hyväksikäyttömahdollisuudet
Tutkimustuloksia ja tutkimuksen aikana kertyneitä kokemuksia voidaan hyödyntää arvioitaessa aiheen soveltuvuutta tekijän opinnäytetyön aiheeksi. 

Jatkotutkimukselle on todennäköisesti löydetyn materiaalin laajuuden ja AIoT:n mielenkiintoisen kehitysvaiheen perusteella tarvetta ja motivaatio, mutta tutkimuksen rajaus ja tutkimuksen sovittaminen koulutusohjelmaan tavoitteisiin tulee tehdä huolella.

# Lähteet
