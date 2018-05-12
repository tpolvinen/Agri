<12-05-2018  11:14>

Iso tarina:
Lähti liikkeelle kysymyksestä: "Sitä dataa ei siis saa siitä koneesta ulos?"
Tämä hämmästytti, joten asiaan tutustuttiin pintapuolisesti ja havaittiin, ettei mitään tiedetä mutta tilanne vaikuttaa mielenkiintoiselta: on tulossa uusia teknologioita ja toimintatapoja. Saman tien ei tullut esiin selkeää kokonaiskuvaa alan standardeista ja käytänteistä esineiden internetin (Internet of Things, IoT) käytössä, joten asiaa päätettiin tutkia tarkemmin. 
Lähtökohtaisesti määriteltiin IoT:n olevan järjestelmiä/ratkaisuita, joissa toteutui jatkuvasti kiertävä tiedon tuottamisen, siirtämisen, tallennuksen, analytiikan, päätöksenteon ja aktuoinnin/ohjaamisen/kontrolloinnin täysautomaattinen ketju ilman ihmisen puuttumista ja ohjausta prosessissa.

-tähän miten tutkimuskysymykset valittiin

Aluksi tiedon hankkiminen oli hankalaa ja hyvät lähteet olivat harvassa. Käytetyn IoT-määrittelyn mukaisten ratkaisujen löytäminen alkoi vaikuttaa lähes mahdottomalta.  Ajan kuluessa, kontaktien karttuessa ja hakumenetelmiä opetellessa parempia lähteitä alkoi löytyä. Omat hakutulokset paranivat, kontakteilta saatiin hyviä lähteitä sekä hyviksi todettujen lähteiden viittauksien kautta löytyi yhä enemmän tietoa.
Kokonaiskuva alkoi hitaasti hahmottua samojen asioiden/analyysien/mielipiteiden tullessa vastaan useista eri lähteistä.
Aiheeseen tutustumisen jälkeen tehtiin systemaattisempi tiedonhaku löydettyjen kirjallisuuskatsausten pohjalta.

-tähän hakumenetelmät, valintaperusteet jne.

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

Maatalous/kasvituotanto ja IoT ovat yhdistymisen alkuvaiheessa, vaikka kaikki tarvittavat teknologiat ovat jo saatavilla.
On sanottu (?) että ollaan maatalouden vallankumouksen reunalla. Vaikka tällä odotetulla vallankumouksella voi olla huomattavat vaikutukset ruoantuotantoon sekä koko arvo- ja tuotantoketjuun pellolta lautaselle asti, niin tekijällä ei ollut ennen työn aloitusta siitä minkäänlaista havaintoa. Teollisesta esineiden internetistä (Industrial Internet of Things, IIoT) on uutisoitu, mutta maatalouden esineiden internetistä ei ilmeisesti olla laajasti tietoisia. Tämä voi johtua siitä, että laajamittaista käyttöönottoa ei ole vielä tapahtunut ja näin ollen asiasta ei juuri uutisoida alan ulkopuolella.

Miksi tämä kasvintuotannon IoT on kiinnostava -ja ajankohtainen aihe?
Useissa lähteissä viitattu FAO:n raportti! Muut perusteet IoF2020.
Tällä teknologiakehityksellä voi olla todella merkittävät vaikutukset
-tähän haasteet ja saavutukset
-tähän yhteys IIoT:hen, IIoT:n saavutukset

Jotta lukija ymmärtäisi ilmiön kokonaisuudessaan, käydään lyhyesti läpi IoT:n, IIoT:n, AIoT:n ja kasvintuotannon historiaa.

-tähän IoT:n historia
-tähän IIoT:n historia 
-tähän AIoT:n historia
-tähän kasvintuotannon/maatalouden vallankumoukset, miksi viimeisin "green revolution" on osoittautumassa kestämättömäksi (mahd. viittaus FAO-raporttiin ja muualle, tästä oli puhetta ööh jossain). Täsmäviljelyn kehitys ja vaatimukset sensoreille ja sitten datalle, analytiikalle, Farm Management System:eille
-tähän kuvaus kentän hajanaisuudesta, hankkeista, uudet ja vanhat toimijat

Miten nämä IoT ja kasvintuotanto tulevat yhteen?
IoT:n ja kasvintuotannon konvergenssi alkoi tapahtua teollisuusautomaation kehityksen myötä niin, että kasvihuoneiden automatiikassa voitiin ottaa käyttöön sensorien keräämän tiedon siirto tallennettavaksi. Tätä dataa voitiin sitten analysoida ja analyysien tuloksia ottaa käyttöön 

---------------------------------------------------------------------------------------------------
Motivaatio: Merkittävät vaikutukset ruoantuotannon koko arvoketjuun ja sitä kautta kaikkien elämään. Tästä ei kuitenkaan ole tietoa maatalouden alan ulkopuolella. Maataloudessa voi olla osaamisvaje IoT- ja IT-taidoista, kun maatalous digitalisoituu. Digitalisaation on sanottu etenevän ja muuttavan alan toimintaa räjähdysmäisesti, eikä hiljakseen. Tämä voi olla merkittävä työllistäjä lähivuosina IT-alan osaajille ja varsinkin IoT-erikoisosaajille.