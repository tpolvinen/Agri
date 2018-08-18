# Tsounis 2017: Internet of Things in agriculture, recent advances and future challenges

@tzounisInternetThingsAgriculture2017

## Abstract

Ruoalle asetettujen vaatimusten kasvu sekä määrässä että laadussa lisää tarvetta maataloustuotannon tehostamiseen ja teollistamiseen.
IoT on hyvin lupaava "teknologiaperhe" jossa on ratkaisuja maataloustuotannon modernisointiin.
Niin teollisuus kuin tutkimusryhmät ja tiedeinstituutiot kilpailevat IoT-tuotteden tuottamisessa markkinoille, tavoitellen rooleja IoTn tulevaisuuden toimijoina.
**tietotekniikan resurssipalvelut** (pilvipalvelut, cloud computing) ja sumutietojenkäsittely (fog computing) tarjoavat riittäviä resursseja sekä ratkaisuja ylläpitää, varastoida ja analysoida valtavia datamääriä, joita IoT-laitteet tuottavat. Tämän Big Datan hallinnointi ja analyysin avulla voidaan automatisoida prosesseja, ennakoida tilanteita ja parantaa toimintojen suorituksia.
Yhteentoimivuuden konsepti heterogeenisten laitteiden kesken inspiroi uusien työkalujen luontia, joilla voidaan kehittää uusia sovelluksia ja palveluita, tuottaen lisäarvoa verkon reunalla tuotetuille datavirroille.
Langattomien sensoriverkkojen kehitys on vaikuttanut huomattavasti maatalouteen. Maatalouden odotetaan hyötyvän myös IoT:stä.

## Introduction and motivation

Kevin Ashton 1999 teki tunnetuksi termin IoT
IoT-paradigma tuottaa teknologiauniversiumin, jossa esineitä (sensorit, käyttöesineet, työkalut ja välineet) parannellaan laskuteholla ja verkkoyhteyksillä/liitettävyydellä.
Nämä esineet voivat toimia yksittäisiä yksiköinä tai osana heterogeenisten laitteiden parvea.
Tällä odotetaan olevan huomattava vaikutus maatalouteen.
FAOn ennuste "global population will reach 8 billion people by 2025 and 9.6 billion people by 2050 (FAO, 2009)."
Väestönkasvu ja laadukkaiden tuotteiden kysyntä tuottavat tarpeen maatalouden tehostamiselle ja modernisoinnille.
Samalla veden ja muiden resurssien käytön tehokkuudelle kohdistuu entistä kovempia vaatimuksia.

**Täsmäviljely** on yksi lupaavimpia konsepteja, jonka odotetaan vaikuttavan merkittävästi ruoantuotannon lisääntymiseen kestävällä tavalla *(Zhang, Wang, & Wang, 2002)*.
Täsmäviljely pyrkii viljelyprosessien parantamiseen ja optimointiin. Täsmäviljely tarvitsee nopeita, luotettavia, hajautettuja mittauksia voidakseen tuottaa viljelijälle tarkan kuvan viljelyalueen tilanteesta.
Lisäksi voidaan koordinoida automatisoitua laitteistoa energiankulutuksen ja tuotantopanosten kuten kasvinsuojeluaineiden ja lannoitteiden käytön optimoinnissa.
Monista heterogeenisista järjestelmistä kerätyn datan analytiikan avulla voidaan parantaa automatiikan toimintaa kasvien tilan perusteella, muodostaa parempia näkemyksiä meneillään olevasta viljelyprosessista, arvioida nykyistä tilannetta sekä tuottaa ennusteita heterogeenisista lähteistä tuotetun mitatun tiedon perusteella *(Kacira, Sase, Okushima, & Ling, 2005; Korner € & Van Straten, 2008)*.
Hajautetun datan käsittelyyn tarvittavien algoritmien tosiaikainen ajaminen vaatii huomattavasti enemmän laskentatehoa kuin matalatehoisten langattomien sensoriverkkojen yhtymäkohdan (node) laitteissa on yleensä saatavilla. IoT-laitteiden ollessa kytkettyinä verkkoon voidaan lasketatehoa vaativat toiminnot siirtää verkon yli resurssipalveluun tai jakaa useiden kytkettyjen laitteiden suoritettaviksi.

Asiasanan IoT esiintyminen kansainvälisessä tutkimuksessa Agriculture-asiasanan yhteydessä selkeästi kasvissa määrin ilmaisee kasvavaa kiinnostusta ilmiötä kohtaan.

Vuosi 2010 valittiin tarkasteltavan aikavälin aluksi, koska silloin ilmestyi huomattava määrä asiaa käsiteleviä julkaisuja.
Lisäksi vuoden 2010 aikaisemmat teknologiat ja lähestymistavat ovat tätä kirjoitettaessa jo vanhentuneita.

Aluksi käsitellään viimeisimpiä teknologioiden trendejä, jotka edustavat IoT:n *building blocks*, kuten RFID, langattomat sensoriverkot, esineisiin viittaaminen verkossa sekä resurssipalvelussa toimivat sovellukset.

Samaa luokkittelua seuraten käsitellään useita julkaisuja jotka edustavat yhtä tai useampaa IoT:n olennaista osaa ja jotka keskittyvät maatalouden sektoriin.

Samoin esitellään joitain yleisimmistä laitealustoista, joita on käytetty maatalouden sovelluksissa.


## Internet of Things enabling technologies

IoT:ssä on kolme tasoa: "the perception layer (sensing), the network layer (data transfer), and the application layer (data storage and manipulation)."

IoT on vielä kehittyvä, lopullista muotoaan etsivä.

Internet on ollut enimmäkseen ihmisten käyttämä, mutta IoT tulee olemaan enimmäkseen laitteiden käytössä, M2M.

### Layer 1: the perception layer

Tuotantoprosessien tarkkailun lisäksi tarvitaan tuotantoketjussa tuotteiden seurantaa ja tarkkailua. Useissa julkaisuissa on käsitelty WSN-sovelluksia varastojen tarkkailua ja ilmastointia. RFID-tunnistimilla on tärkeä rooli maatalouden alalla, jossa yleisimmät käyttötapaukset ovat eläinten tarkkailu, tuotantoketjun ja laaduntarkkailu sekä maataloustuotteiden elinkaaren arviointi *(Welbourne et al., 2009)*.

### Layer 2: the network layer

Langattomat anturi/sensorilaitteet vuorovaikuttavat fyysisten esineiden ja/tai ympäristönsä kanssa, kommunikoivat läheisten laitteiden, verkon solmukohtien tai yhdyskäytävien kanssa rakentaen verkkoja joiden avulla data yleensä siirretään etäiseen palveluun tallennusta, analyysiä, käsittelyä ja tiedon välittämistä varten.

"When it comes to wireless communications, a large scientific literature has been created on sensor networks, addressing several problems, such as energy efficiency, networking features, scalability and robustness (Atzori et al., 2010)."

Anturiverkoista on julkaistu huomattava määrä tutkimusta, jossa on käsitelty anturiverkkojen haasteita kuten energiatehokkuutta, erilaisten tietoverkkojen ominaisuuksia, skaalautuvuutta ja vahvuutta *(Atzori et al., 2010)*.

Protokollat kuten ZigBee, ONE-NET, Sigfox, WirelessHART, ISA100.11a, 6LowPan

### Layer 3: the application layer

IoT:n sovellustasolla on useita avoimia haasteita: laitteiden uniikit tunnisteet. Tunniste, luotettavuus, pysyvyys ja skaalautuvuus edustavat tärkeitä tunnisteskeeman ominaisuuksia *(Gubbi et al., 2013)* IPv6:n odotetaan tuovan ratkaisuita joihinkin laitteiden tunnistuksen ongelmiin ja sen odotetaan näyttelevän tärkeää roolia tässä osassa *(Botta et al., 2014)*.

Heterogeenisyys on IoT:n merkittävä haaste. IoT-visiossa samassa "inter-verkossa" toimii kaikilta ominaisuuksiltaan erilaisia laitteita.

**Väliohjelmistojen** taso (middleware) laitetason ja sovellustason välillä abstraktoi laitteiden toiminnallisuuksia ja teknisiä erityispiirteitä/ominaisuuksia, tarjoten kehittäjille geneerisempiä työkaluja sovellusten rakentamiseen.

Väliohjelmistotaso on saanut paljon huomiota juuri uusien sovellusten kehittämisen yksinkertaistajan roolinsa takia, myös vanhojen teknologioiden integroinnin uusiin takia *(Atzori et al., 2010)*. 

Väliohjelmistotaso yhdistää resurssipalveluiden infratsruktuurin palveluorientoituneen arkkitehtuurin (SOA) sekä sensoriverkkojen kanssa geneerisellä tavalla.

Väliohjelmistotaso mahdollistaa palveluiden toteutuksissa teknologiariippumattomana sekä ohjelmistojen että laitteiden uudelleenkäytön *(Pasley, 2005)*.

Tulevaisuudessa maatalouden kytketyt laitteet voivat sisältää sensoreita, liitettyjä koneita ja ajoneuvoja, sääasemia, internet-yhdyskäytäviä, verkkotallennusjärjestelmiä, RFID-skannereita, älypuhelimia, tabletteja, päälle puettavia laitteita jne.

Tuotettu tieto tulee tallentaa, analysoida, syntetisoida ja esittää ymmärrettävällä ja intuitiivisella tavalla.

Vain verkon resurssipalveluilla on kapasiteettia käsitellä IoT:n tuottamia datamääriä.

Moderneissa maatalouden skenaarioissa tallennettu data automaattisesti käsitellään, tarkastetaan ja käytetään tai yhdistetään keinoälyn algoritmien avulla, koneoppimisen teknologioilla, mallinnusta hyödyntävillä päätöksentekojärjestelmillä, tietämyksen jalostamiseksi tarkasteltavasta ilmiöstä jota ei voida mitata suoraan. Nämä järjestelmät voivat ehdottaa optimaalista toimintamallia loppukäyttäjälle, tuottaa sopivia komentosignaaleja toimilaitteille, tarjoten täysautomatisoituja havaisemisen ja kontrolloinnin ratkaisuita.

Useat tutkimukset ovat keskittyneet IoT:n keskeisten teknologioiden standardointiin. Perinteinen anturiverkon paradigma (hajautetut älykkäät laitteet, jotka anturoivat ympäristöään ja lähettävät dataa tallennettavaksi ja/tai ohjaavat toimilaitteita) on kehittymässä kohti laitteiden ja esineiden yhteentoimivuutta.

IoT:n muihin osiin kuuluvat teknologiat, jotka tukevat laitteiden ja/tai käyttäjien välistä viestintää, alustapalvelut, ohjelmistot, laiteabstraktiot ja ohjelmistokehityksen työkalut *(Atzori et al., 2010; Miorandi et al., 2012)*.  

## Internet of Things hardware, platforms and sensors in agriculture

### Low-power wireless sensor networks

IoT:n potentiaaliset sovellukset voidaan jakaa per *Barcelo-Ordinas, Chanet, Hou, & Garcia-Vidal (2016)* 1) "scalar sensors" joita käytetään maatalouden infrastruktuurin tarkkailussa ja kontrolloinnissa, esimerkiksi kasvihuoneissa sekä anturiverkoissa hyönteisten ja kasvitautien havaitsemiseksi; 2) tunnisteperustaisiin verkkoihin, joilla pyritään tuotteden seuraamiseen ja etätunnistamiseen.

Maataloudessa erityisesti ympäristön vaikutukset langattomaan verkkoon WSN-ratkaisuissa tulee ottaa huomioon. Kasvit tai muut esteet vaikuttavat huomattavasti verkon toimintaan.
Samoin lämpötila, kosteus, sade, auringon voimakas säteily, kasvien lehtien varjostus, myös ympäristössä tehtävät työt kuten rakentaminen vaikuttavat viestinnän laatuun *(Wang, Yang, & Mao, 2017)*.

Maataloudessa tarkkailtavien/mitattavien ilmiöiden jaksottainen luonne vaikuttaa sovellusten kehitykseen.

### Widely used sensors and platform characteristics for agricultural Internet of Things/Wireless Sensor Network deployments 

Realististen WSN/langattomien anturiverkkojen käyttöönotto on huomattavan haasteellista, huolimatta niihin liittyvien useiden teoreettisten seikkojen tutkimuksesta kirjallisuudessa.

Ympäristötekijät voivat aiheuttaa virheellisiä mittauksia tai tuhota sensorin.

Virtalähteiden uusiminen voi olla hajautetuissa järjestelmissä vaikeaa, jolloin virrankulutus rajoittaa laitevalintoja ja energiatehokkuus tulee aina ottaa huomioon suunnittelussa.

Vikaantumisten välttämiseksi kentällä sulautettujen järjestelmien ohjelmakoodi tulee olla laadukasta ja se vaatii syvää ohjelmointiosaamista ja tarpeeksi läpikotaista/perusteellista testausta *(Barrenetxea, Ingelrest, Schaefer, & Vetterli, 2008; Langendoen, Baggio, & Visser, 2006)*.

### Wireless communication protocols in agriculture

Kuten monien muiden IoT:n aspektien yhteydessä, yhteentoimivuus on suurin haaste.

Toinen langattoman tietoliikenteen yleinen haaste on keskenään samoilla taajuuskaistoilla toimivien laitteiden toisilleen aiheuttamat häiriöt. 

Langattoman tietoliikenteessä käytettävät useat erilaiset teknologiat ja standardit haittaavat yhteentoimivuutta tietoliikennetasolla.

Maatalouden käyttöönotoissa korkeat lämpötilat ja kosteus ovat yleisiä.
Lämpötilan on osoitettu vaikuttavan huomattavalla tavalla vastaanotetun signaalin voimakkuuteen, kun lämpötila nousee 25 °C:sta 65 °C:een *(Bannister, Giorgetti, and Gupta, 2008)*.
Kosteuden on osoitettu vaikuttavan voimakkaasti radioaaltojen etenemiseen *(Room & Tate, 2007; Thelen, 2004)*.

Solmukohtien määrä, niiden välinen etäisyys, antennien korkeus ja toimintataajuus on tärkeää ottaa huomioon langattomien tietoliikenneverkkojen suunnittelussa maatalouden sovelluksissa.


## Applications in agriculture

Perinteisen viljelyn kehittyminen täsmäviljelyyn on vaikuttanut erityisesti viimeaikainen kehitys sensoriteknologiassa, laitteiden elektroniikan miniatyrisoinnissa sekä hankintahintojen huomattava aleneminen *(Kacira et al., 2005)*.

Viime vuosina laadukkaiden ja turvallisten maataloustuotteiden kysyntä on kasvanut.
Tämä on lisännyt yhteentoimivien, hajautettujen, kestävien ja tarkkojen logistiikan jäljitettävyysjärjestelmien tarvetta.
IoT-teknologiat tarjoavat tätä varten kaikki tarvittavat työkalut tällaisen infrastruktuurin ja palveluiden rakentamiseen ja ylläpitoon. Erityisesti tuotantoketjujen käyttöön maatalouden alalla.

## Agricultural monitoring and control

Ympäristötekijöiden tarkkailu tuotanto- tai viljely-ympäristössä ja viime aikoina myös kasvien ilmastoon reagoinnin tarkkailu, on kriittistä oikeiden ja aikaisempaa tarkempien päätösten tekemiselle, joilla pyritään optimoimaan tuotannon määrä ja laatu.

Viime aikoina perinteinen anturiverkko on kehittynyt IoT-ystävälliseksi ratkaisuksi yleisempien tietoliikenne standardien avulla, mahdollistaen internet-yhteydet ja älykkään analytiikan käyttöönoton, pyrkien parantamaan tarkkailua ja/tai kontrollointia.

On saatavilla monipuolisia laskentatehokkaita laitteita, kätevän kokoisia ja edullisia, joita voidaan käyttää akuilla pitkiä aikoja, ilman energiankeräimiä tai niiden kanssa.
Nykyisissä sulautetuissa laitteissa on tarpeeksi resursseja vaativien sensorien (kuvantaminen) tukemiseen ja edistyneiden tietoliikenneprotokollien käyttöön, laajentaen perinteisen WSN:n tietoliikenneominaisuuksia.

Luokittelu kirjallisuudesta löytyneille tarkkailun ja kontrolloinnin ratkaisuille:
- Tarkkailu ja joissain tapauksissa aikaisten varoitusten tuottaminen yksinkertaisten sääntöjen perusteella. Esimerkiksi monipistetarkkailu kasvihuoneessa ilmasto-olosuhteiden muutosten havaitsemiseksi.
- Tarkkailu, analytiikka (meta-processing, toteutus resurssipalvelussa) ja kontrolli. Sisältäen myös kontrolli-ehdotukset käyttäjälle sekä täysautomaattisen kontrolloinnin.
- Tarkkailu laskentatehoa enemmän vaativien sensorien (kuvantaminen) avulla sekä tehokkaampien päätelaitteiden (end-node) avulla. Kuvantamisdataa käsitellään joko pelkkään järjestelmän tarkkailuun tai kuvankäsittelyyn laitteessa, verkon reunalla sumutietojenkäsittelynä, resurssipalvelussa/palvelimella.


## Controlled environment agriculture

Kasvihuoneissa tarvitaan tarkempaa kontrollointia ja tarkkailua kasvihuonetuotannon ollessa intensiivisempää.

Useat tutkimukset keskittyvät vain paikallisena tai etänä toteutettuun tarkkailuun, jonka tuottamaa tietoa esitetään useilla visuaalisilla tavoilla. (5)

Useissa tutkimuksissa on esitetty järjestelmiä, jotka käyttävät analytiikkaa, datan siirtoa resurssipalveluihin internetin yli. Käyttäen laskentaa ja kasvien sekä ilmaston (climate) mallinnusta, järjestelmät tuottavat arvioita ilmaston ja/tai kasvien tilasta paremman päätöksenteon mahdollistamiseksi tai aikaisten varoitusten tuottamiseksi. (11)

AIoT-ratkaisut, joissa sovelletaan maataloustuotannon (pilvi-)resurssipalveluita ovat kasvihuonetuotannon yhteydessä jatkuvasti yleisempiä. Sensorilaitteet keräävät dataa joka ladataan resurssipalveluun missä data analysoidaan (syvästi?), nopeammin, edullisemmin, luotettavasti ja tehokkaasti. (2)

Kasvitehtaat ovat yleistymässä "...in the wider frame of urban CEA in smart cities, there have been a number of studies focussing on artificial growth systems"

Osassa tutkimuksia on otettu käyttöön kasvihuoneissa yhden tai useamman toimilaitejärjelmän kontrollointi kuten ilmastointi-, kastelujärjestelmä. (2) Kontrollointi voidaan toteuttaa etäisesti kahdella tavalla: joko viljelijän toimesta käsisäätöisesti tai järjestelmän hallinnoijan toimesta ja päätöksentekojärjestelmän avustamana.

Järjestelmät voivat sisältää integroidun tuholaistorjunnan (IPM)(1), etävalvonnan, varoitukset ja kontrolloinnin sekä pellolla että kasvihuoneissa (3).

On useita tutkimuksia joissa pyritään tuottamaan täysautomatisoitu kontrollointi, joissa kontrollikäskyt on tuotettu sensoridatan analytiikan avulla. (5)

## Open-field agriculture

Tutkimuksissa keskitytään yleensä ilmasto-olosuhteiden ja maaperän mittaamiseen. Usein tutkimuksissa käytetään maaperämittauksissa useita antureita eri syvyyksillä.

Kastelun optimoimiseksi pyritään kastelemaan vain niin paljon kuin kasvi tarvitsee. (1)

Optisia sensoreita on käytetty kasvien heijastuskyvyn mittaamiseen tai lämpötilan etävalvontaan, mutta myös pellon yleistilanteen kartoittamiseen. (4)

IoT:n ja GIS (Geographical Information System) integraatiota on esitetty kun tarkka paikkatieto on tarpeellista. (4)

Maanalaiset sensoriverkot voivat antaa huomattavia etuja peltotuotannon sovelluksissa. (3)

Kehitys sulautettujen laitteiden teknologioissa sekä niiden hintojen aleneminen on mahdollistanut tehokkaiden anturilaitteiden käytön ja paikallisen tiedonkäsittelyn sumutietojenkäsittelynä. Kuvantamisdataa tuottavia anturilaitteita käytetään tutkimuksissa tavallisina turvakameroina (2), eläinten tunkeutumisen havaitsemiseksi (1), hyönteisten tai muiden kasvien uhkien havaitsemiseksi (2) ja satokasvien kasvun tarkkailuun (1).

## Livestock applications

Ei käsitellä.

## Food supply chain tracking

Moderni maatalous on tyypillisesti yhä teollisempaa.
Ruoan turvallisuuden ja laadun takaamiseksi standardisointimekanismeja on otettava käyttöön jokaisessa tuotannon vaiheessa.
Tämän tarve on kasvattanut yleistä kiinnostusta ruokaketjun jäljitettävyysjärjestelmiä kohtaan.
IoT-teknologiat tarjoavat tätä varten useita tarvittavia työkaluja tällaisen infrastruktuurin ja palveluiden rakentamiseen ja ylläpitoon.
Tarkastellussa kirjallisuudessa ratkaisut keskittyvät joko ruoan tuotantoketjun liiketoiminnan puoleen tai teknologioihin. Muutamat julkaisut pyrkivät esittämään ratkaisuita molempien puolien kattamiseen.
Ruoan tuotantoketjun yleisin IoT-teknologia on RFID-tunniste, joiden avulla voidaan seurata maatalouden tuotteita.
IoT-paradigman mukaan viime aikaisissa tutkimuksissa on yhdistetty useita sensoreita rikastamaan kerättävää tietoa tuotteen tilasta aina kun tuotteen RFID luetaan ja tallennetaan. (2)
IoT:n yleiseen luonteeseen kuuluu ratkaisujen hajautuneisuus sekä asynkroninen ja heterogeeninen tietovirta. Tämän takia ruoan tuotantoketjun palveluissa nimeäminen on kriittisen tärkeää tiedon tarkalle ja nopealle löytämiselle. (1)
IoT-infrastruktuurin toteutuminen johtaa tuotantoketjujen virtualisointiin, koska fyysinen läheisyys ei enää ole tarpeellista. *(Verdouw et al., 2013)*.
Tarkastellussa kirjallisuudessa on mallinnuksien avulla analysoitu ruoan tuotantoketjujen ongelmia ja pyritty ratkaisemaan niitä IoT-teknologioiden avulla. (2)
IoT:ssä sovellettavien useiden teknologioiden kehitys yhdistettynä niiden kestävyyden parantumiseen sekä kypsyyteen IoT:ssä on antanut tutkijoille mahdollisuuden kehittää kokonaisia järjestelmiä joissa käytetään sensorimoduleita ja ohjelmistoinfrastruktuureita.
Ohjelmistot ovat (hosted) resurssipalvelussa tai jaettu sidosryhmien kesken.
Kokonaiset järjestelmät tarjoavat automatisoituja palveluita (intelligent schemes?) ja automatisoitua perustelua (reasoning) perustuen mitattuun ilmiöön ja keinoälyyn. (3)
Muut julkaisut lähestyvät ruoan tuotantoketjujärjestelmän tiedonhallintajärjestelmän organisointiin (1) tai miten suunnitella järjestelmä taloudellisen tuoton maksimoimiseksi (1).

## Internet of Things middleware and interoperability



## Multi-layer deployments and commercial solutions



# Discussion

## Internet of Things hardware & software challenges in agriculture 



## Organisational challenges & interoperability



## Networking challenges



## Security challenges



## Stack challenges



## Potential value of IoT in agriculture



# Conclusion






























