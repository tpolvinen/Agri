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


"When it comes to wireless communications, a large scientific literature has been created on sensor networks, addressing several problems, such as energy efficiency, networking features, scalability and robustness (Atzori et al., 2010)."

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



































