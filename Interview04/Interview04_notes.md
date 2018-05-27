Haastattelu 4 muistiinpanot

Järjestelmien järjestelmä -> laitteiden ekosysteemi (?)
ISOBUS-standardi
viljelysuunnittelujärjestelmä
viljelysuunnitteluohjelmisto
vendor lock
AEF
subscription-lisenssimalli
UAV Unmanned Aviation Vehicle (?)



Maatalouden IoT:ssä ja digitalisaatiossa on tällä hetkellä jo valmiina useita kokonaisuuden osia ("leegopalikoita") joita voidaan ottaa käyttöön ja riippuen maatalouden osa-alueesta jossain määrin on otettu käyttöön.
*Osat ovat vielä erillään.*
"Vapaa, avoin, järjestelmien välinen yhteistyö ja dataintegraatio on vielä vaikeaa."

Verrattuna tilanteeseen neljä vuotta sitten, nyt saadaan enemmän kytkettyä laitteita vapaasti toisiinsa.
On suuria ongelmia saada kiinteät laitteet, liikkuvat työkoneet, viljelysuunnitteluohjelmistot, sensorijärjestelmät ja ulkopuolisten tahojen tarjoamat datalähde tai -analyysipalvelut toimimaan yhdessä, jakamaan dataa ja tietoa niin, että sitä pystyisi helposti käyttämään maatilan toiminnan parantamisessa.

Vaikka IoT-ratkaisun/järjestelmän määrittelyssä ollaan joissain tapauksissa korvattu ihmisen tekemä valvonta, päätöksenteko ja toimeenpano automaattisilla koneiden toiminteilla, niin suuri osa IoT-ratkaisuiksi *merkityistä/määritellyistä* järjestelmistä on käytännössä sensoridatan lukemista ja ihmisten vastuulle on jäänyt ainakin lähes, jos ei kaikki päätöksenteko ja toiminta.
Tämä johtuu juuri järjestelmien välisen kommunikaation puutteesta.
Toisaalta ihmiselle jäävä päätösvalta ei ole pelkästään huono asia.
Toisaalta mitä enemmän käytetään dataa ja mitä enemmän kone tekee ihmisen puolesta päätöksiä, niin sitä enemmän pitää kiinnittää huomiota käyttäjän oman asiantuntemuksen ylläpitoon. Käyttäjän nojautuminen täysin automaattisen järjestelmän varaan voi helposti aiheuttaa käyttäjän oman asiantuntemuksen puutteen ja sitä kautta kokonaisprosessin ymmärryksen vähenemisen tai häviämisen.


Viljelijän toiminnan luonteen muuttumiseen tulee kiinnittää huomiota. Rooli peltotöiden suorittajasta on muuttumassa "manageriksi" ja tilan toiminnan hallinnoijaksi.
Tällöin viljelijä on aika kaukana itse pellosta ja pellolla vallitsevasta tilanteesta robotin suorittaessa peltotyön viljelijän puolesta. Tämä vaikuttaa pitemmällä tähtäimellä viljelijän ammattitaitoon ja lyhyellä aikavälillä viljelijän tilannetietoisuuteen pelloilla vallitsevasta tilanteesta.

ISOBUS-standardi on ratkaissut pitkälle työkoneiden yhteenliitettävyyden ongelman ja nyt kehityskulku on menossa kohti seuraavaa vaihetta, missä työkoneet liitetään osaksi jotain isompaa järjestelmää.
Esimerkiksi Agrineuvoksen kehittämällä ratkaisulla saadaan Valtran traktorit kiinni Agrismart-järjestelmään. Agrismart-järjestelmän avulla traktorin tuottama data siirtyy automaattisesti viljelysuunnittelujärjestelmään ja toisin päin.

Integraatio on ollut *tähän asti ja luultavasti vastakin* paljon syvempää suurilla ns. full-liner laitetuottajilla, joilta voi hankkia kaikki toiminnassa käytettävät työkoneet, laitteet, ohjelmistot ja palvelut.
Ongelmana on, että vain harvoilla tiloilla on kaikki laitteisto samalta tuottajalta. Lisäksi siinä tapauksessa ollaan pahasti käytössä olevan merkin ja tuoteperheen talutusnuorassa.

Luultavasti merkittävin yritys avoimien tiedonkäsittelystandardien kehittämiseksi ja ns. vendor lockin välttämiseksi on AEF:n yritys saada tänä vuonna ISOBUS-standardilla kytketyt koneet yhdistettyä viljelysuunnitteluohjelmistoihin. Tästä integraatiosta on tulossa osa ISOBUS-standardia ja sitä valmistelemassa on 4 tai 5 keskieurooppalaista ohjelmistosuunnittelun yritystä. Suomalaisista toimijoista ainakin Agrineuvoksen kehittäjät ovat seuraamassa integraation kehittämistä. Luulen, että he seuraavat tilannetta ja kun standardista tulee riittävän stabiili he tekevät päätöksiä missä määrin ottavat standardin käyttöön omassa toiminnassaan.

Maanviljelyn digitalisaation ja IoT-ratkaisujen tarjoamien hyötyjen/etujen tuomasta kannattavuudesta on vaikea sanoa mitään ja se on pitkään ollut ongelmana: yleisesti nähdään, että teknologiaratkaisuilla on paljon potentiaalia mutta mukaan lähtemisen riskit ovat olemassa ja siihen vaadittaisiin kohtuullisia investointeja.
Uuden teknologian integroiminen *omaan toimintaan* vaatii sekä rahaa että aikaa, varsinkin jos samalla konekantaa joudutaan uusimaan ja/tai ottamaan käyttöön uusia ohjelmistoja. 
Koska suomalaisten viljelijöihen taloudellinen tila ei tällä hetkellä ole mitenkään erityisen hyvä, eritysesti subscription-lisenssimallin ohjelmistojen käyttöönoton kynnys on aika korkea.

Kun viljelysuunnitteluohjelmat siirtyvät yhä enemmän paikallisista ohjelmista pilvipalveluihin viljejijän toiminnassaan tuottaman datan omistajuudesta ei aina ole varmuutta.
En tiedä onko suomessa yleisessä käytössä olevasta Wisu-sovelluksesta enää edes saatavilla paikallista versiota.
Olen ymmärtänyt että kaikki merkittävät suomalaiset viljelysuunnitteluohjelmat ovat menossa kohti pilvimallia, jota käytetään verkkoselaimen tai vastaavan sovelluksen läpi. Tällöin datan omistajuuden kysymyksestä tulee yhä merkittävämmäksi.
Aikaisemmin käyttäjän omalle koneelle tallentannettu tieto oli täysin käyttäjän omassa hallinnassa, mutta palveluntarjoajan tietojärjestelmään tallennettuun tietoon käyttäjällä on vain pääsy.
Maatalouden näkökulmasta toinen merkittävä haaste on syrjäseutujen tietoliikenneverkkojen luotettavuus ja nopeus. Pilvipalveluiden yleistyminen asettaa kasvavia vaatimuksia tietoliikenneyhteyksien luotettavuudelle *varsinkin tilojen toimintakriittisille sovelluksille ja palveluille. Kuinka moni viljejijä haluaisi ottaa riskin sijoittamalla omalle yritykselleen toimintakriittisiä tiedonhallinnan sovelluksia epäluotettavan ja hitaan verkkoyhteyden taakse?*

Tuotettujen datamäärien koko voi olla syrjäseutujen tietoliikenneverkkojen kaistanleveydelle liian suuri. UAV-laitteilla tuotetun datan määrä voi olla liikaa.
Olen itse keskittynyt datasta tehdystä ortomosaiikista tehdyn peltokartan hyödyntämiseen.
Tilanne monimutkaistuu otettaessa käyttöön tilan tarvitsemaa teknologista ekosysteemiä, johon kuuluvat mm. itse drooni, sen ohjelmisto(t) ja otetuista kuvista pellon kokonaiskartan koostava ohjelmisto tai palvelu. *Arvelisin, että mitä useampi sovellus, analyysi ja palveluntarjoaja, sitä vikaherkempi järjestelmä on.*

[00:16:18] noin 70 % jäljellä






































