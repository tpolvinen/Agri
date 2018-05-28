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

UAV-laitteilla tuotetun datan määrä voi olla syrjäseutujen tietoliikenneverkkojen kaistanleveydelle liian suuri.
Olen itse keskittynyt datasta tehdystä ortomosaiikista tehdyn peltokartan hyödyntämiseen.
Tilanne monimutkaistuu otettaessa käyttöön tilan tarvitsemaa teknologista ekosysteemiä, johon kuuluvat mm. itse drooni, sen ohjelmisto(t) ja otetuista kuvista pellon kokonaiskartan koostava ohjelmisto tai palvelu. *Arvelisin, että mitä useampi sovellus, analyysi ja palveluntarjoaja, sitä vikaherkempi järjestelmä on.*

Oman ymmärrykseni mukaan ortomosaiikin rakentaminen on itsessään ratkaistu ongelma. 
Ortomosaiikin rakentamisessa käytettävät sovellukset toisaalta eivät ole vielä niin edistyneitä, että ne tekisivät sen automaattisesti tai melkein automaattisesti, eivätkä nämä sovellukset ole kaikille käyttäjille välttämättä kovin hyviä.
Ortomosaiikkikarttaa koostettaessa varsinkin isolta peltopinta-alalta kaikki kuvaukset eivät välttämättä ole keskenään vertailukelpoisia. Esimerkiksi 10 hehtaarin pinta-alan kuvaukseen menee droonilla aikaa niin paljon, että olosuhteet ovat voineet sen aikana muuttua aurinkoisesta puolipilviseen ja takaisin. Kun analyysiä tehdään kuvista vaikka jonkin tietyn vihreän sävystä niin valaistusolosuhteet ovat vaikuttaneet kuviin eivätkä kuvat enää ole suoraan vertailukelpoisia keskenään. Tällöin analyysin tekeminen vaikeutuu vähentäen sen perusteella tehtävien johtopäätösten luotettavuutta.
Aikasarjoja kuvatessa samalta pellolta voidaan aika varmoja että valaisuolosuhteet eivät ole olleet aika varmastikaan samanlaiset eri kerroilla.
Luultavasti on joitakin menetelmiä joilla tätä voidaan yrittää kompensoida, mutta ymmärtääkseni ne eivät vielä tällä hetkellä toimi parhaalla tavalla.
Referenssipisteitä voidaan asettaa pellolle, mutta ne ovat periaatteessa turhaa infrastruktuuria jos kuvien normalisointi pystyttäisiin ratkaisemaan jollakin tavalla.

*rajapinnat, oman datasetin jako, vertailu*
Tiedän viljelijöitä, jotka jakavat kaiken viljelytoiminnassaan syntyneen datan johonkin palveluun, mutta he ovat yksittäistapauksia. 
Viljelytoiminnassa syntynytta dataa ei mitenkään systemaattisesti käytetä hyväksi.

*kuluttajalle asti näkyvä tuotantodata*
Käytännössä kuluttajien toteutuva datan tutkinta voi jäädä vähäiseksi.
Suuren yleisön kiinnostus lähiruokaa ja REKO-ruokarinkejä kohtaan on hiipunut ja tämä sovellus voi olla samankaltainen ilmiö, joka toteutuessaan jäisi jonkin ajan kuluessa pienen harrastajapiirin käyttöön.
Jotta kuluttajat yleensä jaksaisivat tarkastella tuotantotietoa, tulisi se näyttää heille täysin vaivattomasti vaikka lisätyn todellisuuden avulla ja todennäköisesti Google Glass:in tapaisen laitteen avulla. Kännykän kaivaminen esille tiedon etsintää varten vaikuttaa liian vaivalloiselta.
Älypuhelinsovelluksena tälläinen voitaisiin toteuttaa, mutta universaalia sovellusta voi olla vaikea kehittää useiden eri toimijoiden kuten S- ja K-ryhmän sovellusten kilpaillessa keskenään. Vielä pirstaleisemmaksi tilanne menisi, jos sovellukset olisivat tuottajakohtaisia.
Itse arvioisin, että passiivinen kuluttaja voisi jaksaa lukea tuotteen pakkauksesta tiedot millä tilalla se on tuotettu, kuinka pitkä matka sitä kaikkiaan on kuljetettu, kokonaishiilijalanjälki, hiilidioksidijalanjälki ja vesijalanjälki.

*sertifikaattien tarkkailu*
Sovelluksena sertifikaattien tarkkailu voisi olla lähempänä toteutumista kuin kuluttajalle vietävä tuotantotieto.
Teollisuuden sisällä tieto voisi liikkua ja laatusertifikaatin toteutumisen valvonta jatkuvaa.
Kuluttajalle laadun viestiminen olisi helppoa.
Monet sertifikaatit ovat tällä hetkellä aika kömpelöitä, esimerkiksi päätös luomutuotannosta tulee tehdä ennen tuotantoa, koska byrokratia on raskas. Luomutuotantoa tarkkaillaan sitten tilan omalla kirjanpidolla ja pistokokeilla. Luomun tuottamiseksi voisi olla ketterämpi vaihtoehto siinä, että viljelijä havaitsee, ettei tänä kesänä tarvitsekaan ruiskuttaa kasvinsuojeluaineita ja jatkuvasti toimintaa seuraavilla laitteilla voitaisiin luomun vaatimusten toteutuminen näyttää toteen.
Datalähtöisellä sertifioinnilla voitaisiin saada erilaisten laatumerkkien toiminta joustavammiksi.

*erilliset arvoerät*
Erillisten arvoerien tuottaminen voisi olla mahdollista, mutta vaatisi toiminta- ja ajattelutavoissa huomattavia muutoksia niin viljelijöillä, elintarvikevalvonnassa kuin elintarviketeollisuudessakin.
Tietenkin voisi olla *näiden teknologioiden avulla* yksittäiselle vijelijälle mahdollista näyttää toteen asiakkaalleen että tuotteet on viljelty tietyillä tavoilla ekologisesti, terveellisesti jne.
Laajempi käyttöönotto ja omaksuminen vaatii vähintään aikaa eikä välttämättä sittenkään ota tuulta purjeisiinsa, vaikka kyseinen innovaatio olisi kuinka edistyksellinen ja tarjoaisi huomattavia etuja. Vaikka teknologia on mahdollistaja, lopulta käyttöön jäävän ratkaisun valikoitumista ohjaavat liiketoiminta, käytettävyys ja muut vastaavat ominaisuudet ja olosuhteet.

*näkyvimmät IoT-ratkaisut*
EOS

*kasvitehtaat, kasvihuone-IoT*
Kasvihuonetuotannon ja kasvitehtaiden IoT-ratkaisuiden kehitys käy kuumana, mutta itse odotan muita kuin salaatin kasvatusta.
Itse arvaan, että kasvatetaan korkean hinnan nopeasti kasvavia lajikkeita, esimerkiksi salaattia jota voi markkinoida steriilisti kasvatettuna ja josta voi saada korkeamman hinnan.
Teknologiaratkaisut ovat jännittäviä, mutta salaatilla ei voi ruokkia maailmaa.

Konttiviljelmistä on ollut kaikenlaisia kokeiluita ja sovelluksia, mutta niillä voitaisiin *ainakin teoriassa* mahdollistaa tuoreen ravinnon tuottamisen katastrofialueilla, missä tuoreiden elintarvikkeiden saatavuus on heikko ja niiden kuljettaminen paikan päälle voi olla vaikeaa mm. kylmäketjun puuttuessa.

*kasvatusresepteillä toimiva kasvihuone tms. MIT Food Computer*
Kasvihuonetuotanto on nykyään hyvin automatisoitua, mutta optimointivaraa voi vielä olla.
Itse odotan kerrosviljelyratkaisuita, joissa voisi viljellä peruselintarvikkeita kannattavasti.
Jos joku jossakin vaiheessa onnistuu tuottamaan viljaa tai perunoita kerrosviljelmässä  taloudellisesti kannattavalla tavalla niin se voi merkitä huomattavaa muutosta ruokatuotannon kehityksen suunnalle.
Perunan tuotanto voisi onnistua hydroponisella viljelyllä, ainakin siemenperunan viljelyä tehdään jo niin.
Kuluttajaperunan viljely taloudellisesti kannattavalla tavalla olisi huomattava edistysaskel, joka voisi olla käännekohta maatalouden historiassa.
Erikoistuotteita voi kyllä tulla, olen itse pitkään odottanut suomalaisen mansikan kasvihuoneviljelyn alkamista ja olisiko ympärivuotisesti saataville mansikoille kysyntää. 

*maaseudun tulevaisuus, 20-30 vuotta*
Järjestelmäintegraation, datan käsittelyn ja alustojen yhteisten ekosysteemien onnistunut toteutuminen tulisi muuttamaan maataloustyön luonnetta suorittavasta työstä suunnitteluun, ylläpitoon ja automatiikan ylläpitotyöhön.
Järjestelmäylläpitotyön osuus kasvaa automaatiojärjestelmien monimutkaistuessa ja koon kasvaessa. Järjestelmien toimintaa pitää valvoa, rikkoutuvia laitteita korjata ja korvata usilla.
Tällöin hehtaaritehokkuus per työntekijä kasvaa edelleen, mutta työn luonne muuttuu.
En ole miettinyt miten tämä voisi vaikuttaa maatalouteen ja maaseutuasumiseen laajemmin.
"Voi olla, että 50 vuoden kuluttua stereotypia tyhmästä maajussista pitää vielä vähemmän paikkansa kuin nykyään --koska sen tyhmän maajussin pitää siinä vaiheessa huoltaa ja ylläpitää omaa ruokatehdastaan."

*suuryritysten maatalous*
Tilojen koko tulee varmasti kasvamaan, mutta Suomessa maatalousmaan hajanaisuus rajoittaa yksittäisten tilojen kasvua tietyn rajan yli.

Hajautetut suuret tilat eivät tuskin olisi kannattavia. 

*tutkimus*
Tutkimme juuri nyt maatalouden tietoturvaa ja ylipäätänsä laitteistojärjestelmien kyberturvallisuutta, joka tulee olemaan maatiloilla kasvava ongelma.
Myös maatalouden verkkoon kytkettyjä laitteita koskevat samat tietoturvauhat kuin muitakin teollisia järjestelmiä.
Kiristyshaittaohjelmalla voi hyvinkin haitata maatilan toimintaa, samoin kuin Saksan rautateitä. Vaikka taloudelliset tappiot voivat olla yksittäisellä tilalla tuotannon keskeytymisestä olla pienemmät kuin rautatieliikenteen pysähtymiten vastaavat, eläinten jatkuvan hoidon lamaantuminen tarkoittaa välittömästi eläinsuojelu-uhkaa. Loppujen lopuksi se on jostakin näkökulmasta katsoen vakavampi asia kuin ihmisten pääsy ajoissa töihin.

[00:44:01] *IoT-uhat, vaikeudet*



























