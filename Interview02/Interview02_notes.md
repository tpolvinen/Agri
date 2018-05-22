Haastattelu 2 muistiinpanot

tilanhallintajärjestelmä Farm Management System FMS
viljelysuunnitteluohjelma
rajapinta
satopotentiaali
satovaste
satotappio
sadonlisä
satotasomittari
tuotantoketju
ruokaketjussa
arvoketju


Kasvintuotannossa ei olla ottamassa ihmistä pois päätöksenteosta, missään vaiheessa. Koneilla voidaan kyllä avustaa ja antaa mahdollisuus kanavoida resursseja paremmin.

Pitkän aikavälin kehityksessä voidaan päästä siihen, että järjestelmä voisi koneoppimista hyödyntämällä antaa suosituksia viljelypäätösten tueksi.

Kasviravitsemuksen kannalta ajatellen tällä hetkellä suositukset, neuvot ja soveltamisen tekee vielä ihminen. Tällä hetkellä koneet pystyvät Kasviravitsemuksessa/kasvituotannossa (?) yksinkertaisiin kuvantamistoimintoihin, mutta vielä ei ole mallinnettu kaikkiin olosuhteiin sopivia malleja joita käyttäen kone voisi avustaa ihmistä päätöksenteossa.

Kun joka olosuhteisiin sopivia mallinnuksia pystytään tekemään, voitaisiin tehdä tilakohtaisia räätälöityjä suosituksia ja järjestelmä voisi oppia mitä tilalla tapahtuu.

Peltokasvintuotannon tavoitetila mihin pyritään on monien teknisten rajoitteiden takana. Esimerkiksi dataa pystytään keräämään suuria määriä, mutta sen siirtämiseen ei ole infrastuktuuria sen siirtämiseen.
Suuren datamäärän takiä ei vielä ole teknisesti mahdollista siirtää reaaliaikaisesti pellolta kerättyä dataa järjestelmien välillä.
Nopean tiedonsiirron puuttuminen on tuotekehityksen esteenä ja nyt ei pystytä kehittämään järjestelmiä jotka keskustelisivat keskenään.
Tällä hetkellä keskitytään eri tahojen eri tarkoituksiin keräämien tietojen tiedolliseen käyttämiseen ja jakamiseen eri toimijoiden kesken. (?)

Yara panostaa digitaalisen maatalouden ratkaisuiden kehittämiseen Berliinin Digital Farming -yksikössä. Yksikkö on aloittanut vuoden 2017 syksyllä.
Ollaan siirtymässä koko ajan lähemmäs kokonaisvaltaista tilanhallintajärjestelmää
Agritechnica -messuilla esiteltiin MyYara -viljelijäportaaliohjelmisto, jossa on esim. Saksan markkinoihin räätälöity viljelysuunnitteluohjelma, johon voi syöttää N-sensor-kartat ja N-tester-lukemat.
Lisäksi on portaali, johon kootaan Yaran keräämää tietoa.

Ollaan kehittämässä ja hakemassa rajapintoja järjestelmien välille. Yara tekee yhteistyötä 365FarmNet:in kanssa [https://www.365farmnet.com/en/] ja Yaran laitteilla tuotettua dataa voidaan käsitellä heidän järjestelmissään.

Järjestelmien rajapinnat, integraatiot ja datavirtojen standardointi on vielä työn alla.

Laajamittainen yhteen toimivien järjestelmien käyttöönotto on riippuvainen alustojen kehityksestä ja saatavuudesta. Jos alustoja järjestelmien yhteistoiminnalle kehitetään ja tuodaan saataville niin niitä otetaan käyttöön.

Sensoriteknologia on jo olemassa. Langatonta tietoliikennettä laitteilta ja koneilta eteenpäin voi myös korvata siirrettävillä muistivälineillä, kuten on tehty tähän asti. *Langaton tietoliikenne ei siis ole ehdoton vaatimus.*

Tavoitetila on kuitenkin ihmisen toteuttamien työvaiheiden vähentäminen tietojenkäsittelyssä, mutta en osaa sanoa millä aikavälillä täysin automatisoitu järjestelmä tulee yleiseen käyttöön. Sellaisen toteutus on ilmeisesti lähellä.

Yarassa emme ole viljelijöiden kanssa toimiessamme ole kohdanneet kysymystä datan omistajuudesta. Asiakas omistaa tuottamansa datan ja käyttää sitä omiin tarkoituksiinsa, emmekä ole keränneet asiakkaiden dataa. *Datan keruu voi siis olla tulevaisuudessa kysymys johon toimijoiden on otettava kantaa.*

On jo tapauksia, joissa toimija haluaa laitteillaan tuotetun datan myös itselleen ja määrätä mihin järjestelmiin sen syöttää, eli muihinkin kuin laitteiden valmistajien omiin järjestelmiin. Suurin osa toimijoista jotka pyrkivät datan siirreltävyyteen eivät ole viljelijöitä, vaan yhteistyömahdollisuuksia hakevia järjestelmätoimittajia.
Nämä järjestelmätoimittajat ovat ohjelmistotaloja, jotka kehittävät FMS-järjestelmiä ja pyrkivät käyttämään satelliitti- tai NDVI-kuvantamispalveluita. Heille on eduksi mitä useamman järjestelmän kanssa heidän tuotteensa on yhteensopiva ja mitä enemmän heidän tuotteensa pystyy integroimaan itseensä, joko linkittämällä *rajapinnan kautta(?)* tai ilman *(?)*.
Yksittäisiä FMS-ratkaisuita käyttäviä viljelijöitäkin on, jotka pohtivat voisiko dataa liikutella tai tuoda saataville eri järjestelmien välillä.

Suurin osa viljelijöistä on vielä aika kaukana esimerkiksi Yaran N-sensorilla tehtyjen karttojen ja muitten (pelto)lohkotietojen yhdistämisestä. Sensoritekniikkaa käytetään N-sensorissa lähtökohtaisesti lannoitustyökoneen suoraan ohjaamiseen. *Onko tämä suora ohjaus ilman tiedon tallennusta, analytiikkaa jne. missä määrin yleisempää toimintaa? Ainakin kirjallisuuskatsausten mukaan havainnointi ja kontrollointi ovat huomattavasti yleisempiä kuin analytiikka. Voisiko tutkimusten määrää ja aikaa verrata Big Data-katsausten vastaaviin?*

Muita käyttöönoton vaikeuksia, uhkia, heikkouksia:
Vaikka pieni joukko viljelijöitä ottaa käyttöön uutta teknologiaa matalalla kynnyksellä, kuten täsmäviljelylaitteita, niin suurempi joukko on sellaisia jotka eivät ota.
Joko he eivät näe sen etuja sellaisina, että hankinta ja käyttöönotto olisi juuri heidän tapauksessaan kannattavaa tai sitten he eivät ole täsmäviljelyteknologiasta tietoisia.
Jos suomalaisessa maanviljelyssä ei saada otettua käyttöön uutta teknologiaa, niin on olemassa riski, että suomalaiset viljelijät jäävät jälkeen teknologiakehityksessä *ja menettävät markkinaosuuksiaan muualta tuoduille tuotteille*.

Esimerkiksi teknologian käyttöönotosta Yaran N-sensorin avulla saadaan Saksassa 6 % suurempia satoja ja samalla säästöjä panoksissa, Ruotsissa saman lukeman ollessa 4 %. Voisi ajatella, että *yhteisillä markkinoilla kilpaillessa* Suomessa tämä hävitään joka vuosi. 
Lisäksi suomessa ei aina pystytä implementoimaan uusinta teknologiaa aikaisemman teknologisen kehitysvaiheen ollessa vielä kesken tai puuttuessa kokonaan. *!*

Teknologiakehittäjien haasteena on käytettävyys *ja käyttäjäystävällisyys*. Viljelijän tulee pystyä helposti käyttämään tuotetta tai järjestelmää *tehokkaasti ja saaden siitä täyden hyödyn* oman osaamisensa avulla. Käyttöliittymien tulee olla yksinkertaisia ja yksiselitteisiä sekä tuotetun tiedon oikeaa, jotta sitä voidaan käyttää päätöksenteon ja suunnittelun tukena.
Vaikka tarjolla on monenlaisia teknologioita, niiden tuottaman tiedon merkityksen *ja kausaliteettien* tulisi olla tarjoajan tiedossa *mutta näin ei aina taida olla?* 
*Ilmeisesti tällä hetkellä järjestelmät voivat tuottaa tietoa päätöksenteon tueksi, mutta eivät vielä oppia toiminnasta, eivätkä ehdottaa viljelypäätöksiä, eivätkä tehdä päätöksiä autonomisesti?*

Tuotetun datan eheydessä ei ole puutteita tai vikaa sinänsä, jos data on itsessään tuotettu kalibroiduilla sensoreilla ja data on vertailukelpoista.
Datasta tehdyt johtopäätökset ja niiden tekemisen metodit ovat tärkeämpi asia.
Kasvinviljelyssä on mahdollista kuvantaa erilaisia spektrejä ja saada tuloksena oikeaa dataa, mutta johtopäätöksien tekeminen ja niiden perusteella suositusten antaminen tuotantopanoksien käyttöön vaatii taustalle koetoimintaa tueksi (sekä erilaisia kalibrointeja).

Johtopäätöksien tekeminen vaatii taustatyötä, mikä on vaikka N-sensorin tapauksessa muun muassa typpi- ja vaihtelualgoritmien kehittäminen. Ne perustuvat koetoimintaan, johon perustuvat johtopäätökset ja suositukset ovat testattuja.

Yaran N-sensoria voidaan käyttää typen levittämiseen ja sen avulla saavutetaan tuloksia viljelyn kannattavuuteen, mutta vain jos viljelyn perusasiat ovat kunnossa. Hienokaan laite ei voi korjata puutteita viljelyn perusasioissa.
Viljelyn perusasioiden parantamisen tukena on Yaran verkkosivuilla muun muassa laskureita.
Koska kasvit ovat elävä organismi ja niitä pystytään mallintamaan vain rajallisesti, on hyvin tärkeää harkita tarkkaan mitä toimintoja ja päätöksiä prosesseista voidaan antaa koneiden tehtäviksi. Lisäksi viljelijän päätöksenteon tukena toimii parhaiten toinen ihminen.

Tuotteiden ja teknologioiden käyttöönoton levinneisyyden ratkaisee lopulta kokeilut käytännössä. Toimimattomat ratkaisut hylätään.

Suositusten väärinymmärryksen riski vältetään Yaran N-sensorin tapauksessa yksinkertaisella käyttöliittymällä, joka näyttää mitatun lannoitetarpeen typpikiloa per hehtaari -lukemana. Tällöin tiedon tulva ei näy käyttäjälle eikä viljelijällä ole tarvetta tutkia taustalla olevaa dataa, indeksejä ja algoritmeja. Näytettävästä tiedosta tulee tehdä ymmärrettävää ja väärinymmärryksestä johtuvasta ylireagoinnista ei ole vaaraa.
Jos tiedetään miten eri tuotantopanokset vaikuttavat esimerkiksi satoon, voidaan arvioida laskennallisesti satopotentiaali ja satovaste. Näiden perusteella voidaan arvioida lisälannoituksen tarve tiettynä ajankohtana ja millainen satotappio voidaan kärsiä jos lisälannoitusta ei tehdä.

Sensoriteknologia antaa mahdollisuuksia ulosmitata lohkolta saatavan satovasteen potentiaali tasaisesti. Tämä on menossa eteenpäin viljelijöiden keskuudessa.
Toisaalta jos ei ole omaksuttu aikaisempaa teknologiakehitystä eli jaettua lannoitusta *(onko tämä variable rate?)* niin ei todennäköisesti omaksuta sensoriteknologian mahdollistamaa jaetun lannoituksen hallintaakaan. *Termit on nyt vähän hämärässä, tarkistettava!* 

Viljelijät eivät oman näkemykseni mukaan todennäköisesti tee suuria teknologiaharppauksia tai hyppäyksiä kehitysvaiheiden yli.

Viljelijöiden ja teknologiatoimittajien tulisi keskustella enemmän vallitsevasta tilanteesta ja teknologioiden tuomista mahdollisuuksista.

Sadonlisää on saatavissa, prosenttiluvut ovat lohkokohtaisia ja riippuvat lohkon sisäisistä vaihteluista, lannoitusstrategiasta. Kannattavuuden parantamista ja toiminnan kehittämistä tulisi tehdä pienissä paloissa. Kun on päätelty tuotannon suurimmat ongelmakohdat, voidaan niitä ryhtyä selvittämään ja korjaamaan, jolloin teknologiaa otetaan käyttöön tarvelähtöisesti. *Tällöin on ilmeisesti hyvin harvinaista, että tehtäisiin suuria harppauksia, vaan pienin askelin edetään, jolloin teknologioiden täytyy sopia yhteen sekä vanhojen että tulevien laitteiden kanssa.*

Sadonlisän lisäksi on mahdollista saavuttaa lannoitesäästöjä. Kun lannoitepanoksia kuten typpipanoksia kohdistetaan oikein, niin niiden määrässä säästetään *huuhtoutumat pienenevät myös*. Urakoitsijat ja viljelijät näkevät tämän konkreettisesti levittimeen jääneinä lannoitteina.
Monilla viljelijöillä ei ole satotasomittaria ja vertailukohdat puuttuvat, koska edellisen vuoden satoon ei voi tehdä vertailuja.
Satokaudet ovat huomattavan erilaisia ja esimerkiksi typen dynamiikka on erilainen eri satokausina kasvuolosuhteista riippuen.

Vaikka viljelijä tekisi kaiken samoin joka vuosi, maasta voi vapautua ohrakasvustolle tietystä kohtaa peltoa 100 kiloa typpeä yhtenä vuonna ja toisena vuonna 60-70 kiloa.

Koska olosuhteet ja kasvukaudet vaihtelevat, tarvitaan osaamista, datan louhintaa ja algoritmien kehitystyötä aikaisemman tiedon pohjalta.
Koska lannoitussuositus vaikuttaa sekä sekä satotasoon että kannattavuuteen, tulee suosituksia tehdessä tietää mitä vaikka 40 kilon muutos tarkoittaa ja mihin kaikkeen se vaikuttaa.
Toisaalta muistaakseni noin puolet viljelijöistä ei laske viljatonnin tuotantokustannuksia, joten kustannusrakenteen tietoisuuteen tuomisessa on vielä paljon tehtävää työtä.

Voin kuvitella, että tilakokojen kasvaessa ja tilojen määrän pienentyessä maanviljelystä tulee enemmän liiketoimintamaisempaa ja kustannusrakenteitakin lasketaan tarkemmin.
Pienillä tiloilla, joiden keskiarvoinen hehtaarikoko 40-50, täsmäviljelyn teknologiaratkaisut on erilaisia kuin tiloilla joissa on 200-400 hehtaaria. *Taas se pirstaleisuus.* Tulevaisuudessa käytettävät laitteistot ja järjestelmät voivat poiketa toisistaan huomattavasti tilakoon *ja tilatyypin ja muiden tilan ominaisuuksien* mukaan.
Samoin käytetyn teknologian saavutetut hyötysuhteet voivat vaihdella huomattavasti käyttöympäristöjen vaikutusten mukaan.

Jos ajatellaan millainen maatalouden yleiskuva voisi olla, niin viljelijä voisi saada käyttöliittymäänsä kehotuksia toimista ja niiden perustelut. Esimerkiksi sensorien antaman tiedon analyysin perusteella tarvitaan lisälannoitusta tiettynä ajankohtana.
Lisäksi järjestelmä voisi myös kommunikoida muiden järjestelmien kuten tilanhallinnan FMS, viljelysuositusjärjestelmän ja muiden erilaisten ohjelmistojen kanssa.
Tällaisiin järjestelmiin on vielä vähän matkaa, mutta mallinnuksen, datan keruun ja niiden perusteella tehtävien viljelysuositusten ja niiden ajankohtien määrittelyjen kanssa tehdään paljon työtä. Nämä järjestelmät voivat hyvinkin toteutua.
Kauemmaksi tulevaisuuteen voisi visioida itsenäisesti pelloilla toimivia traktoreita. 

Tiedon liikkuminen tuotantoketjussa *(ruokaketjussa, arvoketjussa?)* kuluttajalle asti voisi toteutua jos siihen saataisiin alustajärjestelmä. Tällöin kuluttaja voisi ottaa selvää millaisella tuotantopanoksilla tuote on tehty.

Ruokaturvan parantamiseen nämä teknologiat voivat osallistua
vähentämällä viljantuotannossa viljelijän toiminnassa ilmeneviä riskejä, jolloin sadoista saataisiin varmempia. Samoin voidaan viljelijän toiminnassa saada järjestelmistä tarkkaa tietoa lohkojen historiasta ja nykytilanteesta, mikä parantaa tilannehallintaa kasvintuotannossa.
Tiedon avulla voidaan tehdä parempaa lajikevalintaa, tunnetaan typen vapautumisen määrät, kasvien tuleentumisen eteneminen ja tämän kautta parantamaan sadon määrää ja laatua ja sitä kautta ruokaturvaa.
Ruokaturvan varmistaminen on viljelijän toiminnassa mukana, mutta vielä merkittävämpi rooli toiminnassa on sellaisen viljan tuottaminen, mistä hän saa parhaan hinnan ja mitä häneltä halutaan ostaa.

Viljanviljelyn riskiarvioita tehdessä voidaan arvioida sadon epäonnistumisen riski ja siitä johtuvat taloudelliset riskit. Silloin voidaan arvioida onko kannattavampaa ottaa näitä teknologioita käyttöön kuin olisi olla käyttämättä, koska näillä teknologioilla voidaan vähentää tuotannon tehon laskun riskiä, myös ilmastonmuutoksen aiheuttaessa muutoksia.

Suomessa Yaran N-sensorin käyttö on harvinaisempaa kuin Ruotsissa. Ruotsissa on noin 220-230 laitetta käytössä ja laskennallisesti 80 % vehnän pinta-alasta ajetaan N-sensorin kanssa.

Yaran N-sensorin hankintahinta nähdään Suomessa vielä korkeana ainakin yksittäisenä investointina tai eränä. Ruotsissa hintaa ei ole pidetty niin korkeana laitteen käytöstä saatujen etujen myötä, investointi on saatu katettua parantuneilla tuloksilla.

Suomessa viljelijät ovat usein katsoneet, että peltopinta-alat ovat liian pieniä jotta täsmäviljelyä kannattaisi tehdä. Pienillä peltopinta-aloilla toimivien tilojen kannattaa ennemmin vuokrata N-sensori tai ostaa se urakointipalveluna. *Voiko ajatella, että riittää kun pienelle pellolle panostetaan tasaisesti? Ehkä. Voisiko tätä yleistää myös muihin kalliisiin uuden teknologian koneisiin? Luultavasti.*

Urakointina voidaan ulkoistaa täsmäviljelytyöt, jotka on aikaisemmin pitänyt tehdä oman hiljaisen tiedon varassa mutta jotka on uudella teknologialla saatu dokumentoitua ja tallennettua urakoitsijalle annettavaan työtiedostoon. Jos löydetään ne tiedot, jotka työtiedostoon tarvitaan.
Useamman vuoden historiatietoja voidaan myös vertailla ja pyrkiä selvittämään kasvuun liittyviä ongelmia, vaikka miksi juuri tuo kohta pellossa tuottaa aina huonoa satoa tai on muuten ongelmainen.

Viljelijät voivat käyttää sensoriteknologiaa lannoituksen jakoon mutta en itse ole tietoinen, että dooneilla tai satelliteilla tehdystä kuvantamistiedoista ja kartoista olisi vielä tehty levitystä tukevaa tehtävää.

Ihminen on toiminnassa vahvasti mukana ja tulkitsee indeksin arvoa. Tässä tulkinnassa tarvitaan asiantuntijuutta jonka avulla tiedostetaan lukujen merkitykset ja tarkoitukset. Ilman sitä kokeisiin, tutkimukseen ja kokemukseen perustuvaa asiantuntijuutta *koneellisesti tulkittuna* voidaan mennä jopa huonompaan suuntaan.

Tällä hetkellä tiedossani ei ole järjestelmää, joka toimisi viljelijöiden tai muiden toimijoiden datasettien vertailun alustana ja osto- ja myyntikanavana. Visiona tämä on kuitenkin mahdollinen.
Tässä vaiheessa visioidaan enemmän kuin voidaan toteuttaa.
Jos viljelijät lähtisivät tällaisen vision perusteella tehtyyn ehdotukseen mukaan, niin sen toteuttamiselle ei ilmeisesti ole mitään esteitä jos poliittiset ja lainsäädännölliset reunaehdot täyttyvät.

Jos tahtoa toteuttaa viljelijöiden ja muiden datasettien vertailualusta löytyy, sitä tullaan jollain aikavälillä rakentamaan pala kerrallaan aloittaen luultavasti rajapintojen ja tietojen siirtämisen ratkaisuista. 

Todennäköisesti viiden vuoden kuluttua tällaiset järjestelmien väliset ja dataa kokoavat järjestelmät ovat jo yleisessä käytössä.

Liiketoiminnan ekosysteemin rakentuminen standardien ympärille vaatii vielä paljon työtä.

Suuren datamäärän analysointi ja muuttaminen ohjelmistokäskyksi jollain tavoin vaatii vielä paljon työtä.

Tilakoot ovat kasvamassa ja rakennemuutos on menossa yhä suurempien tilakokojen suuntaan. Tullaan näkemään ajosuunnittelun ja urakointipalveluiden käytön yleistymistä.
Suomelle tyypilliset pirstaleiset lohkot *(ja muut olosuhteet?)* antavat meille syitä kehittää tehokkuutta parantavia ratkaisuita, jotta voimme pysyä muun maailman tahdissa mukana.

Jos ei mene eteenpäin niin taantuu, paikallaan pysymällä.
