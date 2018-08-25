# Verdouw: Internet of Things in agriculture

@verdouwInternetThingsAgriculture2016a
    Muistiinpanot:
    
## Abstract

Kirjallisuuskatsauksessa tehdään katsaus nykyisiin sovelluksiin, mahdollistaviin teknologioihin ja keskeisiin avoimiin haasteisiin.
Tieteellisten julkaisujen määrä on kasvanut vuodesta 2010 lähtien.
Aasialaiset, erityisesti kiinalaiset tekevät suurimman määrän AIoT:stä kirjoitetuista julkaisuista.
Muilla mantereilla IoT oli viime aikoihin asti EI-maataloustieteilijöiden aluetta.
Useimmin esiin tullut sovellusalue oli tuotantoketju, toiseksi useimmin peltoviljely.
Suurin osa tutkimuksista esittivät eksploratiivisten tutkimuksien tuloksia tai IoT-järjestelmiä jotka on suunniteltu tai implementoitu prototyyppeinä ja pilotteina.
Suurimmassa osassa tutkimuksista käsiteltiin sensorointia (sensing) ja tarkkailua (monitoring), kun taas aktuointi ja etähallinta on harvinaisempaa.
Havainnot viittaavat siihen, että IoT on vielä alkuvaiheessa maatalouden ja ruuan alalla.
Sovellukset ovat usein pirstaleisia, niistä puuttuu saumaton integraatio ja erityisesti edistyneemmät sovellukset ovat kokeellisissa vaiheissa.
Tärkeimmät avoimet haasteet ovat:
* Olemassaolevien IoT-ratkaisuiden integraatio avoimilla IoT-arkkitehtuureilla, alustoilla ja standardeilla.
* Yhteentoimivien IoT-teknologioiden skaalaus aikaisten omaksujien ulkopuolelle, erityisesti nykyisten sovellusten yksinkertaistamisella sekä loppukäyttäjien maksamien hintojen alentamisella.
* IoT-teknologioiden edelleen kehitys laajan käytettävyyden saavuttamiseksi maatalouden monimuotoisessa käyttöympäristössä.

## Introduction

Ruokaturva on keskeinen kysymys joka muodostuu entistä kriittisemmäksi seuraavien vuosikymmenien aikana odotetun väestönkasvun ja (emerging economies) elintason nousun myötä.
Yleisesti argumentoidaan, että maan kantokyky on ylitetty nykyisellä maatalouden tuotantotavoilla/metodeilla.
Globalisaatio, ilmastonmuutos, polttoaineperusteisesta taloudesta bioperustaiseen talouteen siirtyminen, maankäyttöön, makeaan veteen ja työvoimaan kohdistuva kilpailu monimutkaistaa haastetta maailman ruokkimiseen ilman suurempaa saastuttamista tai resurssien liikakäyttöä/liikaottoa.
Odotetaan, että IoT, missä kukin laite on
* yksilöivästi tunnistettava
* sensoreilla varustettu
* reaaliaikaisesti internetiin kytketty
...voi huomattavasti myötävaikuttaa/osallistua näihin haasteisiin vastaamiseen, näin:
* Tuotannon parempaa tarkkailua/havainnointia/monitorointia/sensorointia, kuten maatilan resurssien käyttö, sadon kasvun tarkkailu, ruuan prosessointi, eläinten käyttäytymisen tarkkailu.
* Parempi ymmärrys maatilan olosuhteista kuten säästä, ympäristön tilasta, tuholaisten, rikkakasvien ja tautien ilmenemisestä.
* Edistyneempi ja etänä toteutettava kontrollointi maatilan, prosessoinnin ja logistiikan operaatioissa toimilaitteiden ja robottien avulla kuten kasvinsuojeluaineiden ja lannoitteiden levitys, automaattinen kitkentä roboteilla
* Ruoan laadun tarkkailu ja jäljitettävyys etänä kontrolloiden kuljetuksen ja tuotteiden sijaintia ja olosuhteita.
* Lisäämällä kuluttajatietoisuutta kestävyydestä (sustainability) ja terveyskysymyksistä henkilökohtaisen ravitsemuksen, wearables (?), kotiautomaation avulla.

## What is IoT?

Internet: toisiinsa kytkeytyneiden tietoverkkojen globaali järjestelmä, käyttää Internet protocol suite:a (TCP/IP) miljardien laitteiden yhdistämiseen. Yli 46 % maailman väestöstä käyttää Internetiä **3**. Internetin käyttö keskittyy vielä pääasiassa ihmisten interaktioihin ja monitorointiin käyttöliittymien ja sovellusten kautta.
IoT on seuraava Internetin vaihe, jossa myös fyysiset esineet (things) kommunikoivat.
IoT:n yhdistämät konseptit "Internet" ja "Thing" voidaan semanttisesti määritellä “a world-wide network of interconnected objects uniquely addressable, based on standard communication protocols” **4**.
Konsepti esiteltiin ensimmäistä kertaa MIT Auto-ID Centerin toimesta määriteltäessä kehitystä kohti maailmaa, jossa kaikki fyysiset objektit voidaan jäljittää Internetin yli merkitsemällä ne Radio Frequency IDentification (RFID) -lähettimillä **5**.
Käsite on ajan kuluessa laajentunut kohti maailmanlaajuista älylaitteiden verkkoa jossa laitteet ovat tilannetietoisia (context-sensitive) ja voidaan tunnistaa, tuntea (sense) ja kontrolloida etäisesti käyttäen sensoreita ja aktuaattoreita **6-8**.
IoT:ssä jokainen laite/esine on yksilöllisesti tunnistettavissa, varustettu sensoreilla ja kytketty reaaliaikaisesti internetiin.
IoT:n odotetaan olevan seuraava Internetin vallankumous.
Tähän asti maailmassa on otettu käyttöön/asennettu 5 miljardia "älykästä" verkkoon kytkettyä laitetta.
Ennusteiden mukaan vuonna 2020 kytkettyjä laitteita voi olla jo 50 miljardia, elinaikanamme jo biljoona **9**.

## Literature on IoT in agriculture and food

IoT:tä käsittelevien julkaisujen määrä on noussut selvästi.
"In 2015 slightly fewer publications were found, while the number of journal papers increased." Tämä saattaa tarkoittaa, että maatalouden IoT:n tutkimus on kypsymässä.
Katsauksessa käsitellyistä kirjojen luvuista kaikki oli julkaistu muissa kuin maataloutta käsittelevissä kirjasarjoissa. Journal papers oli sekä maatalouden ja ruokatutkimuksen journal/lehtiä että IT-alan vastaavia.
Aasialaiset dominoivat, erityisesti kiinalaiset: vain 14 käsitellyistä papers/tutkimuksista (?) 168:sta oli muilta kuin aasialaisilta kirjoittajilta.
Muilla mantereilla IoT:n konsepti oli viime aikoihin asti EI-maataloustieteilijöiden aluetta.

### Application areas

Generally, it can be concluded that the area of food supply chains is addressed most frequently, followed by arable farming
* Agriculture in general
* Arable farming
* Agri-food supply chain
* Greenhouse horticulture
* Open air horticulture (incl. orchards)

#### "agriculture in general, 

several papers focus on 
precision agriculture [63, 67] or 
sensing and monitoring the production environment [64, 65, 68-71]. Others try to design a
general management information system based on IoT [55, 72, 73]. Other relevant themes that are touched upon are: 
product quality improvement [45], 
food safety and traceability [65, 74, 75], 
water management [60, 71], 
rural development [76], 
urban agriculture [77] and 
consumer interaction [37]."

#### "arable farming 

many papers are somehow dealing with 
monitoring & control using advanced IoT devices [16, 38, 78-86] sometimes supported by
predictive crop growth models [79, 87, 88]. Many are also focusing 
getting information in general from fields or farmlands [38, 81, 88-92]. Using these approaches, several papers are specifically applying IoT for 
sustainability management including ecology, biodiversity and natural resources, e.g. water [19, 43, 78, 82, 93, 94]. Some papers are dealing with 
IoT and precision agriculture in general [95-98] and other themes that are occasionally mentioned are pest management by early warning systems [16, 99], agricultural machinery [100] and data management [101]."

#### agri-food supply chain

"Most of the references that deal with the agri-food supply chain are focusing on food safety & quality [10, 22, 30-34, 42, 50, 58, 61, 62, 106-122]. This is probably due to the recent crises (e.g. baby milk powder) and food scandals in China. 
Many were also developing a concrete monitoring system for that purpose [10, 20, 42, 46, 50, 106, 108-110, 112, 113, 116, 118, 120]. 
Related to that some were specifically referring to hazard analysis and early warning systems [13, 109, 123]. 
Then there were a lot of references that dealt with tracking and tracing systems based on IoT [13, 15, 31, 32, 41, 45, 46, 49-52, 56-58, 84, 120, 122-131].
Several references relate to (cold chain) logistics and condition monitoring [26, 36, 49, 57, 121, 122, 129, 132-135], some specifically to transparency [136] and trust [137]. 
Some references were related to sustainability, i.c. environmental pollution [128, 138]. 
Other themes that were mentioned are social media & e-commerce [139], inventory management [120], shelf life [59, 140], consumer interaction [62] and virtualization [53, 141]."

#### greenhouse horticulture

Most of the references in the domain of greenhouse horticulture deal with monitoring and control of the greenhouse climate using advanced sensors for e.g. temperature, humidity and actuators for e.g. ventilation and irrigation [12, 35, 47, 142-148]. Some are aiming at a concrete management system [149, 150] or focus on energy management [140]. One reference deals with Big Data [29]

#### open air horticulture

"The same holds for open air horticulture (incl. orchards) focusing on monitoring & control of products [157-159]. Other themes that are mentioned are early warning and pest management [27, 160], traceability [161], expert systems and internet trading [162], micro-irrigation [14] and Big Data [160]."

**Leisure agriculture ja livestock farming jätetään pois.**

#### Teemat

"From the applications in the areas above several generic themes can be identified, in particular precision farming in arable- livestock farming and horticulture, food traceability, food safety and quality management and consumer interaction."
* Precision farming (in arable farming and horticulture)
* Food traceability systems
* Food safety and quality management systems
* Consumer interaction

### Mahdollistavat teknologiat (Enabling technologies)

"An IoT architecture can be subdivided into a device layer, network layer, and application layer (based on **6, 141**."
* Device layer
* Network layer
* Application layer

## Challenges ahead

Tarkasteltua kirjallisuutta dominoi julkaisut jotka esittelevät IoT-järjestelmäsuunnitelman tai jotka raportoivat IoT-implementoinneista prototyyppeinä tai pilotteina.
Katsauksessa käsiteltiin myös useita eksporatiivisia papereita, jotka käsittelevät IoT:n mahdollisuuksia maataloudessa yleisesti tai jollain nimenomaisella sovellusalueella.
Katsauksessa todettiin, että tekijöille saatavilla olevista papereista mikään ei sisältänyt systemaattista analyysiä IoT:n ongelmista ja haasteista maataloudessa.
Havaitut tai käsitellyt haasteet viittaavat siihen, että nykyiset IoT-sovellukset ja teknologioiat maatalouden alalla ovat usei pirstaleisia, vailla saumatonta integraatiota ja erityisesti edistyneemmät sovellukset ovat kokeellisissa vaiheissa. Toiminnalliset sovellukset ovat pääasiassa aikaisten omaksujien käytössä ja keskittyvät perustoiminnallisuuksiin hienorakeisella tasolla (?).

Tärkeitä haasteita nykyisessä tilanteessa on:

- Valtavan IoT-laitteiden ja datan heterogeenisyyden yhteentoimivuuden varmistaminen avoimilla IoT-arkkitehtuureilla, alustoilla ja standardeilla.

- Yhteentoimivien IoT-teknologioiden skaalaus aikaisten omaksujien ulkopuolelle, erityisesti nykyisten sovellusten yksinkertaistamisella sekä edullisuuden parantamisella loppukäyttäjille, varmistaen sopivuuden ja käytettävyyden suurimmalle osalle viljelijöitä ja ruoka-alan yrityksiä. Tästä syystä myös pienille yrityksille sopivia, systemaattisen ekonomisen analyysin kustannuksista ja hyödyistä sisältäviä, liiketoimintamalleja tarvitaan.

- IoT-teknologioiden edelleen kehitys laajan käytettävyyden saavuttamiseksi maatalouden monimuotoisessa käyttöympäristössä, esimerkiksi erilaiset ilmasto-olosuhteet, erilaiset satokasvit ja maaperät.

- IoT-laitteiden kehittäminen vaativiin olosuhteisiin ja luonnon objekteille (kasvit, eläimet, maapinta-ala, pilaantuvat ruokatuotteet) joihin itseensä laitteiden upottaminen/yhdistäminen on rajattua. Erityisesti laittelle, joissa sovelletaan viimeaikaista teknologista kehitystä, koska kypsempien teknologioiden sovelluksessa maatalouteen on jo paljon onnistumisia ja kehitystä.

+ Stabiilin ja luotettavan langattoman kehittäminen kaukaisille alueille, joihin on usein rajattu kenttä ja kaistanleveys.

- Energiatehokkaiden IoT-teknologioiden kehittäminen, mukaanlukien laitteiden ja yhteyksien kehittäminen maaseudun tarpeisiin.

+ Analytiikan kehittäminen yhdistämään esineiden data kolmannen osapuolen historia- ja ennustedatan kanssa, kuten satelliittidata, maaperä-, vesi- ja ilma-analyysit, logistiikkajärjestelmät, hintatietojen, vähittäismyynnin datan, kuluttajatietojen, ruokavaliotietojen jne.

- Luotettavan tietoturvan, yksityisyydensuojan ja datan omistajuuden ratkaisujen saatavuus, jotka soveltuvat dynaamisten ja monimutkaisten sidosryhmien verkostojen tarpeisiin kun sidosryhmiin kuuluu valtava määrä hyvin pieniä yrityksiä, suuria monikansallisia konserneja ja viranomaisia joiden kaikkien tulee toimia yhteistyössä.

## Conclusions

Katsauksen mukaan AIoT on saanut runsaasti huomiota tieteelliseltä yhteisöltä, erityisesti Kiinassa.

Yleisimmin käsitellyt aiheet olivat ruoan tuotantoketju sekä peltokasvituotanto.

Tuotantoketjun suuri esiintyminen tuloksissa voidaan selittää ruoan turvallisuuden ja ruoan laaduntarkkailun tärkeydellä.

Peltokasvituotannon esiintyminen tuloksissa voidaan selittää sillä, että IoT:n on usein katsottu täsmäviljelyn konseptin seuraavana kehitysvaiheena.

Tarkasteltua kirjallisuutta dominoi tutkimiseen liittyvät, eksporatiiviset paperit/julkaisut, jotka esittelevät IoT-järjestelmiä jotka on suunniteltu tai toteutettu prototyyppeinä tai pilotteina.

Tarkastellut paperit/julkaisut keskittyivät sensorointiin/mittaamiseen ja monitorointiin/tarkkailuun, aktuointia ja etäkontrollointia ei ollut käsitelty laajasti.

Tietoliikenneyhteyksistä painotus oli erilaisissa langattomissa verkkosovelluksissa/verkoissa.


Nämä havainnot osoittavat, että vaikka IoT kerää paljon huomiota, se on edelleen alkuvaiheessa maatalouden alalla.

Sovellukset ovat usein pirstaleisia, vailla saumatonta integraatiota ja erityisesti edistyneemmät sovellukset ovat kokeellisissa vaiheissa.

Keskeisimpiin/tärkeimpiin avoimiin haasteisiin kuuluvat:
* Olemassaolevien IoT-ratkaisuiden integraatio avoimilla IoT-arkkitehtuureilla, alustoilla ja standardeilla.
* Yhteentoimivien IoT-teknologioiden skaalaus aikaisten omaksujien ulkopuolelle, erityisesti nykyisten sovellusten yksinkertaistamisella sekä loppukäyttäjien maksamien hintojen alentamisella.
* IoT-teknologioiden edelleen kehitys laajan käytettävyyden saavuttamiseksi maatalouden monimuotoisessa käyttöympäristössä, esimerkiksi erilaiset ilmasto-olosuhteet, erilaiset satokasvit ja maaperät.
Suurin osa yleiskäyttöisistä teknologiakomponenteista (generic technology components) näiden haasteiden ratkaisemiseksi oletetaan olevan olemassa.

Maatalouden muuttuminen kytkettyjen esineiden älykkäiden tietoverkkojen toimi/teollisuudenalaksi tulee odotettavasti muuttamaan viljely- ja muita prosesseja ennennäkemättömällä tavalla, tuottaen uusia kontrollointimekanismeja ja liiketoimintamalleja.
Tekijät uskovat IoT:n muuttavan alaa, rajusti parantaen tuottavuutta ja kestävyyttä.
IoT auttaa viljelijöitä muuttamaan kohti datavetoista viljelyä, jota tukevat päätöksentekotyökalut ajankohtaisella ja tarkalla datalla.
Tämän seurauksena/tuloksena maatilat voivat poiketa perinteisestä tuotanto-orientoituneesta, kustannushintavetoisesta (cost price driven), anonyymistä lähestymistavasta kohti arvoperustaista, informaatiorikasta lähestymistapaa jossa kysyntä ja tarjonta on jatkuvasti kohdennettu toisiinsa. Lopulta maatilat ja ruokatuotantoketjut voivat tulla itsemukautuviksi järjestelmiksi joissa älykkäät, itsenäiset objektit, mukaanlukien maataloustyökoneet, voivat toimia, päättää ja jopa oppia ilman paikan päällä tapahtuvaa tai etänä tehtävää ihmisen puuttumista.








































