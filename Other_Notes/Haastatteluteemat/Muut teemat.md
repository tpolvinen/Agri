# Muut teemat

# H3

H3.10 ISOBUS-standardin haasteena on task:in *toimikäskyn?* muodostuminen reaaliaikaisesti ja vaikka teknisiä mahdollisuuksia tällaiseen toiminnallisuuteen on, niin ISOBUSia ei alun perin ole suunniteltu tällaiseen. Suunniteltu toimintamalli oli task-tiedoston kerralla siirtäminen, eikä jatkuvasti muuttuva ohjaus.

H3.11 Tästä esimerkkinä reaaliaikaisesti kasvustoja mittaava Yaran N-sensori, jonka kaltaisia laitteita on muillakin kuten Claasilla.

H3.44 Automaatiolaitteistojen hinnoissa on vielä aika paljon kehityskuluja ISOBUS-standardin 20 vuoden kehittämiskustannuksista, mitkä ovat vielä maksamatta.

H3.45 ISOBUS-kehitystyöhön on investoitu, eikä ole varmaa saavatko yritykset niitä rahoja takaisin. Massatuotannon avulla ISOBUS-laitteistojen hintojen pitäisi tulla alas, samaan tapaan kuin autoteollisuudessa ECU-laitteet.
Nyt pitäisi maatalousyksiköidenkin hintojen tulla alas, tai ottaa maataloudessa käyttöön samoja yksiköitä kuin autoissakin.

H3.46 Hintojen on oikeastaan tultava alas, samalla kun yritysten on saatava tutkimus- ja kehityskulut katettua. Tuotantosarjojen pituus on tässä avainasemassa.
ISOBUS-kehitystyössä tehdään yhteistyötä niin, että yksi taho valmistaa standardin mukaisia laitteita joille useat ohjelmistokehitystä tekevät toimijat tekevät sovelluksia.

H3.47 Konsortiotyöllä on mahdollista saada fyysisten laitteiden hintaa alas.

# H4

H4.28 *urbaaniviljely*
Loppujen lopuksi viljelyssä syötteitä tulisi olla vähemmän kuin samaa tuotetta tehtäisiin muualla ja tuotaisiin se paikan päälle.

H4.29 Salaatti tarvitsee sähköllä tuotettua valoa, vettä ja ravinteita. Ravinteita tarvitaan salaattiin vähemmän kuin tuotetussa salaatissa on, koska syötteitä tulee muualtakin *(?)*.
Kasvihuone- ja urbaaniviljelyssä ongelma on saada toiminnasta kannattavaa lopputuotteen vaatimilla syötteillä.

--- 

H3.5 ... Esimerkkinä peltoviljelyn maanäytetiedostojen tiedostoformaatti, jota käytetään tiedostojen siirrossa kentältä laboratorioon. Tiedostoformaatti kehitettiin joskus 80- ja 90-lukujen taitteessa ja oli tarkoitettu vain tietyn organisaation sisäiseen käytöön. Se on kuitenkin jäänyt alan standardiksi, vaikka sitä ei ole määritelty missään eikä kukaan ole kirjoittanut sitä auki.

H3.6 Toinen esimerkki on viljavuuspalvelun siirtotiedostoformaatti, jonka kehittäjät kuolivat kaikki samassa onnettomuudessa, eikä kehitystä enää saatu yhden tahon johdon alle.

H4.2 ... Traktoreiden automaatioteknologia tietokoneineen (vaihteisto-, moottori-, nostolaite-, ajotietokone) on integroitu itse traktoriin niin tiukasti, ettei käyttäjä edes huomaa käyttävänsä useita verkotettuja tietokoneita traktoria käyttäessään.

H3.22 Olen itse lähestynyt IoT-asioita lähinnä laitelähtöisesti, ns. rautatasolla. Pidän IoT-laitteen ominaisuuksina sen tietoisuutta sen tietoverkkoon kytkeytymistä sekä sen kykyä lähettää ja vastaanottaa viestejä tietoverkkon yli.
Hyvin yksinkertainen esimerkki voisi olla lämpötilaa mittaava laite, johon voidaan viitata IP-osoitteella ja saada laitteesta vastauksena tiedon sen olemassaolosta, toiminnallisuudesta ja mittauslukemia.

H3.23 Tällä hetkellä on käytössä paljon lämpötila-antureita, mutta niistä laitteista saadaan ulos *jänniteviesti*/volttiviesti ja ne laitteet eivät voi viestiä verkon yli ja sitä voisin pitää jonkinlaisena rajana.
Sovelluksen voi rakentaa alemman layerin/*tason* päälle.
Johtamisen mielessä laitteeseen ja sen toimintaan pitää pystyä vaikuttamaan.
Sovellus voi käyttää yhtä tai useampaa IoT-laitetta, joista se voi tallentaa tietoa *ja*/tai lähettää ohjeita toteutettaviksi.

H3.24 ... Esimerkiksi navetan ilmastointilaitteen tilasta olisi hyödyllistä sekä saada tieto että sen toimintaan vaikuttaa verkon ylitse. Samoin ruokintalaitteen toimintaan olisi hyödyllistä voida vaikuttaa sekä sen tilaa ja toimintaa tarkkailla. ...

H3.25 Viljakuivureissa on sovellettu automatiikkaa 70-luvulta lähtien. Alkuun toiminnallisuus on ollut relepohjaista ja säädettävät anturit ovat ohjanneet automatiikan toimintaa.
Tällä hetkellä suurimmassa osassa viljakuivureiden automatiikoissa käytetään ohjelmoitavaa logiikkaa, mutta anturointi voi olla vielä voltti/jänniteviesteillä havaintoja välittävää johtojen päässä olevaa tekniikkaa, eikä IoT-tekniikkaa jossa tieto liikkuisi verkon yli. *?*

H3.27 Jokaisella laitteella on käytännössä tällöin oma liittymä.
Maatilalla navetassa voi helposti olla 10 eri valmistajien laitetta, joilla on jokaisella oma liittymä ja SIM-kortti, esimerkiksi ilmanvaihdolle on oma, palohälyttimelle oma, ruokinta-automaatille oma, lypsyrobotille oma, toiselle lypsyrobotille toinen jne.
Liittymien kuukausimaksujen ollessa 10 € kuukaudessa näiden laitteiden vuosikustannukset muodostuvat viljelijälle jo huomattaviksi, erityisesti verrattaessa yksittäisten SMS-viestien hintaa IP-verkossa liikkuvien viestien hintaan.
IP-verkossa hinta on käytännössä vain verkon rakentamisen kertakustannus, kun käytössä ei ole datamäärään perustuvaa veloitusta.