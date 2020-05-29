# Bezpieczeństwo IoT
Repozytorium projektu z przedmiotu BOT. 

Temat: bezpieczeństwo IoT. 

Grupa: J. Kulawik, W. Szałyga

# Cele projektu:
- Zapoznanie się z dostępnymi gotowymi rozwiązaniami usług sieciowych w IoT
- Zapoznanie się ze specyfiką bezpieczeństwa w takich usługach
- Zaznajomienie się z rozwiązaniami wirtualizacji IoT lub instalacją oprogramowania na hardwarze
- Trening audytu środowiska bez celowo wystawionych podatności

# Zakres projektu
- Przegląd oraz wybór oprogramowania do przetestowania z zakresu IoT 

   Przykładowo, może być to:

  * gotowe oprogramowanie serwera/brokera
  * zintegrowane lub oddzielne od OS
  * maszyna wirtualna bądź rzeczywista instalacja na hardwarze  
- Pentest wybranego rozwiązania wraz z raportem

Zakres rozszerzony zrealizowany podczas realizacji celów:

- Tworzenie maszyny wirtualnej
- Zaznajomienie z podstawami konfiguracji sieciowej serwera Apache oraz systemu Linux

# Propozycja środowiska testowego

Dokonano przeglądu technologii wirtualizacyjnych IoT. Ze względu na małą dostępność maszyn  wirtualnych IoT, zdecydowano się na stworzenie własnej za pomocą obrazu systemu operacyjnego.

Proponowanym środowiskiem testowym jest wirtualny system Debian używany na płytkach Raspberry Pi - tzw. Raspbian.
Zgodnie ze wspomnianym poniżej poradnikiem zostanie na nim zainstalowany serwer HTTP typu LAMP.

> *P.S. Podczas dalszych badań odkryto technologię Docker oraz oparty na niej, dedykowany dla IoT system balenaOS. Mechanizmy wykorzystywane przez Dockera zdają się być rozwiązaniem bardzo bezpiecznym, dlatego testy aplikacji zbudowanej w kontenerze baleny mogą być ciekawym tematem na przyszłe projekty.*

Test będzie przeprowadzony w stylu greybox - siłą rzeczy znane są pewne szcegóły środowiska (w szcególności elementy konfiguracji sieciowej).
Nie będzie wykorzystywana wiedza na temat haseł oraz loginów - żeby je wykorzystać, muszą zostać wydobyte w trakcie testu.
Ze względu na infrastrukturę sieciową maszyn wirtualnych, test ten odpowiada połączeniu się do sieci np. Wi-fi organizacji/właściciela oraz testowaniu znajdującego się w niej serwera.

# Scenariusz 

Niedoświadczony w zarządzaniu użytkownik stawia prosty serwer na płytce Raspberry Pi.
Pozostawione są domyślne opcje sugerowane przez popularny poradnik ze strony RPi:
https://projects.raspberrypi.org/en/projects/lamp-web-server-with-wordpress

Sprawdzone zostanie bezpieczeństwo takiego rozwiązania, w tym instalowanej strony Wordpress.

# Przygotowania maszyny wirtualnej

Pierwszym krokiem jest stworzenie maszyny wirtualnej zgodnie z z poniższym artykułem:
https://raspberrytips.com/run-raspberry-in-virtual-machine/

Maszynie nadano 1GB RAM (zgodnie z jednym z tańszych modeli RPi).

Za pomocą generatora liczb losowych na hasło użytkownika wybrano nr. 20 (tj. "welcome") z [listy dwudziestu pięciu najpopularniejszych haseł roku 2019 wg. firmy Splashdata.](https://www.prweb.com/releases/what_do_password_and_president_trump_have_in_common_both_lost_ranking_on_splashdatas_annual_worst_passwords_list/prweb16794349.htm)

Logowanie do bazy danych wykonywane jest za pomocą polecenia ```mysql -uroot -p```.
Konto administratora Wordpress utworzono pod nazwą `admin` oraz wg. wskazówek ustawiono "wystarczająco silne" hasło: `Reks\o1997`
W rejestracji wybrano email jednego z członków grupy. Zgodnie z założeniem, dane te nie zostaną wykorzystane w penteście o ile nie zostaną podczas niego znalezione zdalnie.

Dla ułatwienia testowania, w ustawieniach strony Wordpress (Settings/General) zmieniono adres URL na `http://rpi.bot`.
Domyślne ustawienie `http://localhost` sprawiało bowiem problem z testowaniem na innych maszynach.
Następnie w pliku `/etc/hosts/` (zarówno na maszynie do testowania jak i maszynie testowanej) dodano linijkę, która rozwiązuje adres IP testowanego systemu na nazwę `rpi.bot` (a raczej vice-versa).

## Dodawanie użytkowników

W trakcie testów dodano również użytkownika testowego Wordpress o nazwie `NeilBarney`. Wordpress oferuje dobry podział przywilejów w opcjach konta, nowe konto jest jednak zakładane jako symulacja nieodpowiedzialnego sub-administratora w celu poszerzenia zakresu testu.
Użytkownikowi nadano e-mail ze strony GuerillaMail. Strona nie miała z tym problemu, co nie jest dobre - GuerillaMail to serwis tymczasowych kont e-mail, który jest używany do tworzenia alternatywnych tożsamości oraz innych kont złośliwych. Ponieważ jednak dodawanie użytkowników jest na badanej stronie manualne, można na to przymknąć oko. 

Użytkownikowi nadano hasło `qwerty123` (wybrane z tej samej listy co wcześniej, tym razem przez rzut czterema kośćmi z wynikiem 12). Strona ta ma dobry system oceniania haseł, który sprawdza entropię wpisywanego hasła oraz wymaga potwierdzenia nadania hasła słabego. Jest to dobra praktyka, którą celowo ominięto na korzyść testu - można jednak podejrzewać, że użytkownik dla wygody mógłby zrobić podobnie.

Konto to zostało dodane podczas testu, więc nie jest ono wylistowane w niektórych skanach.

# Skanowanie

Przeprowadzono skany TCP oraz UDP całej sieci. Jak można się było spodziewać, znaleziono jedynie usługę HTTP na porcie 80:

```
kali@kali:~/Desktop$ sudo nmap -sV -p-  192.168.56.133
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-22 06:33 EDT
Nmap scan report for rpi.bot (192.168.56.133)
Host is up (0.0021s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
MAC Address: 00:0C:29:60:C2:44 (VMware)
```                     
Skan UDP zwrócił wiele portów typu filtrowane/otwarte. Biorąc pod uwagę, że wynik ten jest dla UDP zwracany kiedy brak jest odpowiedzi, z pewną dozą pewności można powiedzieć że usługi te w systemie nie działają. Jedny otwarty port to NTP:
```
kali@kali:~/Desktop$ sudo nmap -sUV -F  192.168.56.133
(...)
PORT      STATE         SERVICE         VERSION
123/udp   open          ntp             NTP v4 (unsynchronized)
```

<details>
  <summary>[Rozwiń listę wszystkich przeskanowanych portów]</summary>
   
```
kali@kali:~/Desktop$ sudo nmap -sUV -F  192.168.56.133
(...)
PORT      STATE         SERVICE         VERSION
53/udp    open|filtered domain
67/udp    open|filtered dhcps
68/udp    open|filtered dhcpc
69/udp    open|filtered tftp
80/udp    open|filtered http
88/udp    open|filtered kerberos-sec
111/udp   open|filtered rpcbind
123/udp   open          ntp             NTP v4 (unsynchronized)
135/udp   open|filtered msrpc
137/udp   open|filtered netbios-ns
139/udp   open|filtered netbios-ssn
161/udp   open|filtered snmp
177/udp   open|filtered xdmcp
500/udp   open|filtered isakmp
623/udp   open|filtered asf-rmcp
626/udp   open|filtered serialnumberd
996/udp   open|filtered vsinet
999/udp   open|filtered applix
1025/udp  open|filtered blackjack
1028/udp  open|filtered ms-lsa
1029/udp  open|filtered solid-mux
1030/udp  open|filtered iad1
1645/udp  open|filtered radius
1646/udp  open|filtered radacct
1718/udp  open|filtered h225gatedisc
1719/udp  open|filtered h323gatestat
1812/udp  open|filtered radius
2000/udp  open|filtered cisco-sccp
2222/udp  open|filtered msantipiracy
2223/udp  open|filtered rockwell-csp2
3283/udp  open|filtered netassistant
3456/udp  open|filtered IISrpc-or-vat
4444/udp  open|filtered krb524
5353/udp  open|filtered zeroconf
5632/udp  open|filtered pcanywherestat
20031/udp open|filtered bakbonenetvault
30718/udp open|filtered unknown
31337/udp open|filtered BackOrifice
32768/udp open|filtered omad
32769/udp open|filtered filenet-rpc
32815/udp open|filtered unknown
49154/udp open|filtered unknown
49181/udp open|filtered unknown
49186/udp open|filtered unknown
49192/udp open|filtered unknown
49193/udp open|filtered unknown
49194/udp open|filtered unknown
49200/udp open|filtered unknown
```
</details>

## Nikto

Dokonano skanu strony internetowej za pomocą narzędzia Nikto. 

<details>
<summary>[Rozwiń listę wyników]</summary>

```
---------------------------------------------------------------------------
+ Target IP:          192.168.56.133
+ Target Hostname:    rpi.bot
+ Target Port:        80
+ Start Time:         2020-05-27 09:52:39 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.38 (Debian)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'link' found, with multiple values: (<http://rpi.bot/wp-json/>; rel="https://api.w.org/",<http://rpi.bot/>; rel=shortlink,)
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Uncommon header 'x-redirect-by' found, with contents: WordPress
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Entry '/wp-admin/' in robots.txt returned a non-forbidden or redirect HTTP code (302)
+ "robots.txt" contains 2 entries which should be manually viewed.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-3233: /icons/README: Apache default file found.
+ /wp-links-opml.php: This WordPress script reveals the installed version.
+ OSVDB-3092: /license.txt: License file found may identify site software.
+ /wp-app.log: Wordpress' wp-app.log may leak application/system details.
+ /wordpresswp-app.log: Wordpress' wp-app.log may leak application/system details.
+ /: A Wordpress installation was found.
+ /wordpress: A Wordpress installation was found.
+ Cookie wordpress_test_cookie created without the httponly flag
+ OSVDB-3268: /wp-content/uploads/: Directory indexing found.
+ /wp-content/uploads/: Wordpress uploads directory is browsable. This may reveal sensitive information
+ /wp-login.php: Wordpress login found
+ 7790 requests: 0 error(s) and 19 item(s) reported on remote host
+ End Time:           2020-05-27 09:56:15 (GMT-4) (216 seconds)
---------------------------------------------------------------------------
```
</details>

W skan sugeruje warte przetestowania adresy oraz podatności. W szczególności znaleziono potencjalne podatności: XSS, enumaracja użytkowników, ujawnienie danych o serwerze (w tym również plik robots.txt), ciasteczka bez http-only (pozwala na kradzież ciasteczek z użyciem skryptów). 

## WPScan

Przeprowadzono skany silnika Wordpress za pomocą narzędzia WPScan.

<details>
<summary>[Rozwiń listę wyników]</summary>
   
```
_______________________________________________________________

[+] URL: http://rpi.bot/
[+] Started: Wed May 27 09:43:57 2020

Interesting Finding(s):

[+] http://rpi.bot/
 | Interesting Entry: Server: Apache/2.4.38 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] http://rpi.bot/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] http://rpi.bot/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] http://rpi.bot/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://rpi.bot/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] http://rpi.bot/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.1 identified (Latest, released on 2020-04-29).
 | Found By: Rss Generator (Passive Detection)
 |  - http://rpi.bot/feed/, <generator>https://wordpress.org/?v=5.4.1</generator>
 |  - http://rpi.bot/comments/feed/, <generator>https://wordpress.org/?v=5.4.1</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://rpi.bot/wp-content/themes/twentyseventeen/
 | Latest Version: 2.3 (up to date)
 | Last Updated: 2020-03-31T00:00:00.000Z
 | Readme: http://rpi.bot/wp-content/themes/twentyseventeen/readme.txt
 | Style URL: http://rpi.bot/wp-content/themes/twentyseventeen/style.css?ver=20190507
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 2.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://rpi.bot/wp-content/themes/twentyseventeen/style.css?ver=20190507, Match: 'Version: 2.3'
```
</details>

Skan dostarczył przede wszystkim kilku nowych stron wartych przetestowania. Szczególnie interesująca może być strona XML-RPC (remote procedure call). Już sama nazwa technologii wskazuje na potencjalną obecność podatności. Istotnym elementem jest również strona `readme.html` - więcej w podatności

Sprawdzono również metody enumeracji oferowane przez narzędzie. Powiodła się jedynie enumeracja użytkowników (wyniki w podatnościach).

## Pełzacz internetowy

Stronę przeskanowano również za pomocą narzędzia *msfcrawler*.

<details>
<summary>Rozwiń mapę strony</summary>

```
[*] Target: rpi.bot Port: 80 Path: / SSL: 
[*] >> [200] /
[*] >> [200] /
[*] >> [200] /about/
[*] >> [200] /blog/
[*] >> [200] /contact/
[*] >> [200] /hello-world/
[*] >> [200] /
[*] >>> [Q] s=
[*] >> [200] /wp-content/themes/twentyseventeen/assets/images/header.jpg
[*] >> [200] /feed/
[*] >> [200] /comments/feed/
[*] >> [200] /wp-includes/css/dist/block-library/style.min.css
[*] >>> [Q] ver=5.4.1
[*] >> [200] /wp-includes/css/dist/block-library/theme.min.css
[*] >>> [Q] ver=5.4.1
[*] >> [200] /wp-content/themes/twentyseventeen/style.css
[*] >>> [Q] ver=20190507
[*] >> [200] /wp-content/themes/twentyseventeen/assets/css/blocks.css
[*] >>> [Q] ver=20190105
[*] >> [200] /wp-content/themes/twentyseventeen/assets/css/colors-dark.css
[*] >>> [Q] ver=20190408
[*] >> [200] /wp-json/
[*] >> [200] /xmlrpc.php
[*] >>> [Q] rsd
[*] >> [200] /wp-includes/wlwmanifest.xml
[*] >> [200] /wp-json/oembed/1.0/embed
[*] >>> [Q] url=http%3A%2F%2Frpi.bot%2F
[*] >> [200] /wp-includes/js/jquery/jquery.js
[*] >>> [Q] ver=1.12.4-wp
[*] >> [200] /wp-includes/js/jquery/jquery-migrate.min.js
[*] >>> [Q] ver=1.4.1
[*] >> [200] /wp-content/themes/twentyseventeen/assets/js/skip-link-focus-fix.js
[*] >>> [Q] ver=20161114
[*] >> [200] /wp-content/themes/twentyseventeen/assets/js/navigation.js
[*] >>> [Q] ver=20161203
[*] >> [200] /wp-content/themes/twentyseventeen/assets/js/global.js
[*] >>> [Q] ver=20190121
[*] >> [200] /wp-content/themes/twentyseventeen/assets/js/jquery.scrollTo.js
[*] >>> [Q] ver=2.1.2
[*] >> [200] /wp-includes/js/wp-embed.min.js
[*] >>> [Q] ver=5.4.1
[*] >> [301] /
[*] >>> [Q] p=7
[301] Redirection to: http://rpi.bot/about/
[*] >> [200] /wp-json/oembed/1.0/embed
[*] >>> [Q] url=http%3A%2F%2Frpi.bot%2Fabout%2F
[*] >> [200] /wp-content/uploads/2020/05/download.png
[*] >> [301] /
[*] >>> [Q] p=8
[301] Redirection to: http://rpi.bot/contact/
[*] >> [200] /wp-json/oembed/1.0/embed
[*] >>> [Q] url=http%3A%2F%2Frpi.bot%2Fcontact%2F
[*] >> [200] /author/admin/
[*] >> [200] /tag/welcome/
[*] >> [200] /hello-world/
[*] >>> [Q] replytocom=1
[*] >> [200] /wp-comments-post.php
[*] >>> [D] author=&email=&url=&wp-comment-cookies-consent=yes&submit=Post%20Comment&comment_post_ID=1&comment_parent=0
[*] >> [200] /hello-world/feed/
[*] >> [301] /
[*] >>> [Q] p=1
[301] Redirection to: http://rpi.bot/hello-world/
[*] >> [200] /wp-json/oembed/1.0/embed
[*] >>> [Q] url=http%3A%2F%2Frpi.bot%2Fhello-world%2F
[*] >> [200] /wp-includes/js/comment-reply.min.js
[*] >>> [Q] ver=5.4.1
[*] >> [200] /the-new-umoma-opens-its-doors-2/
[*] >> [200] /a-homepage-section/
[*] >> [200] /sample-page/
[*] >> [200] /search/feed/rss2/
[*] >> [200] /author/admin/feed/
[*] >> [200] /tag/welcome/feed/
[*] >> [200] /hello-world/
[*] >> [200] /wp-comments-post.php
[*] >>> [D] author=&email=&url=&wp-comment-cookies-consent=yes&submit=Post%20Comment&comment_post_ID=1&comment_parent=1
[*] >> [405] /xmlrpc.php
[*] Unhandled 405
[*] >> [200] /wp-content/uploads/2020/05/2020-landscape-1.png
[*] >> [301] /
[*] >>> [Q] p=6
[301] Redirection to: http://rpi.bot/the-new-umoma-opens-its-doors-2/
[*] >> [200] /wp-json/oembed/1.0/embed
[*] >>> [Q] url=http%3A%2F%2Frpi.bot%2Fthe-new-umoma-opens-its-doors-2%2F
[*] >> [200] /wp-content/uploads/2020/05/espresso.jpg
[*] >> [301] /
[*] >>> [Q] p=15
[301] Redirection to: http://rpi.bot/a-homepage-section/
[*] >> [200] /wp-json/oembed/1.0/embed
[*] >>> [Q] url=http%3A%2F%2Frpi.bot%2Fa-homepage-section%2F
[*] >> [200] /sample-page/feed/
[*] >> [301] /
[*] >>> [Q] p=2
[301] Redirection to: http://rpi.bot/sample-page/
[*] >> [200] /wp-json/oembed/1.0/embed
[*] >>> [Q] url=http%3A%2F%2Frpi.bot%2Fsample-page%2F
```
</details>

## Przegląd manualny

Inne strony warte sprawdzenia:

- Strona wyszukiwania - `http://rpi.bot/?s=search-term` - 
- Sekcja komentarzy pod blogiem, np. `http://rpi.bot/hello-world/`

# Znalezione false positives
- Katalog `/wp-content/uploads/` został sprawdzony pod kątem directory traversal. Strona reaguje poprawnie, tzn. czyści zapytanie z elementów `../` oraz przekierowuje najdalej do strony głównej. Zawiera on dane wysłane przez administratorów, tj. obrazki załączane do bloga.
- Pliki `/wp-app.log`, `/wordpresswp-app.log`,  nie są dostępne
- Plik `/wp-cron.php` jest pusty. Jest to skrypt, który odpowiada za planowanie zadań. Aktualnie nie są znane żadne związane z nim podatności, jednak [jego domyślna konfiguracja może być wykorzystana do ataku DDoS](https://medium.com/@thecpanelguy/the-nightmare-that-is-wpcron-php-ae31c1d3ae30).
- Katalogi `/icons` oraz `/wordpress` nie są dostępne
- Skrypt `/wp-links-opml.php` oraz plik  `license.txt` zdają się nie ujawniać danych wrażliwych 
- Zawartość pliku `robots.txt`: 
```
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
```
Na chwilę obecną informacje te zdają się nie być wrażliwe.
- Interfejs `/xmlrpc.php` ma liczne znane podatności, jednak zdaje się być wyłączony bądź skonfigurowany w sposób bezpieczny.

- Plik `/wp-config.php` zwraca pustą zawartość.

Inne testy podatności:
(...)

# Zagrożenia

## Wzór opisu zagrożenia (nazwa tutaj)
**Stopień zagrożenia:**  - CVSS  (Wektor: `DoubleClickMe`)

**Położenie:**

**Opis:**

**Koncepcja:**

**Zalecenia:**

## Jawna transmisja danych
**Stopień zagrożenia:** Średni - CVSS 5.9 (Wektor: `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N`)

**Położenie:** `/wp-login.php`

**Opis:** Strona nie jest szyfrowana. Dane logowania są transmitowane tekstem jawnym.

**Koncepcja:** Przeglądarka zwraca uwagę na niezabezpieczoną komunikację. Za pomocą programu Wireshark przechwycono próbę logowania: 

![alt text](https://github.com/jkulawik/BOT-IoT/blob/master/encr.PNG)

Jak widać, dane logowania nie są zabezpieczone.

**Zalecenia:** Implementacja HTTPS, pozyskanie certyfikatu strony

## Enumeracja użytkowników
**Stopień zagrożenia:** Średni - CVSS 5.3 (Wektor: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`)

**Położenie:** `/wp-login.php`

**Opis:** Interfejs logowania pozwala na obecność użytkowników w systemie.

**Koncepcja:** Testowano LDAP injection. Sprawdzono nazwę użytkownika `admin)(&)` z losowym hasłem. Zwróciła ona błąd `Unknown username. Check again or try your email address.`, który różni się od błędu który wyświetla się w przypadku niepoprawnego hasła oraz poprawnego loginu, np. "admin": `Error: The password you entered for the username admin is incorrect`. Następnie sprawdzono dwadzieścia parę niepoprawnych nazw kont - zwracały ten sam błąd co wspomniany na początku.

Podatność ta może być wykorzystana automatycznie za pomocą narzędzia WPScan. Polecenie `wpscan --url rpi.bot --enumerate u` zwraca następujące wyniki:

```
[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://rpi.bot/wp-json/wp/v2/users/?per_page=100&page=1
 |  Oembed API - Author URL (Aggressive Detection)
 |   - http://rpi.bot/wp-json/oembed/1.0/embed?url=http://rpi.bot/&format=json
 |  Rss Generator (Aggressive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)
 
 [+] neilbarney
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```
Należy zwrócić uwagę, że źródła tych dwóch metod enumaracji mogą być różne i wymagać oddzielnych napraw.

**Zalecenia:** Ograniczenie nieudanych liczb logowania. Przykładowo: tymczasowa blokada prób logowania dla jednego adresu IP wypadku przekroczenia dozwolonej liczby nieudanych prób logowania na nieistniejące konto.

[Poradniki zabezpieczania blogów Wordpress](https://www.getastra.com/blog/cms/wordpress-security/stop-user-enumeration/) sugerują zmianę pewnych adresów URL, ręcznie bądź z pomocą wtyczki. 

## Ujawnienie wrażliwych interfejsów
**Stopień zagrożenia:** Brak - CVSS 0.0

**Położenie:** Strona `/readme.html`

**Opis:** Strona zdradza wrażliwe elementy serwisu.

**Koncepcja:** Strona `/readme.html` jest pozostałością po procesie instalacji i zawiera potencjalnie podatne informacje oraz wiele z linków, które są rozpoznawane przez automatyczne skanery.

**Zalecenia:** Jako pozostałość po procesie instalacji, omawiana strona powinna zostać usunięta.

## Ujawnienie plików PHP
**Stopień zagrożenia:** Średni - CVSS 5.3 (Wektor: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`)

**Położenie:** `rpi.bot/wp-includes/`

**Opis:** Dostępny jest katalog z indeksem plików wykonawczych serwera.

**Koncepcja:** Strona wyświetla listę plików, które wykonują różne funkcje serwera "od zaplecza". Kod tych plików nie jest możliwy do zobaczenia z przeglądarki, ponieważ zwracane są puste pliki.

**Zalecenia:** [Ukrycie wspomnianego folderu.](https://wordpress.org/support/article/hardening-wordpress/#securing-wp-includes)


