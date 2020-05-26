# Bezpieczeństwo IoT
Repozytorium projektu z przedmiotu BOT. 

Temat: bezpieczeństwo IoT. 

Grupa: J. Kulawik, W. Szałyga

## Cele projektu:
- Zapoznanie się z dostępnymi gotowymi rozwiązaniami usług sieciowych w IoT
- Zapoznanie się ze specyfiką bezpieczeństwa w takich usługach
- Zaznajomienie się z rozwiązaniami wirtualizacji IoT lub instalacją oprogramowania na hardwarze
- Trening audytu środowiska bez celowo wystawionych podatności

## Zakres projektu
- Przegląd oraz wybór oprogramowania do przetestowania z zakresu IoT 

   Przykładowo, może być to:

  * gotowe oprogramowanie serwera/brokera
  * zintegrowane lub oddzielne od OS
  * maszyna wirtualna bądź rzeczywista instalacja na hardwarze  
- Pentest wybranego rozwiązania wraz z raportem

Zakres rozszerzony zrealizowany podczas realizacji celów:

- Tworzenie maszyny wirtualnej
- Zaznajomienie z podstawami konfiguracji sieciowej serwera Apache oraz systemu Linux

## Propozycja środowiska testowego

Dokonano przeglądu technologii wirtualizacyjnych IoT. Ze względu na małą dostępność maszyn  wirtualnych IoT, zdecydowano się na stworzenie własnej za pomocą obrazu systemu operacyjnego.

Proponowanym środowiskiem testowym jest wirtualny system Debian używany na płytkach Raspberry Pi - tzw. Raspbian.
Zgodnie ze wspomnianym poniżej poradnikiem zostanie na nim zainstalowany serwer HTTP typu LAMP.

> *P.S. Podczas dalszych badań odkryto technologię Docker oraz oparty na niej, dedykowany dla IoT system balenaOS. Mechanizmy wykorzystywane przez Dockera zdają się być rozwiązaniem bardzo bezpiecznym, dlatego testy aplikacji zbudowanej w kontenerze baleny mogą być ciekawym tematem na przyszłe projekty.*

Test będzie przeprowadzony w stylu greybox - siłą rzeczy znane są pewne szcegóły środowiska (w szcególności elementy konfiguracji sieciowej).
Nie będzie wykorzystywana wiedza na temat haseł oraz loginów - żeby je wykorzystać, muszą zostać wydobyte w trakcie testu.
Ze względu na infrastrukturę sieciową maszyn wirtualnych, test ten odpowiada połączeniu się do sieci np. Wi-fi organizacji/właściciela oraz testowaniu znajdującego się w niej serwera.

## Scenariusz 

Niedoświadczony w zarządzaniu użytkownik stawia prosty serwer na płytce Raspberry Pi.
Pozostawione są domyślne opcje sugerowane przez popularny poradnik ze strony RPi:
https://projects.raspberrypi.org/en/projects/lamp-web-server-with-wordpress

Sprawdzone zostanie bezpieczeństwo takiego rozwiązania, w tym instalowanej strony Wordpress.

## Przygotowania maszyny wirtualnej

Pierwszym krokiem jest stworzenie maszyny wirtualnej zgodnie z z poniższym artykułem:
https://raspberrytips.com/run-raspberry-in-virtual-machine/

Maszynie nadano 1GB RAM (zgodnie z jednym z tańszych modeli RPi).

Za pomocą generatora liczb losowych na hasło użytkownika wybrano nr. 20 (tj. "welcome") z [listy dwudziestu pięciu najpopularniejszych haseł roku 2019 wg. firmy Splashdata.](https://www.prweb.com/releases/what_do_password_and_president_trump_have_in_common_both_lost_ranking_on_splashdatas_annual_worst_passwords_list/prweb16794349.htm)

Logowanie do bazy danych wykonywane jest za pomocą polecenia ```mysql -uroot -p```.
Konto administratora Wordpress utworzono pod nazwą 'admin' oraz wg. wskazówek ustawiono "wystarczająco silne" hasło: 'Reks\o1997'
W rejestracji wybrano email jednego z członków grupy. Zgodnie z założeniem, dane te nie zostaną wykorzystane w penteście o ile nie zostaną podczas niego znalezione zdalnie.

Dla ułatwienia testowania, w ustawieniach strony Wordpress (Settings/General) zmieniono adres URL na `http://rpi.bot`.
Domyślne ustawienie `http://localhost` sprawiało bowiem problem z testowaniem na innych maszynach.
Następnie w pliku `/etc/hosts/` (zarówno na maszynie do testowania jak i maszynie testowanej) dodano linijkę, która rozwiązuje adres IP testowanego systemu na nazwę `rpi.bot` (a raczej vice-versa).

## Skanowanie

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


## Testowanie aplikacji internetowej

W testowaniu wstrzyknięć SQL przydatna będzie [wiedza o budowie baz danych wordpress](https://wp-staging.com/docs/the-wordpress-database-structure/).
