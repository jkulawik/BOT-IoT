# Bezpieczeństwo IoT
Repozytorium projektu z przedmiotu BOT. 

Temat: bezpieczeństwo IoT. 

Grupa: J. Kulawik, W. Szałyga

## Cele projektu:
- Zapoznanie się z dostępnymi gotowymi rozwiązaniami usług sieciowych w IoT
- Zapoznanie się ze specyfiką bezpieczeństwa w takich usługach
- Zaznajomienie się z rozwiązaniami wirtualizacji IoT lub instalacją oprogramowania na hardwarze
- Trening audytu
- ...

## Zakres projektu
- Przegląd oraz wybór oprogramowania do przetestowania z zakresu IoT 

   Przykładowo, może być to:

  * gotowe oprogramowanie serwera/brokera
  * zintegrowane lub oddzielne od OS
  * maszyna wirtualna bądź rzeczywista instalacja na hardwarze  
- Pentest wybranego rozwiązania wraz z raportem
- ...

## Scenariusz 

Niedoświadczony w zarządzaniu użytkownik stawia prosty serwer na płytce Raspberry Pi.
Pozostawione są domyślne opcje sugerowane przez popularny poradnik ze strony RPi:
https://projects.raspberrypi.org/en/projects/lamp-web-server-with-wordpress

Sprawdzone zostanie bezpieczeństwo takiego rozwiązania, w tym instalowanej strony Wordpress.

## Propozycja środowiska testowego

Proponowanym środowiskiem testowym jest wirtualny system Debian używany na płytkach Raspberry Pi.
Zgodnie ze wspomnianym wyżej poradnikiem zostanie na nim zainstalowany serwer.

Po skonfigurowaniu środowiska, hasła, porty, etc. są "zapominane" - muszą być znalezione w trakcie pentestu.
Wyjątkiem jest IP, które ze względu na pracę zespołową na maszynach wirtualnych nie będzie stałe.
Zakładamy, że w innym wypadku scenariusz ten polegałby na znalezieniu IP w DMZ, którym byłaby sieć domowa testera maszyny wirtualnej.

## Przygotowania maszyny wirtualnej

Pierwszym krokiem jest stworzenie maszyny wirtualnej zgodnie z z poniższym artykułem:
https://raspberrytips.com/run-raspberry-in-virtual-machine/

Maszynie nadano 1GB RAM (zgodnie z jednym z tańszych modeli RPi).

Za pomocą generatora liczb losowych na hasło użytkownika wybrano nr. 20 (tj. "welcome") z [listy dwudziestu pięciu najpopularniejszych haseł roku 2019 wg. firmy Splashdata.](https://www.prweb.com/releases/what_do_password_and_president_trump_have_in_common_both_lost_ranking_on_splashdatas_annual_worst_passwords_list/prweb16794349.htm)

Logowanie do bazy danych wykonywane jest za pomocą polecenia ```mysql -uroot -p```.
Konto administratora Wordpress utworzono pod nazwą 'admin' oraz wg. wskazówek ustawiono "wystarczająco silne" hasło: 'Reks\o1997'
W rejestracji wybrano email jednego z członków grupy. Zgodnie z założeniem, dane te nie zostaną wykorzystane w penteście o ile nie zostaną podczas niego znalezione zdalnie.

## Skanowanie

(COMING SOON)

## Testowanie aplikacji internetowej

W testowaniu wstrzyknięć SQL przydatna będzie [wiedza o budowie baz danych wordpress](https://wp-staging.com/docs/the-wordpress-database-structure/).
