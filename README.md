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

## Propozycja środowiska testowego

Proponowanym środowiskiem testowym jest wirtualne Raspberry Pi, na którym zainstalowany zostanie serwer.

Pierwszym krokiem będzie stworzenie maszyny wirtualnej zgodnie z z poniższym artykułem:
https://raspberrytips.com/run-raspberry-in-virtual-machine/

W następnym kroku zainstalowany zostanie serwer www na podstawie następującego poradnika:
https://projects.raspberrypi.org/en/projects/lamp-web-server-with-wordpress

Po skonfigurowaniu środowiska, hasła, porty, etc. są "zapominane" - muszą być znalezione w trakcie pentestu.
Wyjątkiem jest IP, które ze względu na pracę zespołową na maszynach wirtualnych nie będzie stałe.
Zakładamy, że w innym wypadku scenariusz ten polegałby na znalezieniu IP w DMZ, którym byłaby sieć domowa testera maszyny wirtualnej.

