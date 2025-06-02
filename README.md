## How to run

```
docker build -t charm-crypto .
docker run -it --rm -v $(pwd)/output:/app/output charm-crypto
```

# System udostępniania danych z kontrolą dostępu opartą na kryptografii atrybutowej (ABE)

## Opis 
Celem projektu jest stworzenie systemu, który pozwala użytkownikom udostępniać zaszyfrowane dane (np. pliki, raporty, dane osobowe), ale tylko tym odbiorcom, którzy spełniają określone warunki — zamiast konkretnych kluczy, dostęp przyznawany jest na podstawie atrybutów (rola, dział, poziom uprawnień). 

## Wykorzystana technologia: 
Attribute-Based Encryption (ABE) – np. CP-ABE (Ciphertext-Policy) lub KP-ABE (Key-Policy), przy użyciu bibliotek typu Charm-Crypto lub pyAbe. 

## Zakres funkcjonalny: 

Generowanie kluczy dla użytkowników z zestawem atrybutów (np. "student", "admin", "dział=HR"). 

Szyfrowanie danych wg polityki dostępu (np. "dział=HR i stanowisko=manager"). 

Odszyfrowanie tylko wtedy, gdy klucz użytkownika spełnia politykę. 

Prosty interfejs (CLI lub GUI) do testowania różnych scenariuszy dostępu. 

## Przykład zastosowania: 

Udostępnianie danych w firmie lub uczelni bez konieczności ręcznego zarządzania listą odbiorców. 

Zabezpieczanie danych w chmurze bez polegania na zaufaniu wobec dostawcy. 

## Efekt końcowy: 

Działający system z możliwością testowania różnych polityk dostępu. 
