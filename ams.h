#ifndef AMS_H_INCLUDED
#define AMS_H_INCLUDED

// Nikola Rebraca RA202/2015

#include <stdio.h>
#include <stdlib.h>
#include <string.h>			// strlen(), strcpy(), strcat(), strcmp(), sprintf()
#include <unistd.h>			// access()
#include <math.h>			// ceil(), log2(), pow()

#define faktorBlokiranja 5

// strukture
typedef struct Slog {

	int aktivan;			// statusno polje, posmatrano kao boolean
	int evidencioniBroj;		// 9 cifara
	char registracija[11];		// do 10 znakova
	char datum[12];			// dd.mm.yyyy.
	char vreme[9];			// hh:mm:ss
	char servisnoMesto[8];		// 7 znakova
	int trajanje;			// u minutima, do 1 000 000
}SLOG;

typedef struct Blok {			// blok u serijskoj, sekvencijalnoj i primarnoj zoni indeks-sekvencijalne datoteke
	SLOG slog[faktorBlokiranja];
}BLOK;

typedef struct Fajl {			// pokazivac na fajl i naziv fajla
	FILE *fajl;
	char naziv[21];
}FAJL;

typedef struct Lista {			// jednostruko spregnuta lista slogova
	SLOG slog;
	struct Lista *sled;
}LISTA;

typedef struct SlogId {			// slog u zoni indeksa
	int kljuc;
	int adresa;
}SLOGID;

typedef struct Cvor {			// cvor stabla trazenja
	SLOGID levi;
	SLOGID desni;
}CVOR;

typedef struct List {			// list stabla trazenja
	CVOR primar;
	CVOR prekor;
}LIST;

typedef struct ListaListova {		// dinamicka lista listova
	LIST list;
	struct ListaListova *sled;
}LISTLIST;

typedef struct BlokPreko {		// blok u zoni prekoracilaca
	SLOG slog;
	int sled;
}BLOKPREKO;

// "konstruktori" - inicijalizuju instance struktura
FAJL newFajl() {
	FAJL f;
	f.fajl = NULL;
	strcpy(f.naziv, "");
	
	return f;
}
SLOG newSlog() {
	SLOG s;
	
	s.aktivan = 0;
	s.evidencioniBroj = -1;		// kljuc praznog sloga (indikator kraja ser. i sek. datoteke)
	strcpy(s.registracija, "");
	strcpy(s.datum, "dd.mm.yyyy.");
	strcpy(s.vreme, "hh:mm:ss");
	strcpy(s.servisnoMesto, "");
	s.trajanje = 0;

	return s;
}

// deklaracije procedura
void ispisiMeni();
void odaberi(int o, FAJL*, int*, int*, char*);
void formirajPraznuDatoteku();
void izaberiAktivnuDatoteku(FAJL*);
void prikaziNazivAktivneDatoteke(FAJL*);
void formirajSerijskuDatoteku();
void ucitajSlog(SLOG*);
void formirajSekvencijalnuDatoteku();
void formirajAktivnuDatoteku(FAJL*);
void izgradiStablo(FAJL*, int, int*, int*);
void upisiNoviSlog(FAJL*);
void traziAdresuBloka(FAJL*, int, int*, int*, int*);
void traziProizvoljniSlog(FAJL*, int*, int*, char*);
void ispisiSlog(SLOG, int, int, char*);
void obrisiAktuelniSlog(FAJL*, int*, int*, char*);
void prikaziSveSlogove(FAJL*);


#endif

