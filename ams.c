#include "ams.h"

// Nikola Rebraca RA202/2015

int main() {

	int odabir;
	FAJL aktivna = newFajl();
	int adresaBloka = -1;
	int redniBrojSloga = -1;
	char kljuc[10];
	strcpy(kljuc, "");

	do {
		ispisiMeni();
		scanf(" %d", &odabir);
		fflush(stdin);

		if (odabir)
			odaberi(odabir, &aktivna, &adresaBloka, &redniBrojSloga, kljuc);
	} while (odabir);

	if (aktivna.fajl) {
		fclose(aktivna.fajl);
		printf("\n\n\tdatoteka '%s' je zatvorena\n\n", aktivna.naziv);
	}
	return EXIT_SUCCESS;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////
//	prikaz osnovnog menija
///////////////////////////////////////////////////////////////////////////////////////////////////////////
void ispisiMeni() {

	printf("\n\n\tMENI\todaberite neku od funkcionalnosti:\n");
	printf("\n\n\t> 1\tformiranje prazne datoteke\n");
	printf("\t> 2\tizbor aktivne datoteke\n");
	printf("\t> 3\tprikaz naziva aktivne datoteke\n");
	printf("\t> 4\tformiranje serijske datoteke\n");
	printf("\t> 5\tformiranje sekvencijalne datoteke\n");
	printf("\t> 6\tformiranje aktivne datoteke\n");
	printf("\t> 7\tupis novog sloga u aktivnu datoteku\n");
	printf("\t> 8\ttrazenje proizvoljnog sloga u aktivnoj datoteci\n");
	printf("\t> 9\tlogicko brisanje aktuelnog sloga iz aktivne datoteke\n");
	printf("\t> 10\tprikaz svih slogova aktivne datoteke\n");
	printf("\n\t> 0\tizlaz iz programa\n");
	printf("\n\n\t>> ");
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////
//	pozivanje odabrane procedure
///////////////////////////////////////////////////////////////////////////////////////////////////////////
void odaberi(int o, FAJL *aktivna, int *aB, int *rBS, char *kljuc) {

	switch (o) {
		case 1:  formirajPraznuDatoteku();		break;
		case 2:  izaberiAktivnuDatoteku(aktivna);	break;
		case 3:  prikaziNazivAktivneDatoteke(aktivna);	break;
		case 4:  formirajSerijskuDatoteku();		break;
		case 5:  formirajSekvencijalnuDatoteku();	break;
		case 6:  formirajAktivnuDatoteku(aktivna);	break;
		case 7:  upisiNoviSlog(aktivna);		break;
		case 8:  traziProizvoljniSlog(aktivna, aB, rBS, kljuc);	break;
		case 9:  obrisiAktuelniSlog(aktivna, aB, rBS, kljuc);	break;
		case 10: prikaziSveSlogove(aktivna);		break;
		default: printf("\n\n\n\tnepostojeci izbor, pokusajte ponovo\n");
	}
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////
//	formiranje prazne datoteke
///////////////////////////////////////////////////////////////////////////////////////////////////////////
void formirajPraznuDatoteku() {

	FILE *fajl = NULL;
	char naziv[21];

	printf("\n\n\tunesite naziv datoteke: ");
	scanf(" %s", naziv);
	fflush(stdin);

	fajl = fopen(naziv, "wb");		// binarno pisanje, kreira binarnu

	if (fajl) {
		printf("\n\n\n\tkreirana je datoteka '%s'\n", naziv);
		fclose(fajl);			// potrebno je samo kreirati, zatvori odmah potom
	} else {
		printf("\n\n\n\tkreiranje datoteke nije uspelo\n");
	}
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////
//	izbor aktivne datoteke
///////////////////////////////////////////////////////////////////////////////////////////////////////////
void izaberiAktivnuDatoteku(FAJL *aktivna) {

	if (aktivna->fajl) {
		fclose(aktivna->fajl);
		aktivna->fajl = NULL;
		printf("\n\n\n\tprethodno aktivna datoteka '%s' je zatvorena\n", aktivna->naziv);
		strcpy(aktivna->naziv, "");
	}

	printf("\n\n\tnaziv datoteke koju zelite da postavite za aktivnu: ");
	scanf(" %s", aktivna->naziv);
	fflush(stdin);

	if (access(aktivna->naziv, F_OK) == -1) {		// da li je moguce pristupiti datoteci
		printf("\n\n\n\tne postoji datoteka sa nazivom '%s'\n", aktivna->naziv);
		strcpy(aktivna->naziv, "");
	} else {
		aktivna->fajl = fopen(aktivna->naziv, "rb+");	// binarno citanje i pisanje
		printf("\n\n\n\tuspesno otvaranje, datoteka '%s' je aktivna\n", aktivna->naziv);
	}
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////
//	prikaz naziva aktivne datoteke
///////////////////////////////////////////////////////////////////////////////////////////////////////////
void prikaziNazivAktivneDatoteke(FAJL *aktivna) {

	if (aktivna->fajl) {
		printf("\n\n\n\taktivna datoteka je '%s'\n", aktivna->naziv);
	} else {
		printf("\n\n\n\tnijedna datoteka nije odabrana\n");
	}
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////
//	formiranje serijske datoteke
///////////////////////////////////////////////////////////////////////////////////////////////////////////
void formirajSerijskuDatoteku() {

	FAJL ser = newFajl();
	printf("\n\n\tunesite naziv serijske datoteke koju zelite da formirate: ");
	scanf(" %s", ser.naziv);
	fflush(stdin);

	ser.fajl = fopen(ser.naziv, "wb");		// binarno pisanje
	if(ser.fajl) {
		printf("\n\n\tdatoteka je kreirana, unesite podatke kako bi se formirao slog");
	} else {
		printf("\n\n\n\tdatoteka nije uspesno kreirana\n");
		return;
	}

	BLOK *trnBlk = NULL;		// pokazivac na blok koji se trenutno popunjava
	SLOG slg;			// slog koji se popunjava i potom upisuje u datoteku
	int brSlg = 0;			// broj slogova upisanih u trenutni blok
	int kljucevi[1000];		// niz kljuceva svih slogova upisanih u datoteku
	int brKlj = 0;			// ukupan broj kljuceva (slogova) u datoteci - duzina niza kljuceva
	int duplikat;			// indikator jedinstvenosti, stavlja se na 1 ako se kljuc ponovi
	int i;				// brojac za for petlje
	int jos;			// da li korisnik zeli da unese jos jedan slog
	char eb[20];			// string u koji se ucitava evidencioni broj
	int ieb;			// indikator ispravnosti evidencionog broja

	// unos sloga
	do {
		if (!trnBlk) {
			trnBlk = (BLOK*)malloc(sizeof(BLOK));
			for (i = 0; i < faktorBlokiranja; i++)
				trnBlk->slog[i] = newSlog();
		}

		// unos evidencionog broja
		do {
			duplikat = 0;
			do {		// evidencioni broj mora da sadrzi 9 cifara
				ieb = 0;
				printf("\n\n\tevidencioni broj (tacno 9 cifara): ");
				scanf(" %s", eb);
				fflush(stdin);

				if (strlen(eb) == 9)
					for (i = 0; i < 9; i++) {
						if (eb[i] < '0' || eb[i] > '9') {
							ieb = 1;
							printf("\n\n\tevidencioni broj ne moze da sadrzi druge znakove osim cifara");
							break;
						}
					}
				else {
					ieb = 1;
					printf("\n\n\tevidencioni broj mora da sadrzi tacno 9 cifara\n");
				}
			} while (ieb);

			slg.evidencioniBroj = atoi(eb);	// upis

			for (i = 0; i < brKlj; i++) {	// ev. broj mora biti jedinstven na nivou datoteke
				if (kljucevi[i] == slg.evidencioniBroj) {
					duplikat = 1;
					printf("\n\n\tevidencioni broj mora da bude jedinstven na nivou datoteke\n");
					break;
				}
			}
		} while (duplikat);

		kljucevi[brKlj] = slg.evidencioniBroj;	// dodaj ev. broj u listu kljuceva
		++brKlj;

		// unos ostatka sloga
		ucitajSlog(&slg);

		trnBlk->slog[brSlg] = slg;		// smesti slog u blok
		++brSlg;

		if (brSlg == faktorBlokiranja) {	// ako je blok popunjen, upisi ga u fajl
			fwrite(trnBlk, sizeof(BLOK), 1, ser.fajl);
			free(trnBlk);
			trnBlk = NULL;
			brSlg = 0;			// u novom bloku jos uvek nema slogova
		}

		char c;
		do {
			printf("\n\n\n\tslog je dodat\n");
			printf("\n\tzelite li da unesete jos jedan slog? (Y/n) >> ");
			scanf(" %c", &c);
			fflush(stdin);	// ocisti ulazni bafer

			if (c == 'y' || c == 'Y')
				jos = 1;
			else if (c == 'n' || c == 'N')
				jos = 0;
			else
				printf("\n\n\tneispravan unos, samo 'y' ako zelite ili 'n' ako ne zelite\n");
		} while (!(c == 'y' || c == 'Y' || c == 'n' || c == 'N'));
	} while (jos);

	printf("\n\n\n\tkreirana serijska datoteka - aktivnih slogova: %d, blokova: %d\n", brKlj, brKlj/5+1);

	if (brSlg == 0) {
	// ako je poslednji blok ceo popunjen, nemamo prazan slog kao indikator kraja datoteke
		free(trnBlk);
		trnBlk = (BLOK*)malloc(sizeof(BLOK));
		for (i = 0; i < faktorBlokiranja; i++)
			trnBlk->slog[i] = newSlog();
		fwrite(trnBlk, sizeof(BLOK), 1, ser.fajl);
		free(trnBlk);
	} else {
		fwrite(trnBlk, sizeof(BLOK), 1, ser.fajl);
		free(trnBlk);
	}

	fclose(ser.fajl);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////
//	ucitavanje ostatka sloga na osnovu evidencionog broja
///////////////////////////////////////////////////////////////////////////////////////////////////////////
void ucitajSlog(SLOG *slg) {

	int ieb, gd, ms, dn;
	char eb[20];

	// unos registarske oznake
	do {
		printf("\n\tregistarska oznaka vozila (do 10 znakova): ");
		scanf(" %s", eb);
		fflush(stdin);

		if (strlen(eb) > 10)
			printf("\n\n\tregistarska oznaka ne moze da ima vise od 10 karaktera\n");
	} while (strlen(eb) > 10);
	strcpy(slg->registracija, eb);		// upis registracije

	// unos datuma i vremena
	printf("\n\n\tunesite datum i vreme servisiranja\n");
	// godina
	do {
		printf("\n\tgodina (1920-2020): ");
		scanf(" %d", &gd);
		fflush(stdin);

	} while (gd < 1920 || gd > 2020);
	// mesec
	do {
		printf("\n\tmesec (1-12): ");
		scanf(" %d", &ms);
		fflush(stdin);

	} while (ms < 1 || ms > 12);
	// dan
	do {
		ieb = 0;
		printf("\n\tdan: ");
		scanf(" %d", &dn);
		fflush(stdin);

		ieb = dn < 1;
		if (ms == 1 || ms == 3 || ms ==5 || ms == 7 || ms == 8 || ms == 10 || ms == 12)
			ieb = ieb || dn > 31;
		else if (ms != 2)
			ieb = ieb || dn > 30;
		else {
			if(gd % 400 == 0)
				ieb = ieb || dn > 29;
			else if (gd % 100 == 0)
				ieb = ieb || dn > 28;
			else if(gd % 4 == 0)
				ieb = ieb || dn > 29;
			else
				ieb = ieb || dn > 28;
		}
	} while (ieb);
	// upis datuma
	if (dn > 9 && ms > 9)
		sprintf(slg->datum, "%d.%d.%d.", dn, ms, gd);
	else if (dn<10 && ms > 9)
		sprintf(slg->datum, "0%d.%d.%d.", dn, ms, gd);
	else if (dn<10 && ms < 10)
		sprintf(slg->datum, "0%d.0%d.%d.", dn, ms, gd);
	else
		sprintf(slg->datum, "%d.0%d.%d.", dn, ms, gd);
	// sati
	do {
		printf("\n\tsati (0-23): ");
		scanf(" %d", &dn);
		fflush(stdin);

	} while (dn < 0 || dn > 23);
	// minuti
	do {
		printf("\n\tminuta (0-59): ");
		scanf(" %d", &ms);
		fflush(stdin);

	} while (ms < 0 || ms > 59);
	// sekunde
	do {
		printf("\n\tsekundi (0-59): ");
		scanf(" %d", &gd);
		fflush(stdin);

	} while (gd < 0 || gd > 59);
	// upis vremena
	if (dn > 9 && ms > 9 && gd > 9)
		sprintf(slg->vreme, "%d:%d:%d", dn, ms, gd);
	else if (dn < 10)
		if (ms > 9 && gd > 9)
			sprintf(slg->vreme, "0%d:%d:%d", dn, ms, gd);
		else if (ms < 10 && gd > 9)
			sprintf(slg->vreme, "0%d:0%d:%d", dn, ms, gd);
		else if (ms < 10 && gd < 10)
			sprintf(slg->vreme, "0%d:0%d:0%d", dn, ms, gd);
		else
			sprintf(slg->vreme, "0%d:%d:0%d", dn, ms, gd);
	else if (ms < 10)
		if (gd > 9)
			sprintf(slg->vreme, "%d:0%d:%d", dn, ms, gd);
		else
			sprintf(slg->vreme, "%d:0%d:0%d", dn, ms, gd);
	else
		sprintf(slg->vreme, "%d:%d:0%d", dn, ms, gd);

	// unos oznake dodeljenog servisnog mesta
	do {
		printf("\n\toznaka servisnog mesta (tacno 7 znakova): ");
		scanf(" %s", eb);
		fflush(stdin);

		if (strlen(eb) != 7)
			printf("\n\n\toznaka servisnog mesta mora da ima tacno 7 karaktera\n");
	} while (strlen(eb) != 7);
	strcpy(slg->servisnoMesto, eb);		// upis oznake servisnog mesta

	// unos trajanja servisa u minutima
	do {
		printf("\n\tduzina trajanja serivisa u minutima (1 - 1000000): ");
		scanf(" %d", &(slg->trajanje));
		fflush(stdin);

	} while (slg->trajanje > 1000000 || slg->trajanje < 1);

	// postavljanje statusnog polja na 1, slog je aktivan
	slg->aktivan = 1;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////
//	formiranje sekvencijalne datoteke
///////////////////////////////////////////////////////////////////////////////////////////////////////////
void formirajSekvencijalnuDatoteku() {

	FAJL f = newFajl();
	printf("\n\n\tunesite naziv serijske datoteke: ");
	scanf(" %s", f.naziv);
	fflush(stdin);

	if (access(f.naziv, F_OK) == -1) {		// da li datoteka postoji
		printf("\n\n\n\tne postoji datoteka sa nazivom: %s\n", f.naziv);
		return;
	} else
		f.fajl = fopen(f.naziv, "rb");	// binarno citanje

	BLOK *blk = (BLOK*)malloc(sizeof(BLOK));
	LISTA *glava = NULL, *trenutni = NULL, *novi = NULL;
	int i;

	// citanje jednog po jednog bloka iz serijske datoteke
	while (fread(blk, sizeof(BLOK), 1, f.fajl)) {	// dok uspesno cita blokove

		for (i = 0; i < faktorBlokiranja; i++) {	// za svaki slog u bloku
			if (blk->slog[i].evidencioniBroj == -1) {
			// prazan slog ide na kraj datoteke
				trenutni = glava;
				if (trenutni) {
					while (trenutni->sled)
						trenutni = trenutni->sled;
					novi = (LISTA*)malloc(sizeof(LISTA));
					novi->slog = blk->slog[i];
					novi->sled = NULL;
					trenutni->sled = novi;
				} else {
					novi = (LISTA*)malloc(sizeof(LISTA));
					novi->slog = blk->slog[i];
					novi->sled = NULL;
					trenutni = novi;
				}
			}
			else if (!glava) {
			// prazna lista
				glava = (LISTA*)malloc(sizeof(LISTA));
				glava->sled = NULL;
				glava->slog = blk->slog[i];
			} else if (glava->slog.evidencioniBroj > blk->slog[i].evidencioniBroj) {
			// nova glava
				novi = (LISTA*)malloc(sizeof(LISTA));
				novi->sled = glava;
				novi->slog = blk->slog[i];
				glava = novi;
			} else {
			// nije glava
				trenutni = glava;
				while (trenutni->sled != NULL && trenutni->sled->slog.evidencioniBroj < blk->slog[i].evidencioniBroj)
					trenutni = trenutni->sled;
				if (trenutni->sled) {
				// treba da se umetne izmedju trenutnog i sledeceg
					novi = (LISTA*)malloc(sizeof(LISTA));
					novi->slog = blk->slog[i];
					novi->sled = trenutni->sled;
					trenutni->sled = novi;
				} else {
				// treba da se postavi na kraj liste
					novi = (LISTA*)malloc(sizeof(LISTA));
					novi->slog = blk->slog[i];
					novi->sled = NULL;
					trenutni->sled = novi;
				}
			}
		}
	}
	fclose(f.fajl);

	// napravi sekvencijalnu datoteku i upisi sortirane podatke iz dinamicke liste u nju
	printf("\n\n\tunesite naziv sekvencijalne: ");
	scanf(" %s", f.naziv);
	fflush(stdin);

	f.fajl = fopen(f.naziv, "wb");	// binarno pisanje
	if (!f.fajl) {
		printf("\n\n\n\tsekvencijalna datoteka nije uspesno kreirana\n");
		return;
	}
	trenutni = glava;
	i = 0;
	while(trenutni) {		// jedan po jedan slog iz liste se stavlja u blok
		blk->slog[i] = trenutni->slog;
		++i;
		if(i == faktorBlokiranja) {	// kada je blok pun, upisuje se u fajl
			fwrite(blk, sizeof(BLOK), 1, f.fajl);
			i = 0;
		}
		trenutni = trenutni->sled;
	}
	fclose(f.fajl);
	free(blk);

	printf("\n\n\n\tsekvencijalna datoteka '%s' je formirana\n", f.naziv);

	while (glava) {			// obrisi dinamicku listu
		trenutni = glava;
		glava = glava->sled;
		free(trenutni);
	}
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////
//	formiranje aktivne datoteke
///////////////////////////////////////////////////////////////////////////////////////////////////////////
void formirajAktivnuDatoteku(FAJL *aktivna) {

	if (!aktivna->fajl) {
		printf("\n\n\n\tprvo morate odabrati aktivnu datoteku\n");
		return;
	}

	char naziv[21];
	FAJL sekv = newFajl();
	printf("\n\n\tunesite naziv sekvencijalne datoteke: ");
	scanf(" %s", sekv.naziv);
	fflush(stdin);

	if (access(sekv.naziv, F_OK) == -1) {		// da li datoteka postoji
		printf("\n\n\n\tne postoji datoteka sa nazivom: %s\n", sekv.naziv);
		return;
	} else {
		sekv.fajl = fopen(sekv.naziv, "rb");	// binarno citanje
	}

	BLOK *blk = (BLOK*)malloc(sizeof(BLOK));;
	LISTLIST *glava = NULL, *trenutni = NULL, *novi = NULL;
	int brBlokova = 0;
	int brListova = 0;
	int kljuc;

	// u zaglavlje datoteke treba upisati adrese pocetaka svake od zona - za to ostavljam tri mesta velicine intidzera - primarna zona moze da krene nakon toga
	int primZona = 3*sizeof(int);
	fseek(aktivna->fajl, primZona, SEEK_SET);

	// citanje jednog po jednog bloka iz sekvencijalne datoteke i pisanje u primarnu zonu ind-sekv
	while (fread(blk, sizeof(BLOK), 1, sekv.fajl)) {

		fwrite(blk, sizeof(BLOK), 1, aktivna->fajl);

		// u dinamicku listu se smestaju listovi stabla trazenja
		if(brBlokova % 2 == 0) {    // levi element u listu
			if (!glava) {
				glava = (LISTLIST*)malloc(sizeof(LISTLIST));
				glava->sled = NULL;
				glava->list.primar.levi.adresa = primZona + brBlokova*sizeof(BLOK);
				kljuc = blk->slog[faktorBlokiranja-1].evidencioniBroj;
				// -1 je indikator kraja datoteke
				if (kljuc == -1)
					glava->list.primar.levi.kljuc = 999999999;
				else
					glava->list.primar.levi.kljuc = kljuc;

				glava->list.prekor.levi.adresa = glava->list.primar.levi.adresa;
				glava->list.prekor.levi.kljuc = glava->list.primar.levi.kljuc;
				trenutni = glava;
			} else {
				novi = (LISTLIST*)malloc(sizeof(LISTLIST));
				novi->sled = NULL;
				novi->list.primar.levi.adresa = primZona + brBlokova*sizeof(BLOK);

				kljuc = blk->slog[faktorBlokiranja-1].evidencioniBroj;
				// -1 je indikator kraja datoteke
				if (kljuc == -1)
					novi->list.primar.levi.kljuc = 999999999;
				else
					novi->list.primar.levi.kljuc = kljuc;

				novi->list.prekor.levi.adresa = novi->list.primar.levi.adresa;
				novi->list.prekor.levi.kljuc = novi->list.primar.levi.kljuc;
				trenutni->sled = novi;
				trenutni = trenutni->sled;
			}
			++brListova;
		}
		else {			    // desni element u listu
			trenutni->list.primar.desni.adresa = primZona + brBlokova*sizeof(BLOK);

			kljuc = blk->slog[faktorBlokiranja-1].evidencioniBroj;
			// -1 je indikator kraja datoteke
			if (kljuc == -1)
				trenutni->list.primar.desni.kljuc = 999999999;
			else
				trenutni->list.primar.desni.kljuc = kljuc;

			trenutni->list.prekor.desni.adresa = trenutni->list.primar.desni.adresa;
			trenutni->list.prekor.desni.kljuc = trenutni->list.primar.desni.kljuc;
		}
		++brBlokova;
	}
	fclose(sekv.fajl);
	free(blk);

	// neparan broj blokova => poslednji list pokazuje samo na jedan (levi) blok
	if (brBlokova % 2 != 0) {
		trenutni->list.primar.desni.kljuc = -1;
		trenutni->list.primar.desni.adresa = -1;
	}

	int visinaStabla = (int)ceil(log2(brBlokova));
	int brCvorova = 0;
	int i;
	for (i = 1; i < visinaStabla; i++)	// broj cvorova stabla ne racunajuci listove
		brCvorova += (int)ceil(brBlokova/pow(2.0, visinaStabla - i + 1));

	int pocetakZoneIndeksa = primZona + brBlokova*sizeof(BLOK);	// adresa na koju ce biti upisan koren stabla
	int adresaPrvogLista = pocetakZoneIndeksa + brCvorova*sizeof(CVOR);
	int adreseListova[brListova];
	int kljuceviListova[brListova];

	// u datoteku treba upisati listove iz dinamicke strukture podataka
	fseek(aktivna->fajl, adresaPrvogLista, SEEK_SET);	// pozicioniranje na mesto prvog lista
	trenutni = glava;
	i = 0;
	while (trenutni) {
		fwrite(&(trenutni->list), sizeof(LIST), 1, aktivna->fajl);

		if (trenutni->list.primar.desni.kljuc != -1)
			kljuceviListova[i] = trenutni->list.primar.desni.kljuc;
		else
			kljuceviListova[i] = trenutni->list.primar.levi.kljuc;
		adreseListova[i] = adresaPrvogLista + i*sizeof(LIST);

		++i;
		glava = trenutni;
		trenutni = trenutni->sled;
		free(glava);					// brisanje dinamicke liste
	}
	int pocetakZonePrekoracenja = (int)ftell(aktivna->fajl);	// zona prekoracenja pocinje iza poslednjeg lista stabla pretrazivanja, tojest iza zone indeksa

	// sada treba izgraditi ostatak stabla i upisati ga u datoteku
	izgradiStablo(aktivna, brListova, adreseListova, kljuceviListova);

	rewind(aktivna->fajl);	// pozicioniramo se na pocetak fajla
	// u zaglavlje datoteke upisujemo adrese pocetaka zona podataka, indeksa (koren) i prekoracenja (adresa prve slobodne lokacije)
	fwrite(&primZona, sizeof(int), 1, aktivna->fajl);
	fwrite(&pocetakZoneIndeksa, sizeof(int), 1, aktivna->fajl);
	fwrite(&pocetakZonePrekoracenja, sizeof(int), 1, aktivna->fajl);	// pocetak zone prekoracenja

	int prvaSlobodnaAdr = pocetakZonePrekoracenja + sizeof(int);
	fseek(aktivna->fajl, pocetakZonePrekoracenja, SEEK_SET);
	fwrite(&prvaSlobodnaAdr, sizeof(int), 1, aktivna->fajl);	// na samom pocetku zone prekoracenja se nalazi informacija o prvoj slobodnoj lokaciji

	printf("\n\n\n\tindeks-sekvencijalna datoteka '%s' je formirana\n", aktivna->naziv);
	rewind(aktivna->fajl);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////
//	formiranje ostatka stabla od listova ka korenu na osnovu listova
///////////////////////////////////////////////////////////////////////////////////////////////////////////
void izgradiStablo(FAJL *aktivna, int brPodredjenih, int *adresePodredjenih, int *kljuceviPodredjenih) {

	int brCvorova = (int)ceil(brPodredjenih/2.0);	// broj cvorova na trenutnom nivou

	int nepar = (brPodredjenih % 2 != 0) ? 1 : 0;

	int adresa = adresePodredjenih[0] - brCvorova*sizeof(CVOR);
	fseek(aktivna->fajl, adresa, SEEK_SET);

	if (brCvorova == 1) {		// stigli smo do korena, nema dalje - uslov za izlazak iz rekuzrije

		CVOR koren;

		koren.levi.adresa = adresePodredjenih[0];
		koren.levi.kljuc = kljuceviPodredjenih[0];

		koren.desni.adresa = adresePodredjenih[1];
		koren.desni.kljuc = kljuceviPodredjenih[1];

		fwrite(&koren, sizeof(CVOR), 1, aktivna->fajl);

		return;
	}

	CVOR cvorovi[brCvorova];
	int j, k = 0;
	int adrCvor[brCvorova];
	int kljCvor[brCvorova];

	for (j = 0; j < brCvorova-nepar; j++) {
		cvorovi[j].levi.adresa = adresePodredjenih[k];
		cvorovi[j].levi.kljuc = kljuceviPodredjenih[k];

		cvorovi[j].desni.adresa = adresePodredjenih[++k];
		cvorovi[j].desni.kljuc = kljuceviPodredjenih[k++];

		kljCvor[j] = cvorovi[j].desni.kljuc;	// narednom cvoru se prosledjuje kljuc iz desnog elementa
		adrCvor[j] = adresa + j*sizeof(CVOR);

		fwrite(&(cvorovi[j]), sizeof(CVOR), 1, aktivna->fajl);
	}

	// ako je u podnivou bio neparan broj cvorova, desni element poslednjeg cvora u ovom nivou ne pokazuje ni na jedan cvor, a kao kljuc iz ovog cvora u visi nivo se salje kljuc iz levog elementa podnivoa
	if (nepar) {
		cvorovi[j].levi.adresa = adresePodredjenih[k];
		cvorovi[j].levi.kljuc = kljuceviPodredjenih[k];

		cvorovi[j].desni.adresa = -1;
		cvorovi[j].desni.kljuc = -1;

		kljCvor[j] = cvorovi[j].levi.kljuc;	// kljuc iz LEVOG elementa
		adrCvor[j] = adresa + j*sizeof(CVOR);

		fwrite(&(cvorovi[j]), sizeof(CVOR), 1, aktivna->fajl);
		++j;
	}

	izgradiStablo(aktivna, brCvorova, adrCvor, kljCvor);
	rewind(aktivna->fajl);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////
//	upis novog sloga u aktivnu datoteku
///////////////////////////////////////////////////////////////////////////////////////////////////////////
void upisiNoviSlog(FAJL *aktivna) {

	if (!aktivna->fajl) {
		printf("\n\n\n\tprvo morate odabrati aktivnu datoteku\n");
		return;
	}

	SLOG slg = newSlog();
	int ieb, i;
	char eb[20];

	// 1
	// prvo unos kompletnog sloga

	// unos evidencionog broja
	do {		// evidencioni broj mora da sadrzi 9 cifara
		ieb = 0;
		printf("\n\n\tevidencioni broj (tacno 9 cifara): ");
		scanf(" %s", eb);
		fflush(stdin);

		if (strlen(eb) == 9)
			for (i = 0; i < 9; i++) {
				if (eb[i] < '0' || eb[i] > '9') {
					ieb = 1;
					printf("\n\n\tevidencioni broj ne moze da sadrzi druge znakove osim cifara");
					break;
				}
			}
		else {
			ieb = 1;
			printf("\n\n\tevidencioni broj mora da sadrzi tacno 9 cifara\n");
		}
	} while (ieb);

	slg.evidencioniBroj = atoi(eb);	// upis

	// unos ustatka sloga
	ucitajSlog(&slg);

	int kljuc = slg.evidencioniBroj;

	// 2
	// sada kad imamo slog, treba pronaci adresu bloka u kom cemo traziti slog
	int adresa;
	int adrLista;
	int prekoracioc;
	traziAdresuBloka(aktivna, kljuc, &adresa, &prekoracioc, &adrLista);

	// ako se ucitani blok nalazi u zoni podataka
	if (!prekoracioc) {

		// ucitaj blok
		BLOK *blk = (BLOK*)malloc(sizeof(BLOK));;
		fseek(aktivna->fajl, adresa, SEEK_SET);		// pozicioniranje na blok u primarnoj zoni
		fread(blk, sizeof(BLOK), 1, aktivna->fajl);	// citanje bloka iz primarne zone

		// pronadji slog u bloku ako ga ima i prebroj aktivne slogove
		int duplikat = 0;
		int aktivnih = 0;
		for (i = 0; i < faktorBlokiranja; i++) {
			if (blk->slog[i].aktivan) {
				++aktivnih;
				if (blk->slog[i].evidencioniBroj == kljuc) {
					duplikat = 1;
					break;
				}
			}
		}
		// ako je slog pronadjen, duplikat nece biti dodat
		if (duplikat) {
			printf("\n\n\n\tneuspesno dodavanje, slog sa kljucem '%s' vec postoji\n", eb);
			rewind(aktivna->fajl);
			return;
		} else {
			int j;
			if (aktivnih < faktorBlokiranja) {	// blok nije pun

				for (i = 0; i < faktorBlokiranja; i++)
					if (!blk->slog[i].aktivan) {
						blk->slog[i] = slg;	// ubaci novi slog na mesto prvog neaktivnog
						break;
					}

				// sortiraj blok pre upisa u primarnu zonu
				for (i = 0; i < faktorBlokiranja-1; i++)
					for (j = i+1; j < faktorBlokiranja; j++)
						if (blk->slog[j].evidencioniBroj == -1)
							break;	// prazni slogovi ostaju na kraju bloka
						else if (blk->slog[j].evidencioniBroj < blk->slog[i].evidencioniBroj) {
							slg = blk->slog[j];
							blk->slog[j] = blk->slog[i];
							blk->slog[i] = slg;
						}
				printf("\n\n\n\tslog je dodat u blok primarne zone sa adresom '%d'\n", adresa);

			} else {	// blok je pun

				BLOKPREKO bPrek;	// blok koji ide u zonu prekoracenja

				int prim = 0;

				if (slg.evidencioniBroj < blk->slog[faktorBlokiranja-1].evidencioniBroj) {
				// krajnji desni slog ispada iz bloka primarne zone
					bPrek.slog = blk->slog[faktorBlokiranja-1];
					blk->slog[faktorBlokiranja-1] = slg;

					prim = 1;

					// sortiraj blok pre upisa u primarnu zonu
					for (i = 0; i < faktorBlokiranja-1; i++)
						for (j = i+1; j < faktorBlokiranja; j++)
							if (blk->slog[j].evidencioniBroj < blk->slog[i].evidencioniBroj) {
								slg = blk->slog[j];
								blk->slog[j] = blk->slog[i];
								blk->slog[i] = slg;
							}
				} else	// u zonu prekoracenja ide novi slog, prvi prekoracioc poslednjeg bloka
					bPrek.slog = slg;

				LIST list;
				fseek(aktivna->fajl, adrLista, SEEK_SET);
				fread(&list, sizeof(LIST), 1, aktivna->fajl);

				int levi = 0;
				// novi najveci kljuc u bloku primarne zone
				if (list.primar.levi.adresa == adresa) {
					list.primar.levi.kljuc = blk->slog[faktorBlokiranja-1].evidencioniBroj;
					++levi;
				} else
					list.primar.desni.kljuc = blk->slog[faktorBlokiranja-1].evidencioniBroj;

				// da li je ovaj blok ranije imao prekoracioce?
				int jeste = 0;
				if (levi) {	// blok je levi element lista
					if (list.prekor.levi.adresa != list.primar.levi.adresa)
						++jeste;
				} else {	// blok je desni element lista
					if (list.prekor.desni.adresa != list.primar.desni.adresa)
						++jeste;
				}

				int adr;
				// adresa pocetka zone prekoracenja na kojoj je upisana adresa prve slobodne lokacije
				fseek(aktivna->fajl, 2*sizeof(int), SEEK_SET);
				fread(&adr, sizeof(int), 1, aktivna->fajl);

				fseek(aktivna->fajl, adr, SEEK_SET);
				fread(&adr, sizeof(int), 1, aktivna->fajl);
				// u "adr" se sada nalazi adresa prve slobodne lokacije, na nju ce biti upisan "bPrek"

				// uvezi prekoracioc i upisi ga u zonu prekoracenja
				if (jeste) {
					int adrPret;

					if (levi)
						adrPret = list.prekor.levi.adresa;
					else
						adrPret = list.prekor.desni.adresa;

					// novi prekoracioc sa najmanjim kljucem, postaje prvi u zoni prekoracenja
					bPrek.sled = adrPret;
					if (levi)
						list.prekor.levi.adresa = adr;
					else
						list.prekor.desni.adresa = adr;
					// azuriraj list
					fseek(aktivna->fajl, adrLista, SEEK_SET);
					fwrite(&list, sizeof(LIST), 1, aktivna->fajl);

					// upis u zonu prekoracenja
					fseek(aktivna->fajl, adr, SEEK_SET);
					fwrite(&bPrek, sizeof(BLOKPREKO), 1, aktivna->fajl);
				} else {	// prvi prekoracioc iz ovog bloka

					bPrek.sled = -1;

					// promeni adresu prekoracioca u listu stabla
					if (levi)
						list.prekor.levi.adresa = adr;
					else
						list.prekor.desni.adresa = adr;
					fseek(aktivna->fajl, adrLista, SEEK_SET);
					fwrite(&list, sizeof(LIST), 1, aktivna->fajl);

					// upisi blok u zonu prekoracenja
					fseek(aktivna->fajl, adr, SEEK_SET);
					fwrite(&bPrek, sizeof(BLOKPREKO), 1, aktivna->fajl);
				}
				// azuriraj adresu prve slobodne lokacije
				int slob = (int)ftell(aktivna->fajl);

				// adresa na kojoj je upisana adresa prve slobodne lokacije
				fseek(aktivna->fajl, 2*sizeof(int), SEEK_SET);
				fread(&j, sizeof(int), 1, aktivna->fajl);

				fseek(aktivna->fajl, j, SEEK_SET);
				fwrite(&slob, sizeof(int), 1, aktivna->fajl);

				if (prim)
					printf("\n\n\n\tslog je dodat u blok primarne zone sa adresom '%d'\n", adresa);
				else
					printf("\n\n\n\tslog je dodat kao prekoracioc bloka sa adrese '%d'\n\tna adresu '%d' u zonu prekoracenja\n", adresa, adr);
			}
			// upisi blok u primarnu zonu
			fseek(aktivna->fajl, adresa, SEEK_SET);
			fwrite(blk, sizeof(BLOK), 1, aktivna->fajl);
		}
		free(blk);
	} else {	// ucitani blok se nalazi u zoni prekoracenja

		BLOKPREKO bPrek;	// blok zone prekoracenja
		bPrek.slog = slg;

		LIST list;
		fseek(aktivna->fajl, adrLista, SEEK_SET);
		fread(&list, sizeof(LIST), 1, aktivna->fajl);

		// levi ili desni element u listu
		int levi = 0;
		int adrBloka;
		if (bPrek.slog.evidencioniBroj <= list.prekor.levi.kljuc) {
			++levi;
			adrBloka = list.primar.levi.adresa;
		} else
			adrBloka = list.primar.desni.adresa;
		int adr;
		// adresa pocetka zone prekoracenja na kojoj je upisana adresa prve slobodne lokacije
		fseek(aktivna->fajl, 2*sizeof(int), SEEK_SET);
		fread(&adr, sizeof(int), 1, aktivna->fajl);

		fseek(aktivna->fajl, adr, SEEK_SET);
		fread(&adr, sizeof(int), 1, aktivna->fajl);
		// u "adr" se sada nalazi adresa prve slobodne lokacije, na nju ce biti upisan "bPrek"

		// uvezi prekoracioc i upisi ga u zonu prekoracenja

		int adrPret;
		if (levi)
			adrPret = list.prekor.levi.adresa;
		else
			adrPret = list.prekor.desni.adresa;

		BLOKPREKO prethodni, sledeci;

		fseek(aktivna->fajl, adrPret, SEEK_SET);
		fread(&sledeci, sizeof(BLOKPREKO), 1, aktivna->fajl);

		prethodni.sled = -2;	// indikator - da li novi prekoracioc ima najmanji kljuc medju prekoracima istog bloka

		while (bPrek.slog.evidencioniBroj >= sledeci.slog.evidencioniBroj) {
			// kljuc mora da bude jedinstven
			if (bPrek.slog.evidencioniBroj == sledeci.slog.evidencioniBroj) {
				if (sledeci.slog.aktivan) {
					printf("\n\n\n\tneuspesno dodavanje, slog sa kljucem '%s' vec postoji\n", eb);
					rewind(aktivna->fajl);
					return;
				} else if (prethodni.sled == -2) {
					adr = adrPret;
				} else {
					adr = prethodni.sled;
				}
				bPrek.sled = sledeci.sled;

				fseek(aktivna->fajl, adr, SEEK_SET);
				fwrite(&bPrek, sizeof(BLOKPREKO), 1, aktivna->fajl);

				printf("\n\n\n\tslog je dodat kao prekoracioc bloka sa adrese '%d'\n\tna adresu '%d' u zonu prekoracenja\n", adrBloka, adr);
				rewind(aktivna->fajl);
				return;
			}
			if (sledeci.sled == -1)
				break;
			if (prethodni.sled != -2)
				adrPret = prethodni.sled;
			prethodni = sledeci;
			fseek(aktivna->fajl, prethodni.sled, SEEK_SET);
			fread(&sledeci, sizeof(BLOKPREKO), 1, aktivna->fajl);
		}

		if (bPrek.slog.evidencioniBroj > sledeci.slog.evidencioniBroj) {
		// ide na kraj liste
		// moguca situacija kod poslednjeg bloka ciji je kljuc u stablu "999999999"

			sledeci.sled = adr;
			bPrek.sled = -1;

			// azuriraj adresu narednog za "sledeci"
			if (prethodni.sled == -2) {
				if (levi)
					prethodni.sled = list.prekor.levi.adresa;
				else
					prethodni.sled = list.prekor.desni.adresa;
			}
			fseek(aktivna->fajl, prethodni.sled, SEEK_SET);
			fwrite(&sledeci, sizeof(BLOKPREKO), 1, aktivna->fajl);

			// upisi sad ovaj novi
			fseek(aktivna->fajl, adr, SEEK_SET);
			fwrite(&bPrek, sizeof(BLOKPREKO), 1, aktivna->fajl);
		} else if (prethodni.sled == -2) {
		// prekoracioc sa najmanjim kljucem

			bPrek.sled = adrPret;
			if (levi)
				list.prekor.levi.adresa = adr;
			else
				list.prekor.desni.adresa = adr;

			// azuriraj list
			fseek(aktivna->fajl, adrLista, SEEK_SET);
			fwrite(&list, sizeof(LIST), 1, aktivna->fajl);

			// upis u zonu prekoracenja
			fseek(aktivna->fajl, adr, SEEK_SET);
			fwrite(&bPrek, sizeof(BLOKPREKO), 1, aktivna->fajl);
		} else {
		// uvezuje se izmedju dva
			bPrek.sled = prethodni.sled;
			prethodni.sled = adr;

			//azuriraj adresu narednog za "prethodni"
			fseek(aktivna->fajl, adrPret, SEEK_SET);
			fwrite(&prethodni, sizeof(BLOKPREKO), 1, aktivna->fajl);

			// upisi "bPrek"
			fseek(aktivna->fajl, adr, SEEK_SET);
			fwrite(&bPrek, sizeof(BLOKPREKO), 1, aktivna->fajl);
		}

		// azuriraj adresu prve slobodne lokacije
		int slob = (int)ftell(aktivna->fajl);

		// adresa na kojoj je upisana adresa prve slobodne lokacije
		fseek(aktivna->fajl, 2*sizeof(int), SEEK_SET);
		fread(&adresa, sizeof(int), 1, aktivna->fajl);

		fseek(aktivna->fajl, adresa, SEEK_SET);
		fwrite(&slob, sizeof(int), 1, aktivna->fajl);

		printf("\n\n\n\tslog je dodat kao prekoracioc bloka sa adrese '%d'\n\tna adresu '%d' u zonu prekoracenja\n", adrBloka, adr);
	}
	rewind(aktivna->fajl);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////
//	trazenje adrese bloka na osnovu kljuca sloga
///////////////////////////////////////////////////////////////////////////////////////////////////////////
void traziAdresuBloka(FAJL *aktivna, int kljuc, int *adresa, int *prekoracioc, int *adrL) {

	int primZ;
	int koren;

	rewind(aktivna->fajl);
	fread(&primZ, sizeof(int), 1, aktivna->fajl);
	fread(&koren, sizeof(int), 1, aktivna->fajl);

	int brBlk = (koren - primZ)/sizeof(BLOK);		// broj blokova
	int visina = (int)ceil(log2(brBlk));			// visina stabla pretrage
	CVOR cvr;

	fseek(aktivna->fajl, koren, SEEK_SET);

	// spusti se do lista
	while(visina > 1) {
		fread(&cvr, sizeof(CVOR), 1, aktivna->fajl);

		if (kljuc <= cvr.levi.kljuc)
			*adresa = cvr.levi.adresa;
		else
			*adresa = cvr.desni.adresa;
		fseek(aktivna->fajl, *adresa, SEEK_SET);
		--visina;
	}

	LIST lst;
	fread(&lst, sizeof(LIST), 1, aktivna->fajl);

	*adrL = *adresa;
	*prekoracioc = 0;

	// iz lista preuzmi adresu bloka u zoni podataka ili prekoracenja
	if (kljuc <= lst.primar.levi.kljuc)
		*adresa = lst.primar.levi.adresa;
	else if (kljuc <= lst.prekor.levi.kljuc) {
		*adresa = lst.prekor.levi.adresa;
		*prekoracioc = 1;
	} else if (kljuc <= lst.primar.desni.kljuc)
		*adresa = lst.primar.desni.adresa;
	else {
		*adresa = lst.prekor.desni.adresa;
		*prekoracioc = 1;
	}
	rewind(aktivna->fajl);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////
//	trazenje proizvoljnog sloga u aktivnoj datoteci
///////////////////////////////////////////////////////////////////////////////////////////////////////////
void traziProizvoljniSlog(FAJL *aktivna, int *adrBlk, int *rBrSlg, char *evidBr) {

	if (!aktivna->fajl) {
		printf("\n\n\n\tprvo morate odabrati aktivnu datoteku\n");
		return;
	}

	char evBr[20];
	int ieb;
	int i;

	do {
		ieb = 0;
		printf("\n\n\tunesite evidencioni broj sloga: ");
		scanf(" %s", evBr);
		fflush(stdin);

		if (strlen(evBr) != 9)
			ieb = 1;
		else
			for (i = 0; i < 9; i++)
				if (evBr[i] < '0' || evBr[i] > '9') {
					ieb = 1;
					break;
				}
	} while (ieb);

	int kljuc = atoi(evBr);

	// sada kad imamo kljuc, treba pronaci adresu bloka u kom cemo traziti slog
	int adresa;
	int prekoracioc;
	int adrLista;

	traziAdresuBloka(aktivna, kljuc, &adresa, &prekoracioc, &adrLista);

	SLOG slogTr;
	slogTr.aktivan = 0;	// bice promenjeno ukoliko slog bude pronadjen

	if (!prekoracioc) {	// slog se nalazi u bloku primarne zone

		// citanje bloka primarne zone sa dobijene adrese
		BLOK blk;
		fseek(aktivna->fajl, adresa, SEEK_SET);		// pozicioniranje na blok u primarnoj zoni
		fread(&blk, sizeof(BLOK), 1, aktivna->fajl);	// citanje bloka iz primarne zone

		// pronadji slog u bloku ako ga ima
		for (i = 0; i < faktorBlokiranja; i++) {
			if (blk.slog[i].aktivan) {	// ne razmatramo neaktivne slogove (prazne i logicki obrisane)
				if (blk.slog[i].evidencioniBroj == kljuc) {
					slogTr = blk.slog[i];
					break;
				}
			}
		}
	} else {		// slog se nalazi u zoni prekoracenja

		// citanje prvog bloka iz zone prekoracenja
		BLOKPREKO blk;
		fseek(aktivna->fajl, adresa, SEEK_SET);
		fread(&blk, sizeof(BLOKPREKO), 1, aktivna->fajl);

		while (kljuc >= blk.slog.evidencioniBroj) {
			if (blk.slog.aktivan && kljuc == blk.slog.evidencioniBroj) {
				if (blk.slog.aktivan) {
					slogTr = blk.slog;
					i = -1;
				}
				break;
			}
			if (blk.sled == -1)
				break;
			adresa = blk.sled;
			fseek(aktivna->fajl, adresa, SEEK_SET);
			fread(&blk, sizeof(BLOKPREKO), 1, aktivna->fajl);
		}
	}

	// ako je pronadjen, smesten je u promenljivu "slogTr"
	if (slogTr.aktivan) {		// pronadjen je
		printf("\n\n\n\ttrazeni slog je pronadjen\n");
		ispisiSlog(slogTr, adresa, i+1, evBr);

		*adrBlk = adresa;
		strcpy(evidBr, evBr);
		*rBrSlg = i+1;	// bice 0 ako je slog prekoracioc
	} else {			// nema ga
		printf("\n\n\n\ttrazeni slog nije pronadjen\n");

		*adrBlk = -1;
		*rBrSlg = -1;
		strcpy(evidBr, "");
	}
	rewind(aktivna->fajl);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////
//	prikaz pojedinacnog sloga
///////////////////////////////////////////////////////////////////////////////////////////////////////////
void ispisiSlog(SLOG slog, int adr, int rbr, char *evbr) {

	printf("\n\tadresa bloka: %d", adr);

	if (rbr)
		printf("\n\tredni broj sloga u bloku: %d\n", rbr);
	else
		printf("\n\tprekoracioc\n");

	printf("\n\tevidencioni broj: %s", evbr);
	printf("\n\tregistarska oznaka: %s", slog.registracija);
	printf("\n\tdatum servisiranja: %s", slog.datum);
	printf("\n\tvreme servisiranja: %s", slog.vreme);
	printf("\n\toznaka servisnog mesta: %s", slog.servisnoMesto);
	printf("\n\ttrajanje servisa: %d min", slog.trajanje);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////
//	logicko brisanje aktuelnog sloga iz aktivne datoteke
///////////////////////////////////////////////////////////////////////////////////////////////////////////
void obrisiAktuelniSlog(FAJL *aktivna, int *adrBlk, int *rBrSlg, char *kljuc) {

	BLOK blok;
	BLOKPREKO blokP;

	if (!aktivna->fajl) {
		printf("\n\n\n\tnijedna datoteka nije aktivna\n");
		return;
	} else if (*adrBlk == -1 || *rBrSlg == -1 || strcmp(kljuc, "") == 0) {
		printf("\n\n\n\tnijedan slog nije aktuelan, pronadjite slog preko evidencionog broja\n");
		traziProizvoljniSlog(aktivna, adrBlk, rBrSlg, kljuc);

		if (*rBrSlg == -1) {
			return;
		} else if (!*rBrSlg) {
			fseek(aktivna->fajl, *adrBlk, SEEK_SET);
			fread(&blokP, sizeof(BLOKPREKO), 1, aktivna->fajl);
		} else {
			fseek(aktivna->fajl, *adrBlk, SEEK_SET);
			fread(&blok, sizeof(BLOK), 1, aktivna->fajl);
		}
	} else {
		printf("\n\n\n\taktuelni slog:\n\n");
		if (*rBrSlg) {
			fseek(aktivna->fajl, *adrBlk, SEEK_SET);
			fread(&blok, sizeof(BLOK), 1, aktivna->fajl);
			ispisiSlog(blok.slog[*rBrSlg - 1], *adrBlk, *rBrSlg, kljuc);
		} else {
			fseek(aktivna->fajl, *adrBlk, SEEK_SET);
			fread(&blokP, sizeof(BLOKPREKO), 1, aktivna->fajl);
			ispisiSlog(blokP.slog, *adrBlk, *rBrSlg, kljuc);
		}
	}

	int obrisi;
	char c;

	do {
		printf("\n\n\tsigurno zelite da obrisete ovaj slog? (Y/n) >> ");
		scanf(" %c", &c);
		fflush(stdin);	// ocisti ulazni bafer

		if (c == 'y' || c == 'Y')
			obrisi = 1;
		else if (c == 'n' || c == 'N')
			obrisi = 0;
		else
			printf("\n\n\tneispravan unos, samo 'y' ako zelite ili 'n' ako ne zelite\n");
	} while (!(c == 'y' || c == 'Y' || c == 'n' || c == 'N'));

	if (!obrisi) {
		*adrBlk = -1;
		*rBrSlg = -1;
		strcpy(kljuc, "");
		rewind(aktivna->fajl);
		return;
	}

	// logicko brisanje
	if (*rBrSlg) {
		blok.slog[*rBrSlg-1].aktivan = 0;

		fseek(aktivna->fajl, *adrBlk, SEEK_SET);
		if (fwrite(&blok, sizeof(BLOK), 1, aktivna->fajl) == 1) {
			printf("\n\n\n\tslog je logicki obrisan\n");
			*adrBlk = -1;
			*rBrSlg = -1;
			strcpy(kljuc, "");
		}
		else {
			printf("\n\n\n\tbrisanje neuspesno, doslo je do greske\n");
		}
	} else {
		blokP.slog.aktivan = 0;

		fseek(aktivna->fajl, *adrBlk, SEEK_SET);
		if (fwrite(&blokP, sizeof(BLOKPREKO), 1, aktivna->fajl) == 1) {
			printf("\n\n\n\tslog je logicki obrisan\n");
			*adrBlk = -1;
			*rBrSlg = -1;
			strcpy(kljuc, "");
		}
		else {
			printf("\n\n\n\tbrisanje neuspesno, doslo je do greske\n");
		}
	}
	rewind(aktivna->fajl);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////
//	prikaz svih slogova aktivne datoteke
///////////////////////////////////////////////////////////////////////////////////////////////////////////
void prikaziSveSlogove(FAJL *aktivna) {

	if (!aktivna->fajl) {
		printf("\n\n\n\tprvo morate odabrati aktivnu datoteku\n");
		return;
	}

	// iz zaglavlja se cita adresa pocetka zone podataka
	rewind(aktivna->fajl);		// na pocetak
	int primZona;
	fread(&primZona, sizeof(int), 1, aktivna->fajl);
	int indZona;
	fread(&indZona, sizeof(int), 1, aktivna->fajl);

	// sad se ispozicioniraj na pocetak primarne zone
	fseek(aktivna->fajl, primZona, SEEK_SET);

	BLOK blk;
	int i;
	char evbr[10];
	int kraj = 0;

	printf("\n\n\n\n\t* zona podataka:");

	while (fread(&blk, sizeof(BLOK), 1, aktivna->fajl)) {

		i = 0;
		printf("\n\n\n\n\t| adresa bloka: %d", (int)ftell(aktivna->fajl) - sizeof(BLOK));
		// trenutna adresa je umenjena za velicinu jednog bloka jer je fread() pomerila adresu nakon ucitavanja trenutnog bloka

		while (i < faktorBlokiranja) {

			if (blk.slog[i].aktivan && blk.slog[i].evidencioniBroj != -1) {	// ne ispisujemo neaktivne slogove, oni su logicki obrisani
				printf("\n\t|\n\t|\n\t|\n\t|\t| redni broj sloga: %d\n\t|\t|", i+1);

				// priprema evidencionog broja za stampu u punoj duzini sa nulama na vodecim pozicijama
				if (blk.slog[i].evidencioniBroj < 10)
					sprintf(evbr, "00000000%d", blk.slog[i].evidencioniBroj);
				else if (blk.slog[i].evidencioniBroj < 100)
					sprintf(evbr, "0000000%d", blk.slog[i].evidencioniBroj);
				else if (blk.slog[i].evidencioniBroj < 1000)
					sprintf(evbr, "000000%d", blk.slog[i].evidencioniBroj);
				else if (blk.slog[i].evidencioniBroj < 10000)
					sprintf(evbr, "00000%d", blk.slog[i].evidencioniBroj);
				else if (blk.slog[i].evidencioniBroj < 100000)
					sprintf(evbr, "0000%d", blk.slog[i].evidencioniBroj);
				else if (blk.slog[i].evidencioniBroj < 1000000)
					sprintf(evbr, "000%d", blk.slog[i].evidencioniBroj);
				else if (blk.slog[i].evidencioniBroj < 10000000)
					sprintf(evbr, "00%d", blk.slog[i].evidencioniBroj);
				else if (blk.slog[i].evidencioniBroj < 100000000)
					sprintf(evbr, "0%d", blk.slog[i].evidencioniBroj);
				else
					sprintf(evbr, "%d", blk.slog[i].evidencioniBroj);

				printf("\n\t|\t| evidencioni broj: %s", evbr);
				printf("\n\t|\t| registarska oznaka: %s", blk.slog[i].registracija);
				printf("\n\t|\t| datum servisiranja: %s", blk.slog[i].datum);
				printf("\n\t|\t| vreme servisiranja: %s", blk.slog[i].vreme);
				printf("\n\t|\t| oznaka servisnog mesta: %s", blk.slog[i].servisnoMesto);
				printf("\n\t|\t| trajanje servisa: %d min", blk.slog[i].trajanje);
			} else if (!blk.slog[i].aktivan && blk.slog[i].evidencioniBroj != -1) {
				printf("\n\t|\n\t|\n\t|\n\t|\t %d - obrisan slog", i+1);	// obrisan
			} else if (blk.slog[i].evidencioniBroj == -1) {
				printf("\n\t|\n\t|\n\t|\n\t|\t %d - prazan slog", i+1);		// prazan
			}

			++i;
		}
		if (indZona == (int)ftell(aktivna->fajl)) {
			printf("\n\n\n\t* kraj zone podataka");
			break;
		}
	}

	int slob, prek;
	fseek(aktivna->fajl, 2*sizeof(int), SEEK_SET);
	fread(&prek, sizeof(int), 1, aktivna->fajl);
	fseek(aktivna->fajl, prek, SEEK_SET);
	fread(&slob, sizeof(int), 1, aktivna->fajl);	// adresa prve slobodne lokacije
	prek = ftell(aktivna->fajl);			// adresa prvog bloka u zoni prekoracenja

	if (prek < slob) {
		printf("\n\n\n\n\n\t* zona prekoracenja:");

		BLOKPREKO bpr;
		while (prek < slob) {
			fread(&bpr, sizeof(BLOKPREKO), 1, aktivna->fajl);
			prek = ftell(aktivna->fajl);

			printf("\n\n\n\n\t| adresa : %d", prek - sizeof(BLOKPREKO));

			if (!bpr.slog.aktivan) {
				printf("\n\t|\n\t|\n\t|\n\t|\t| obrisan");
				printf("\n\t|\t|\n\t|\t| adresa sledeceg: %d", bpr.sled);
				continue;
			}

			// priprema evidencionog broja za stampu u punoj duzini sa nulama na vodecim pozicijama
			if (bpr.slog.evidencioniBroj < 10)
				sprintf(evbr, "00000000%d", bpr.slog.evidencioniBroj);
			else if (bpr.slog.evidencioniBroj < 100)
				sprintf(evbr, "0000000%d", bpr.slog.evidencioniBroj);
			else if (bpr.slog.evidencioniBroj < 1000)
				sprintf(evbr, "000000%d", bpr.slog.evidencioniBroj);
			else if (bpr.slog.evidencioniBroj < 10000)
				sprintf(evbr, "00000%d", bpr.slog.evidencioniBroj);
			else if (bpr.slog.evidencioniBroj < 100000)
				sprintf(evbr, "0000%d", bpr.slog.evidencioniBroj);
			else if (bpr.slog.evidencioniBroj < 1000000)
				sprintf(evbr, "000%d", bpr.slog.evidencioniBroj);
			else if (bpr.slog.evidencioniBroj < 10000000)
				sprintf(evbr, "00%d", bpr.slog.evidencioniBroj);
			else if (bpr.slog.evidencioniBroj < 100000000)
				sprintf(evbr, "0%d", bpr.slog.evidencioniBroj);
			else
				sprintf(evbr, "%d", bpr.slog.evidencioniBroj);

			printf("\n\t|\n\t|\t\n\t|\t| evidencioni broj: %s", evbr);
			printf("\n\t|\t| registarska oznaka: %s", bpr.slog.registracija);
			printf("\n\t|\t| datum servisiranja: %s", bpr.slog.datum);
			printf("\n\t|\t| vreme servisiranja: %s", bpr.slog.vreme);
			printf("\n\t|\t| oznaka servisnog mesta: %s", bpr.slog.servisnoMesto);
			printf("\n\t|\t| trajanje servisa: %d min", bpr.slog.trajanje);
			printf("\n\t|\t|\n\t|\t| adresa sledeceg: %d", bpr.sled);
		}
	}

	printf("\n\n\n\t* kraj datoteke\n");

	rewind(aktivna->fajl);
}

