#include <stdio.h>
#include <stdarg.h>

float detect_version(FILE *fin)
{
	fseek(fin, 0xDA0DD, SEEK_SET);
	if (getc(fin) == 0x32)
		return 2.0f;

	// Check CM 97/98
	fseek(fin, 0x14559B, SEEK_SET);
	if (getc(fin) == '3' || getc(fin) == '4')
		return 2.93f;

	return -1;
}

void write_byte(FILE* fin, long pos, int byte)
{
	fseek(fin, pos, SEEK_SET);
	putc(byte, fin);
}

void write_bytes(FILE* fin, long pos, int numberofbytes, ...)
{
	fseek(fin, pos, SEEK_SET);

	va_list vl;
    va_start(vl, numberofbytes);

	for (int i = 0; i < numberofbytes; i++)
		putc(va_arg(vl, int), fin);

	va_end(vl);
}

int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		printf("Usage: CM2YEAR CM2.EXE <Year>\n");
		return -1;
	}

	printf("CM2YEAR - Championship Manager 2 - Start Year Changer\n");
	printf("Version 0.3 - By Nick+Co\n\n");

	FILE *fin = fopen(argv[1], "r+b");
	if (fin)
	{
	       // Get Year from arguments
	       int year;
	       sscanf(argv[2], "%d", &year);

	       // Detect CM2 Version
	       float version = detect_version(fin);

	       int real_year;
	       if (version == 2.0f)
	       {
			real_year = 96 + ((year - 1996) % 4);
			write_byte(fin, 0x64b69, real_year);

			int base_year = 1900 + (year - 1996) - (real_year - 96);
			write_byte(fin, 0x37841, (base_year - 0x700));
			write_byte(fin, 0x4F59A, (base_year - 0x700));
			write_byte(fin, 0x54A1C, (base_year - 0x700));
			write_byte(fin, 0x57109, (base_year - 0x700));
			write_byte(fin, 0x57172, (base_year - 0x700));
			write_byte(fin, 0x57580, (base_year - 0x700));
			write_byte(fin, 0x57599, (base_year - 0x700) + 1);

			// Make it so it's "Season 2020/21" rather than "Season 2020/1"
			write_byte(fin, 0x575E6, 0x90);
			write_byte(fin, 0x575E7, 0x90);
			write_byte(fin, 0x575EA, 0x02);
			write_byte(fin, 0x575EB, 0x7c);

			write_byte(fin, 0x57651, 0x83);
			if (year >= 1996)
			{
				write_byte(fin, 0x57652, 0xc2);
				write_byte(fin, 0x57653, (year - 1996) - (real_year - 96));
			}
			else
			{
				write_byte(fin, 0x57652, 0xea);
				write_byte(fin, 0x57653, (1996 - year) - (real_year - 96));
			}
			write_byte(fin, 0x57654, 0x83);
			write_byte(fin, 0x57655, 0xfa);
			write_byte(fin, 0x57656, 0x64);
			write_byte(fin, 0x57657, 0x7c);
			write_byte(fin, 0x57658, 0x03);
			write_byte(fin, 0x57659, 0x83);
			write_byte(fin, 0x5765a, 0xea);
			write_byte(fin, 0x5765b, 0x64);
			write_byte(fin, 0x5765c, 0x66);

			write_byte(fin, 0x576CE, (base_year - 0x700));
			write_byte(fin, 0x5EE2C, (base_year - 0x700));
			write_byte(fin, 0x5F0A4, (base_year - 0x700));
			write_byte(fin, 0x7A346, (base_year - 0x700));
			write_byte(fin, 0x8030E, (base_year - 0x700));

			fclose(fin);
	       }
	       else if (version == 2.93f)
	       {
				// Set the real year it will start from
				if (year == 2021)
				{
					// Set year to '97 and Day to Friday (so starts Fri 16th July 2021)
					real_year = 97;
					write_byte(fin, 0xAB0EE, 6);
				}
				else
					real_year = 97 + ((year - 1997) % 4);
				write_byte(fin, 0xAB085, real_year);

				// set 1900 back to account for it (e.g. add ecx, 76Ch)
				int base_year = 1900 + (year - 1997) - (real_year - 97);
				write_byte(fin, 0x757C5, (base_year - 0x700));  // 1
				write_byte(fin, 0x918FF, (base_year - 0x700));  // 2
				write_byte(fin, 0x96AD1, (base_year - 0x700));  // 3
				write_byte(fin, 0x99BD1, (base_year - 0x700));  // 4
				write_byte(fin, 0x99C3A, (base_year - 0x700));  // 5
				write_byte(fin, 0x9A165, (base_year - 0x700));  // 5.1
				write_byte(fin, 0x9A17E, ((base_year - 0x700)+1));  // 5.2
				write_byte(fin, 0x9A2B6, (base_year - 0x700) + 1); // 6
				write_byte(fin, 0xA4213, (base_year - 0x700) + 1); // 7
				write_byte(fin, 0xA448B, (base_year - 0x700) + 1); // 8
				write_byte(fin, 0xC26D1, (base_year - 0x700) + 1); // 9
				write_byte(fin, 0xC9587, (base_year - 0x700) + 1); // 10

				// Make it so it's "Season 2020/21" rather than "Season 2020/1"
				write_byte(fin, 0x9A1CB, 0x90);
				write_byte(fin, 0x9A1CC, 0x90);
				write_byte(fin, 0x9A1CF, 0x02);
				write_byte(fin, 0x9A1D0, 0x7c);

				// No idea what this code does anymore :)
				write_byte(fin, 0x9A236, 0x83);
				if (year >= 1997)
				{
					write_byte(fin, 0x9A237, 0xc2);
					write_byte(fin, 0x9A238, (year - 1997) - (real_year - 97));
				}
				else
				{
					write_byte(fin, 0x9A237, 0xea);
					write_byte(fin, 0x9A238, (1997 - year) - (real_year - 97));
				}
				write_byte(fin, 0x9A239, 0x83);
				write_byte(fin, 0x9A23A, 0xfa);
				write_byte(fin, 0x9A23B, 0x64);
				write_byte(fin, 0x9A23C, 0x7c);
				write_byte(fin, 0x9A23D, 0x03);
				write_byte(fin, 0x9A23E, 0x83);
				write_byte(fin, 0x9A23F, 0xea);
				write_byte(fin, 0x9A240, 0x64);
				write_byte(fin, 0x9A241, 0x66);

				// Stop game from exiting after 30 seasons
				write_byte(fin, 0x75625, 0xEB);

				// Wage Fix
				write_byte(fin, 0x14C0C8, 0xF8);
				write_byte(fin, 0x14D79C, 0xF8);
				write_byte(fin, 0x14D7EC, 0xF8);
				write_byte(fin, 0x152CA2, 0xF8);
				write_byte(fin, 0x152F12, 0xF8);

				// Change name to right year (maybe decide against this in the end)
				fseek(fin, 0x13FD95, SEEK_SET);
				fprintf(fin, "%02d-%02d", (year%100), (year%100)+1);

				// Expand the Data Segment
				write_byte(fin, 0x290C8, 0);
				write_byte(fin, 0x290C9, 0);
				write_byte(fin, 0x290CA, 0xFF);
				write_byte(fin, 0x290CB, 0x01);

				// Allocate more memory for players
				write_byte(fin, 0x9EBE9, 0x06);

				// Allocate more memory for players
				write_byte(fin, 0xA014C, 0x06E);

				// Set number of leagues allowed
				write_byte(fin, 0xAA86C, 0x05);

				// Set Charity Shield + FA Cup to have no restrictions
				write_byte(fin, 0x106EE6, 0x10);
				write_byte(fin, 0x104228, 0x10);

				// Set Prem Subs to 5/3 (and no restrictions)
				write_byte(fin, 0x107BF5, 0x5);
				write_byte(fin, 0x107C03, 0x3);
				write_byte(fin, 0x107C11, 0x10);

				// Set Division 1 to have 5/3 Subs (and no restrictions) + Corresponding FixUp Table
				write_bytes(fin, 0x10875A, 14, 0x66, 0xC7, 0x80, 0x48, 0x2D, 0x17, 0x00, 0x05, 0x03, 0xB6, 0x10, 0x90, 0x90, 0x90); 
				write_byte(fin, 0x5C02E, 0x09);
				write_bytes(fin, 0x5C025, 4, 0x09, 0x07, 0x02, 0x48);

				// Set Division 2 to have 5/3 Subs (and no restrictions) + Corresponding FixUp Table
				write_bytes(fin, 0x1093C6, 20, 0x66, 0xC7, 0x80, 0x48, 0x2D, 0x17, 0x00, 0x05, 0x03, 0x8A, 0x1D, 0x6A, 0x49, 0xA4, 0x00, 0x90, 0x90, 0x90, 0xB6, 0x10); 
				write_byte(fin, 0x5CF67, 0x75);
				write_byte(fin, 0x5CF6A, 0x48);
				write_byte(fin, 0x5CF70, 0x7D);
				write_byte(fin, 0x5CF79, 0x75);

				// Set Division 3 to have 5/3 Subs (and no restrictions) + Corresponding FixUp Table
				write_bytes(fin, 0x10A035, 20, 0x66, 0xC7, 0x80, 0x48, 0x2D, 0x17, 0x00, 0x05, 0x03, 0x8A, 0x1D, 0x6A, 0x49, 0xA4, 0x00, 0x90, 0x90, 0x90, 0xB6, 0x10); 
				write_byte(fin, 0x5C724, 0xE4);
				write_byte(fin, 0x5C727, 0x48);
				write_byte(fin, 0x5C72D, 0xEC);
				write_byte(fin, 0x5C736, 0xE4);

				// Set Serie A to 5/5 (and no restrictions) + Corresponding FixUp Table
				write_bytes(fin, 0x112849, 12, 0x66, 0xC7, 0x80, 0x49, 0x2D, 0x17, 0x00, 0x05, 0x10, 0x90, 0x90, 0x90);
				write_byte(fin, 0x621C6, 0xF8);
				write_byte(fin, 0x621C9, 0x49);
				write_byte(fin, 0x621CF, 0xF8);

				// Set Serie B to 5/5 (and no restrictions) + Corresponding FixUp Table
				write_bytes(fin, 0x113871, 12, 0x66, 0xC7, 0x80, 0x49, 0x2D, 0x17, 0x00, 0x05, 0x10, 0x90, 0x90, 0x90);
				write_byte(fin, 0x62FDF, 0x20);
				write_byte(fin, 0x62FE2, 0x49);
				write_byte(fin, 0x62FE8, 0x20);

				// Set Coppa Italia to 5/5 (and no restrictions) - no need for fix up for once! Woo!
				write_byte(fin, 0x1113D2, 0x10);
				write_byte(fin, 0x1113DA, 0x88);

				// Set SuperCoppa to 5/5 (and no restrictions). Just need to change the Used
				write_byte(fin, 0x1144AC, 0x5);

				// Money Inflation (x4) Patch
				write_bytes(fin, 0x81F17, 5, 0xE9, 0xFF, 0xBA, 0x0B, 0x00);
				write_bytes(fin, 0x13DA1B, 14, 0xD9, 0xE1, 0x83, 0xEC, 0x08, 0xD8, 0xC0, 0xD8, 0xC0, 0xE9, 0xF3, 0x44, 0xF4, 0xFF);
				write_bytes(fin, 0x822A3, 5, 0xE9, 0x81, 0xB7, 0x0B, 0x00);
				write_bytes(fin, 0x13DA29, 14, 0xD9, 0xE1, 0x83, 0xEC, 0x08, 0xD8, 0xC0, 0xD8, 0xC0, 0xE9, 0x71, 0x48, 0xF4, 0xFF);

				// Stop Work Permit Rejection
				write_byte(fin, 0xE5BB2, 0xEB);

				// Ensure Work Permits always renew
				write_bytes(fin, 0xC8EEC, 6, 0xE9, 0x9A, 0x00, 0x00, 0x00, 0x90);

				// Teams with a reputation lower 15 don't load a full 32 players ?! Just puts extras on Free Transfer. This fixes it:
				write_byte(fin, 0x9F2B1, 0x20);

				// Skip Splash Screens (+ Fix Up)
				write_bytes(fin, 0xA9D7E, 2, 0xEB, 0x6C);
				write_bytes(fin, 0x3B233, 7, 0x07, 0x00, 0x52, 0x0E, 0x02, 0x78, 0x75);

				// Change their website name
				fseek(fin, 0x14119C, SEEK_SET);
				fprintf(fin, "https://www.sigames.com%c", 0);
           }
	       else
	       {
				printf("Cannot detect CM2 exe version!");
				fclose(fin);
				return -1;
	       }
	       printf("Version %.02f detected.\n\nYear changed to %d!\n(underlying year: %d)\n", version, year, 1900+real_year);
	}
	else
	{
		printf("Unable to open %s!\n", argv[1]);
		return -1;
	}

	return 0;
}