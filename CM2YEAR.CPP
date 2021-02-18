#include <stdio.h>

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
               }
	       else
	       {
			printf("Cannot detect CM2.exe version!");
			fclose(fin);
			return -1;
	       }
	       printf("Version %.02f detected.\n\nYear changed to %d!\n(underlying year: %d - year shift: +%d)\n", version, year, 1900+real_year, real_year-96);
	}
	else
	{
		printf("Unable to open %s!\n", argv[1]);
		return -1;
	}

	return 0;
}