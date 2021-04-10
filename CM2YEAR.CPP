#include <stdio.h>
#include <stdarg.h>
#include <string.h>

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

unsigned char HexCharToVal(char c)
{
	 if (c >= '0' && c <= '9') 
		 c -= '0';
     else if (c >= 'a' && c <='f') 
		 c -= ('a' - 10);
     else if (c >= 'A' && c <='F') 
		 c -= ('A' - 10);    
	 return (unsigned)c;
}


void write_bytes(FILE* fin, long pos, const char *patch)
{
	fseek(fin, pos, SEEK_SET);
	int len = strlen(patch);
	for (int i = 0; i < len; i+=2)
	{
		unsigned char byte = (HexCharToVal(patch[i]) << 4) | HexCharToVal(patch[i+1]);
		putc(byte, fin);
	}
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

				// Change the World Cup hosts to Qatar for 2021 and Germany for Euro 2024
				if (year == 2021)
				{
					fseek(fin, 0x145BD4, SEEK_SET);
					fprintf(fin, "Qatar%c", 0);

					fseek(fin, 0x145BDC, SEEK_SET);
					fprintf(fin, "Germany");
				

					// Update World Cup History
					write_bytes(fin, 0x52C38, "F81000");	// Point 2018 (last) Host to Russia (FixUp)
					write_bytes(fin, 0xF8C79, "F8100E");	// Point 2018 (last) Host to Russia
					write_bytes(fin, 0x52C1D, "6405");		// Point 2018 (last) Winner to France (FixUp)
					write_bytes(fin, 0xF8C9E, "6405");		// Point 2018 (last) Winner to France
					write_bytes(fin, 0x52C02, "84");		// Point 2018 (last) Runner-Up to Croatia (FixUp)
					write_bytes(fin, 0xF8CC3, "84");		// Point 2018 (last) Runner-Up to Croatia 
					write_bytes(fin, 0xF8CEE, "E9E5050000");  // Skip the next years

					// Update Euros History
					write_bytes(fin, 0xFBF07, "5C");		// Set the first one to 1996 (so it will be 2016)
					write_bytes(fin, 0x547F5, "6405");		// Set host to France (FixUp)
					write_bytes(fin, 0xFBF1B, "6405");		// Set host to France
					write_bytes(fin, 0x547DA, "D45100");	// Set Winner to Portugal (FixUp)
					write_bytes(fin, 0xFBF3F, "D45100");	// Set Winner to Portugal
					write_bytes(fin, 0x547BF, "6405");		// Set Runners-Up to France (FixUp)
					write_bytes(fin, 0xFBF64, "6405");		// Set Runners-Up to France 
					write_bytes(fin, 0xFBF89, "E99904");    // Skip the next years

					// Change Header Colour (I always really hated the Green and Yellow)
					write_byte(fin, 0xA9CFC, 0x81);	// White writing
					write_byte(fin, 0xA9D03, 0x87);	// Darkish Red banner
					write_byte(fin, 0x7A0A0, 0x81);	// White writing
					write_byte(fin, 0x7A0A5, 0x87);	// Darkish Red banner
				}

				// Coloured Attributes Patch
				write_bytes(fin, 0xC4EDB, "E9DF890700");		// Jump
				//write_bytes(fin, 0x13D8BF, "89C3E89244F4FFBA060000008A4D760FB69B8AB82700909093E91976F8FF9080A3A3A3A4A591919190908F8F8F8A8B8C8D878685858585858585858585858585858585858585");  // 1st Colors Attempt
				//write_bytes(fin, 0x13D8BF, "89C3E89244F4FFBA060000008A4D760FB69B8AB82700909093E91976F8FF9080A6A6A6A5A5A5A5A4A4A4A4A3A3A3828282828281858585858585858585858585858585858585");  // Greyscale Colors
				//write_bytes(fin, 0x13D8BF, "89C3E89244F4FFBA060000008A4D760FB69B8AB82700909093E91976F8FF9080A6A6A6A6A5A5A4A4A392929292928C8C8B8B8A85858585858585858585858585858585858585");  // 2nd Colors Attempt
				write_bytes(fin, 0x13D8BF, "89C3E89244F4FF8A4D76E8000000005A2E0FB65C1A12BA0600000093E91676F8FF80A6A6A6A6A5A5A4A4A392929292928C8C8B8B8A858590909090");						   // Using 2nd Colors Attempt but with Position Independent Code

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