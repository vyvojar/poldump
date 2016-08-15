#include <stdio.h>
#include <windows.h>
#include <ntstatus.h>
#include <winternl.h>
#include "wind.h"

int main()
{
	HKEY hk;
	UCHAR b[65536];
	DWORD t = REG_BINARY, n = sizeof(b);
	wind_pol_ent *ar[WIND_POL_MAX];
	RegOpenKeyExA(HKEY_LOCAL_MACHINE,
			"SYSTEM\\CurrentControlSet\\Control\\ProductOptions",
			0, KEY_READ, &hk);
	if (RegQueryValueEx(hk, "ProductPolicy", NULL, &t, b, &n))
		return 1;
	n = wind_pol_unpack(b, ar);
	printf("REGEDIT4\n\n"
	"[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\ProductOptions\\CustomPolicy]\n");
	for (int i = 0; i < n; i++) {
		wind_pol_ent *e = ar[i];
		BYTE *d = e->name + e->name_sz;
		printf("\"%.*S\"=", e->name_sz/2, (WCHAR*)e->name);
		switch (e->type) {
			case REG_DWORD:
				printf("dword:%08x\n", *(DWORD*)d);
				break;
			case REG_SZ:
				printf("\"%.*S\"\n", e->data_sz/2, (WCHAR*)d);
				break;
			case REG_BINARY:
				printf("hex:");
				for (int j = 0; j < e->data_sz; j++)
					printf("%02hhx%c",d[j],j!=e->data_sz-1?',':'\n');
				break;
			default:
				printf(";Unknown policy type %d\n",e->type);
		}
	}
}
