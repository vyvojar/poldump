#include <stdio.h>
#include <windows.h>
#include <ntstatus.h>
#include <winternl.h>
#include "wind.h"

#define QUERY_KERNEL 1

NTSTATUS NTAPI NtQueryLicenseValue(PUNICODE_STRING,DWORD*,PVOID,DWORD,DWORD*);
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
		DWORD t = e->type;
		DWORD l = e->data_sz;
#if QUERY_KERNEL
		WCHAR buf[512];
		UNICODE_STRING us;
		memcpy(buf, e->name, e->name_sz);
		buf[e->name_sz/2] = 0;
		RtlInitUnicodeString(&us, buf);
		l = sizeof(buf);
		if (!NT_SUCCESS(NtQueryLicenseValue(&us, &t, buf, l, &l)))
			continue;
		d = (void*)buf;
#endif
		printf("\"%.*S\"=", e->name_sz/2, (WCHAR*)e->name);
		switch (t) {
			case REG_DWORD:
				printf("dword:%08x\n", *(DWORD*)d);
				break;
			case REG_SZ:
				printf("\"%.*S\"\n", l/2, (WCHAR*)d);
				break;
			case REG_BINARY:
				printf("hex:");
				for (int j = 0; j < l; j++)
					printf("%02hhx%c",d[j],j!=l-1?',':'\n');
				break;
			default:
				printf(";Unknown policy type %d\n",e->type);
		}
	}
}
