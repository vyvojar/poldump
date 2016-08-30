all: pdnt pdreg
pdnt:
	gcc -DQUERY_KERNEL=1 -O2 pd.c -s -o pdnt -lntdll
pdreg:
	gcc -DQUERY_KERNEL=0 -O2 pd.c -s -o pdreg -lntdll
clean:
	rm -f *.exe
