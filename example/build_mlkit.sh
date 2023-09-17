gcc -DTAG_VALUES -DENABLE_GC -o ../libstubs.a -c ../mlkit-stubs.c
mlkit -gc -o example -libdirs ".." -libs "m,c,dl,stubs,jwt" example.mlkit.mlb
