gcc -o ../libstubs.a -c ../mlkit-stubs.c
mlkit -no_gc -o example -libdirs ".." -libs "m,c,dl,stubs,jwt" example.mlkit.mlb