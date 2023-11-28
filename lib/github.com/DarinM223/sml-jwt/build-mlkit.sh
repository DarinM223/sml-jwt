gcc -DTAG_VALUES -DENABLE_GC -o libstubs.a -c mlkit-stubs.c
mlkit -gc -o sml-jwt -libdirs "." -libs "m,c,dl,stubs,jwt" sml-jwt.mlkit.mlb