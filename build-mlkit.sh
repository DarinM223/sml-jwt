gcc -o libstubs.a -c mlkit-stubs.c
mlkit -o sml-jwt -libdirs "." -libs "m,c,dl,stubs,jwt" sml-jwt.mlkit.mlb