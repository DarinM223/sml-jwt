sml-jwt
=======

Standard ML bindings for [libjwt](https://github.com/benmcollins/libjwt). Supports MLton, Poly/ML, and MLKit.

Installation:
-------------

To install libjwt, clone the repository and build it from source. The Poly/ML bindings expects that the libjwt dynamic library location is in `/usr/local/lib/libjwt.so` by default, but that can be modified in the `sml-jwt.polyml.sml` file.

Then to build the library, run the `./build-mlkit.sh` or `./build-mlton.sh` scripts in the root project directory. To build the example, run the `./build_mlkit.sh`, `./build_mlton.sh`, or `./build_polyml.sh` scripts in the example directory. The `./build_polyml.sh` script also requires `mlton` to be installed, since it uses it to convert the MLB file into `use` statements.

Issues:
-------

The MLKit bindings may segfault if the garbage collector runs in the middle of FFI calls. To prevent
this from happening, run the executable with the `-disable_gc` flag. For example: `./example -disable_gc`