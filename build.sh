mlton -default-ann 'allowFFI true' -target-link-opt linux '-ljwt' sml-jwt.mlb
# mlton -default-ann 'allowFFI true' -export-header export.h -target-link-opt linux '-ljwt' jwt.mlb stubs.c