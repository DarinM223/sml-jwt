#include "export.h"
#include <errno.h>
#include <jwt.h>

int custom_errno () {
  return errno;
}