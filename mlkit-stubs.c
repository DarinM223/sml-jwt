#include <jwt.h>
#include "./mlkit/Runtime/List.h"
#include "./mlkit/Runtime/String.h"
#include "./mlkit/Runtime/Exception.h"
#include "./mlkit/Runtime/Region.h"
#include "./mlkit/Runtime/Tagging.h"

uintptr_t c_jwt_new(Context ctx, uintptr_t exn)
{
  jwt_t *jwt = NULL;
  int ret = jwt_new(&jwt);
  if (ret != 0 || jwt == NULL)
  {
    raise_exn(ctx, exn);
    return 0;
  }

  return (uintptr_t)jwt;
}

uintptr_t c_jwt_show(Region strRho, Context ctx, uintptr_t jwt, uintptr_t exn)
{
  char *result = jwt_dump_str((jwt_t *)jwt, 0);
  if (result == NULL)
  {
    raise_exn(ctx, exn);
    return 0;
  }
  String mlResult = convertStringToML(strRho, result);
  free((void *)result);
  return (uintptr_t)mlResult;
}