#include <jwt.h>
#include <errno.h>
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

uintptr_t c_jwt_get_grant(Region strRho, Context ctx, uintptr_t jwt, String key, uintptr_t exn)
{
  char cKey[1000];
  convertStringToC(ctx, key, cKey, 1000, exn);
  const char *result = jwt_get_grant((jwt_t *)jwt, cKey);
  if (result == NULL)
  {
    raise_exn(ctx, exn);
    return 0;
  }

  String mlResult = convertStringToML(strRho, result);
  return (uintptr_t)mlResult;
}

long c_jwt_get_grant_int(Context ctx, uintptr_t jwt, String key, uintptr_t exn)
{
  char cKey[1000];
  convertStringToC(ctx, key, cKey, 1000, exn);
  long result = jwt_get_grant_int((jwt_t *)jwt, cKey);
  if (errno == ENOENT)
  {
    raise_exn(ctx, exn);
    return 0;
  }
  return convertIntToML(result);
}

int c_jwt_get_grant_bool(Context ctx, uintptr_t jwt, String key, uintptr_t exn)
{
  char cKey[1000];
  convertStringToC(ctx, key, cKey, 1000, exn);
  int result = jwt_get_grant_bool((jwt_t *)jwt, cKey);
  if (errno == ENOENT)
  {
    raise_exn(ctx, exn);
    return 0;
  }
  return convertBoolToML(result);
}

uintptr_t c_jwt_get_grants_json(Region strRho, Context ctx, uintptr_t jwt, String key, uintptr_t exn)
{
  char *result = NULL;
  if (key == NULL)
  {
    result = jwt_get_grants_json((jwt_t *)jwt, NULL);
  }
  else
  {
    char cKey[1000];
    convertStringToC(ctx, key, cKey, 1000, exn);
    result = jwt_get_grants_json((jwt_t *)jwt, cKey);
  }
  if (result == NULL)
  {
    raise_exn(ctx, exn);
    return 0;
  }
  String mlResult = convertStringToML(strRho, result);
  return (uintptr_t)mlResult;
}

void c_jwt_add_grant(Context ctx, uintptr_t jwt, String key, String value, uintptr_t exn)
{
  char cKey[1000];
  convertStringToC(ctx, key, cKey, 1000, exn);
  char cValue[1000];
  convertStringToC(ctx, value, cValue, 1000, exn);
  int result = jwt_add_grant((jwt_t *)jwt, cKey, cValue);
  if (result != 0)
  {
    raise_exn(ctx, exn);
  }
}