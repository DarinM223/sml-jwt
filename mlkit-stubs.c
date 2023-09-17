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

uintptr_t c_jwt_get_grants_json(Region strRho, Context ctx, uintptr_t jwt, String key, long key_len, uintptr_t exn)
{
  char *result = NULL;
  if (key == NULL)
  {
    result = jwt_get_grants_json((jwt_t *)jwt, NULL);
  }
  else
  {
    key_len = convertIntToC(key_len);
    char cKey[key_len + 1];
    convertStringToC(ctx, key, cKey, key_len + 1, exn);
    result = jwt_get_grants_json((jwt_t *)jwt, cKey);
  }
  if (result == NULL)
  {
    raise_exn(ctx, exn);
    return 0;
  }
  String mlResult = convertStringToML(strRho, result);
  free((void *)result);
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

void c_jwt_add_grant_int(Context ctx, uintptr_t jwt, String key, long value, uintptr_t exn)
{
  char cKey[1000];
  convertStringToC(ctx, key, cKey, 1000, exn);
  value = convertIntToC(value);
  int result = jwt_add_grant_int((jwt_t *)jwt, cKey, value);
  if (result != 0)
  {
    raise_exn(ctx, exn);
  }
}

void c_jwt_add_grant_bool(Context ctx, uintptr_t jwt, String key, int value, uintptr_t exn)
{
  char cKey[1000];
  convertStringToC(ctx, key, cKey, 1000, exn);
  value = convertBoolToC(value);
  int result = jwt_add_grant_bool((jwt_t *)jwt, cKey, value);
  if (result != 0)
  {
    raise_exn(ctx, exn);
  }
}

void c_jwt_add_grants_json(Context ctx, uintptr_t jwt, String json, long json_size, uintptr_t exn)
{
  json_size = convertIntToC(json_size);
  char cJson[json_size + 1];
  convertStringToC(ctx, json, cJson, json_size + 1, exn);
  int result = jwt_add_grants_json((jwt_t *)jwt, cJson);
  if (result != 0)
  {
    raise_exn(ctx, exn);
  }
}

void c_jwt_del_grants(Context ctx, uintptr_t jwt, String key, uintptr_t exn)
{
  int result;
  if (key == NULL)
  {
    result = jwt_del_grants((jwt_t *)jwt, NULL);
  }
  else
  {
    char cKey[1000];
    convertStringToC(ctx, key, cKey, 1000, exn);
    result = jwt_del_grants((jwt_t *)jwt, cKey);
  }
  if (result != 0)
  {
    raise_exn(ctx, exn);
  }
}

uintptr_t c_jwt_encode(Region strRho, Context ctx, uintptr_t jwt, uintptr_t exn)
{
  char *result = jwt_encode_str((jwt_t *)jwt);
  if (result == NULL)
  {
    raise_exn(ctx, exn);
    return 0;
  }
  String mlResult = convertStringToML(strRho, result);
  free((void *)result);
  return (uintptr_t)mlResult;
}

uintptr_t c_jwt_decode(Context ctx, String token, long token_len, String key, long key_len, uintptr_t exn)
{
  token_len = convertIntToC(token_len);
  char cToken[token_len + 1];
  convertStringToC(ctx, token, cToken, token_len + 1, exn);
  int result;
  jwt_t *jwt = NULL;
  if (key == NULL)
  {
    result = jwt_decode(&jwt, cToken, NULL, 0);
  }
  else
  {
    key_len = convertIntToC(key_len);
    char cKey[key_len + 1];
    convertStringToC(ctx, key, cKey, key_len + 1, exn);
    result = jwt_decode(&jwt, cToken, cKey, key_len);
  }
  if (result != 0)
  {
    raise_exn(ctx, exn);
    return 0;
  }
  return (uintptr_t)jwt;
}

void c_jwt_set_alg(Context ctx, uintptr_t jwt, long alg, String key, long key_len, uintptr_t exn)
{
  alg = convertIntToC(alg);
  int result;
  if (key == NULL)
  {
    result = jwt_set_alg((jwt_t *)jwt, (jwt_alg_t)alg, NULL, 0);
  }
  else
  {
    key_len = convertIntToC(key_len);
    char cKey[key_len + 1];
    convertStringToC(ctx, key, cKey, key_len + 1, exn);
    result = jwt_set_alg((jwt_t *)jwt, (jwt_alg_t)alg, cKey, key_len);
  }
  if (result != 0)
  {
    raise_exn(ctx, exn);
  }
}

long c_jwt_get_alg(uintptr_t jwt)
{
  long result = jwt_get_alg((jwt_t *)jwt);
  return convertIntToML(result);
}