structure FFIUtils =
struct
  fun fetchCString ptr =
    let
      fun loop (i, accum) =
        let
          val w = MLton.Pointer.getWord8 (ptr, i)
        in
          (* Search for explicit null termination. *)
          if w = 0wx0 then String.implode (List.rev accum)
          else loop (i + 1, Byte.byteToChar w :: accum)
        end
    in
      loop (0, [])
    end

  val timeToCTime: Time.time -> C_Time.t = C_Time.fromLargeInt o Time.toSeconds
  val cTimeToTime: C_Time.t -> Time.time = Time.fromSeconds o C_Time.toLargeInt
end

structure Jwt: JWT =
struct
  open Jwt FFIUtils
  structure P = MLton.Pointer
  structure F = MLton.Finalizable
  type t = P.t F.t

  val c_jwt_new = _import "jwt_new" public : P.t ref -> int;
  val c_jwt_free = _import "jwt_free" public : P.t -> unit;
  val c_jwt_dump = _import "jwt_dump_str" public : P.t * int -> P.t;
  val c_jwt_get_grant = _import "jwt_get_grant" public : P.t * string -> P.t;
  val c_jwt_get_grant_int =
    _import "jwt_get_grant_int" public : P.t * string -> C_Long.t;
  val c_jwt_get_grant_bool =
    _import "jwt_get_grant_bool" public : P.t * string -> bool;
  val c_jwt_get_grants_json =
    _import "jwt_get_grants_json" public : P.t * string -> P.t;
  val c_jwt_get_grants_json2 =
    _import "jwt_get_grants_json" public : P.t * P.t -> P.t;
  val c_jwt_add_grant =
    _import "jwt_add_grant" public : P.t * string * string -> int;
  val c_jwt_add_grant_int =
    _import "jwt_add_grant_int" public : P.t * string * C_Long.t -> int;
  val c_jwt_add_grant_bool =
    _import "jwt_add_grant_bool" public : P.t * string * bool -> int;
  val c_jwt_add_grants_json =
    _import "jwt_add_grants_json" public : P.t * string -> int;
  val c_jwt_del_grant = _import "jwt_del_grants" public : P.t * string -> int;
  val c_jwt_del_grants = _import "jwt_del_grants" public : P.t * P.t -> int;
  val c_jwt_encode = _import "jwt_encode_str" public : P.t -> P.t;
  val c_jwt_decode =
    _import "jwt_decode" public : P.t ref * string * string * int -> int;
  val c_jwt_set_alg =
    _import "jwt_set_alg" public : P.t * int * string * int -> int;
  val c_jwt_get_alg = _import "jwt_get_alg" public : P.t -> int;
  val c_errno = _import "Posix_Error_getErrno" private : unit -> int;
  val ENOENT = 2

  fun create () =
    let
      val p = ref P.null
      val () = check "create" (c_jwt_new p)
      val jwt_ptr = F.new (!p)
    in
      F.addFinalizer (jwt_ptr, c_jwt_free);
      jwt_ptr
    end
  fun free _ = ()
  fun show t =
    fetchCString (F.withValue (t, fn t => c_jwt_dump (t, 0)))
  fun getGrant t key =
    F.withValue (t, fn t =>
      let val p = c_jwt_get_grant (t, key)
      in if p = P.null then NONE else SOME (fetchCString p)
      end)
  fun getGrantInt t key =
    F.withValue (t, fn t =>
      let val r = c_jwt_get_grant_int (t, key)
      in if c_errno () = ENOENT then NONE else SOME (C_Long.toInt r)
      end)
  fun getGrantBool t key =
    F.withValue (t, fn t =>
      let val r = c_jwt_get_grant_bool (t, key)
      in if c_errno () = ENOENT then NONE else SOME r
      end)
  fun getGrantsJson t (SOME (Key key)) =
        F.withValue (t, fn t =>
          let val p = c_jwt_get_grants_json (t, key)
          in if p = P.null then NONE else SOME (fetchCString p)
          end)
    | getGrantsJson t NONE =
        F.withValue (t, fn t =>
          let val p = c_jwt_get_grants_json2 (t, P.null)
          in if p = P.null then NONE else SOME (fetchCString p)
          end)
  fun addGrant t key value =
    F.withValue (t, fn t => check "addGrant" (c_jwt_add_grant (t, key, value)))
  fun addGrantInt t key value =
    F.withValue (t, fn t =>
      check "addGrantInt" (c_jwt_add_grant_int (t, key, C_Long.fromInt value)))
  fun addGrantBool t key value =
    F.withValue (t, fn t =>
      check "addGrantBool" (c_jwt_add_grant_bool (t, key, value)))
  fun addGrantsJson t json =
    F.withValue (t, fn t =>
      check "addGrantsJson" (c_jwt_add_grants_json (t, json)))
  fun delGrant t key =
    F.withValue (t, fn t => check "delGrant" (c_jwt_del_grant (t, key)))
  fun delGrants t =
    F.withValue (t, fn t => check "delGrants" (c_jwt_del_grants (t, P.null)))
  fun encode t =
    F.withValue (t, fn t =>
      let val p = c_jwt_encode t
      in if p = P.null then raise JwtError ("encode", ~1) else fetchCString p
      end)
  fun decode key s =
    let
      val p = ref P.null
      val (key, key_len) =
        case key of
          SOME (Key key) => (key, String.size key)
        | NONE => ("", 0)
      val () = check "decode" (c_jwt_decode (p, s, key, key_len))
      val jwt_ptr = F.new (!p)
    in
      F.addFinalizer (jwt_ptr, c_jwt_free);
      jwt_ptr
    end
  fun setAlg t key alg =
    F.withValue (t, fn t =>
      let
        val (key, key_len) =
          case key of
            SOME (Key key) => (key, String.size key)
          | NONE => ("", 0)
      in
        check "setAlg" (c_jwt_set_alg (t, AlgUtils.toInt alg, key, key_len))
      end)
  fun getAlg t =
    F.withValue (t, fn t => AlgUtils.fromInt (c_jwt_get_alg t))
end

structure JwtValid: JWT_VALID =
struct
  open JwtValid FFIUtils
  structure P = MLton.Pointer
  structure F = MLton.Finalizable
  type t = P.t F.t
  type jwt = Jwt.t
  type algorithm = Jwt.algorithm
  type error = C_UInt.t
  exception ValidationError of error

  val c_jwt_valid_new = _import "jwt_valid_new" public : P.t ref * int -> int;
  val c_jwt_valid_free = _import "jwt_valid_free" public : P.t -> unit;
  val c_jwt_valid_get_grant =
    _import "jwt_valid_get_grant" public : P.t * string -> P.t;
  val c_jwt_valid_get_grant_int =
    _import "jwt_valid_get_grant_int" public : P.t * string -> C_Long.t;
  val c_jwt_valid_get_grant_bool =
    _import "jwt_valid_get_grant_bool" public : P.t * string -> bool;
  val c_jwt_valid_get_grants_json =
    _import "jwt_valid_get_grants_json" public : P.t * string -> P.t;
  val c_jwt_valid_get_grants_json2 =
    _import "jwt_get_grants_json" public : P.t * P.t -> P.t;
  val c_jwt_valid_add_grant =
    _import "jwt_valid_add_grant" public : P.t * string * string -> int;
  val c_jwt_valid_add_grant_int =
    _import "jwt_valid_add_grant_int" public : P.t * string * C_Long.t -> int;
  val c_jwt_valid_add_grant_bool =
    _import "jwt_valid_add_grant_bool" public : P.t * string * bool -> int;
  val c_jwt_valid_add_grants_json =
    _import "jwt_valid_add_grants_json" public : P.t * string -> int;
  val c_jwt_valid_del_grant =
    _import "jwt_valid_del_grants" public : P.t * string -> int;
  val c_jwt_valid_del_grants =
    _import "jwt_valid_del_grants" public : P.t * P.t -> int;
  val c_jwt_valid_get_exp_leeway =
    _import "jwt_valid_get_exp_leeway" public : P.t -> C_Time.t;
  val c_jwt_valid_set_exp_leeway =
    _import "jwt_valid_set_exp_leeway" public : P.t * C_Time.t -> int;
  val c_jwt_valid_get_nbf_leeway =
    _import "jwt_valid_get_nbf_leeway" public : P.t -> C_Time.t;
  val c_jwt_valid_set_nbf_leeway =
    _import "jwt_valid_set_nbf_leeway" public : P.t * C_Time.t -> int;
  val c_jwt_valid_set_now =
    _import "jwt_valid_set_now" public : P.t * C_Time.t -> int;
  val c_jwt_validate = _import "jwt_validate" : P.t * P.t -> C_UInt.t;
  val c_errno = _import "Posix_Error_getErrno" private : unit -> int;
  val ENOENT = 2

  fun create alg =
    let
      val p = ref P.null
      val () = check "create" (c_jwt_valid_new (p, AlgUtils.toInt alg))
      val jwt_ptr = F.new (!p)
    in
      F.addFinalizer (jwt_ptr, c_jwt_valid_free);
      jwt_ptr
    end
  fun free _ = ()
  fun getGrant t key =
    F.withValue (t, fn t =>
      let val p = c_jwt_valid_get_grant (t, key)
      in if p = P.null then NONE else SOME (fetchCString p)
      end)
  fun getGrantInt t key =
    F.withValue (t, fn t =>
      let val r = c_jwt_valid_get_grant_int (t, key)
      in if c_errno () = ENOENT then NONE else SOME (C_Long.toInt r)
      end)
  fun getGrantBool t key =
    F.withValue (t, fn t =>
      let val r = c_jwt_valid_get_grant_bool (t, key)
      in if c_errno () = ENOENT then NONE else SOME r
      end)
  fun getGrantsJson t (SOME (Key key)) =
        F.withValue (t, fn t =>
          let val p = c_jwt_valid_get_grants_json (t, key)
          in if p = P.null then NONE else SOME (fetchCString p)
          end)
    | getGrantsJson t NONE =
        F.withValue (t, fn t =>
          let val p = c_jwt_valid_get_grants_json2 (t, P.null)
          in if p = P.null then NONE else SOME (fetchCString p)
          end)
  fun addGrant t key value =
    F.withValue (t, fn t =>
      check "addGrant" (c_jwt_valid_add_grant (t, key, value)))
  fun addGrantInt t key value =
    F.withValue (t, fn t =>
      check "addGrantInt"
        (c_jwt_valid_add_grant_int (t, key, C_Long.fromInt value)))
  fun addGrantBool t key value =
    F.withValue (t, fn t =>
      check "addGrantBool" (c_jwt_valid_add_grant_bool (t, key, value)))
  fun addGrantsJson t json =
    F.withValue (t, fn t =>
      check "addGrantsJson" (c_jwt_valid_add_grants_json (t, json)))
  fun delGrant t key =
    F.withValue (t, fn t => check "delGrant" (c_jwt_valid_del_grant (t, key)))
  fun delGrants t =
    F.withValue (t, fn t =>
      check "delGrants" (c_jwt_valid_del_grants (t, P.null)))
  fun getExpLeeway t =
    F.withValue (t, fn t => cTimeToTime (c_jwt_valid_get_exp_leeway t))
  fun setExpLeeway t time =
    F.withValue (t, fn t =>
      check "setExpLeeway" (c_jwt_valid_set_exp_leeway (t, timeToCTime time)))
  fun getNbfLeeway t =
    F.withValue (t, fn t => cTimeToTime (c_jwt_valid_get_nbf_leeway t))
  fun setNbfLeeway t time =
    F.withValue (t, fn t =>
      check "setNbfLeeway" (c_jwt_valid_set_nbf_leeway (t, timeToCTime time)))
  fun setNow t time =
    F.withValue (t, fn t =>
      check "setNow" (c_jwt_valid_set_now (t, timeToCTime time)))
  fun validate jwt t =
    F.withValue (jwt, fn jwt =>
      F.withValue (t, fn t =>
        let
          val result = c_jwt_validate (jwt, t)
        in
          if result = C_UInt.fromInt 0 then () else raise ValidationError result
        end))
  fun hasError error valid_error =
    if
      C_UInt.andb (error, C_UInt.fromInt (ValidUtils.toInt valid_error))
      = C_UInt.fromInt 0
    then false
    else true
end
