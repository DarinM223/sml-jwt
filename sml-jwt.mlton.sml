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
