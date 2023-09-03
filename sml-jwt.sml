structure Jwt =
struct
  structure P = MLton.Pointer
  structure F = MLton.Finalizable
  exception JwtError of string * int
  type t = P.t F.t
  datatype key = Key of string
  datatype algorithm =
    HS256
  | HS384
  | HS512
  | RS256
  | RS384
  | RS512
  | ES256
  | ES384
  | ES512
  | TERM

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
  val c_errno = _import "custom_errno" public : unit -> int;
  val ENOENT = 2

  fun check s ret =
    if ret <> 0 then raise JwtError (s, ret) else ()
  fun fetchCString ptr =
    let
      fun loop (i, accum) =
        let
          val w = P.getWord8 (ptr, i)
        in
          (* Search for explicit null termination. *)
          if w = 0wx0 then String.implode (List.rev accum)
          else loop (i + 1, Byte.byteToChar w :: accum)
        end
    in
      loop (0, [])
    end

  fun create () =
    let
      val p = ref P.null
      val () = check "create" (c_jwt_new p)
      val jwt_ptr = F.new (!p)
    in
      F.addFinalizer (jwt_ptr, c_jwt_free);
      jwt_ptr
    end
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
  fun getGrantsJson t (SOME key) =
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
          SOME key => (key, String.size key)
        | NONE => ("", 0)
      val () = check "decode" (c_jwt_decode (p, s, key, key_len))
      val jwt_ptr = F.new (!p)
    in
      F.addFinalizer (jwt_ptr, c_jwt_free);
      jwt_ptr
    end
end

local
  fun showOption f (SOME s) = "SOME " ^ f s
    | showOption _ NONE = "NONE"
in
  val showStr_option = showOption (fn t0 => "\"" ^ t0 ^ "\"")
  val showInt_option = showOption Int.toString
  val showBool_option = showOption Bool.toString
end

val jwt = Jwt.create ()
val () = print (Jwt.show jwt ^ "\n")
val () = Jwt.addGrant jwt "hello" "world"
val () = print (showStr_option (Jwt.getGrant jwt "hello") ^ "\n")
val () = print (showStr_option (Jwt.getGrant jwt "world") ^ "\n")
val () = Jwt.addGrantInt jwt "life" 42
val () = print (showInt_option (Jwt.getGrantInt jwt "life") ^ "\n")
val () = Jwt.addGrantBool jwt "foo" true
val () = print (showBool_option (Jwt.getGrantBool jwt "foo") ^ "\n")
val () = print (showStr_option (Jwt.getGrantsJson jwt NONE) ^ "\n")
val () = print (showStr_option (Jwt.getGrantsJson jwt (SOME "life")) ^ "\n")
val () = Jwt.addGrantsJson jwt "{\"a\": \"b\",\"c\": 100}"
val () = print (showStr_option (Jwt.getGrantsJson jwt NONE) ^ "\n")
val () = Jwt.delGrant jwt "c"
val () = print (showStr_option (Jwt.getGrantsJson jwt NONE) ^ "\n")
val s = Jwt.encode jwt
val () = print (s ^ "\n")
val jwt2 = Jwt.decode NONE s
val () = print (showStr_option (Jwt.getGrantsJson jwt2 NONE) ^ "\n")
val () = Jwt.delGrants jwt
val () = print (showStr_option (Jwt.getGrantsJson jwt NONE) ^ "\n")
