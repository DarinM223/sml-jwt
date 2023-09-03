structure Jwt: JWT =
struct
  open Jwt
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

local
  fun showOption f (SOME s) = "SOME " ^ f s
    | showOption _ NONE = "NONE"
in
  val showStr_option = showOption (fn t0 => "\"" ^ t0 ^ "\"")
  val showInt_option = showOption Int.toString
  val showBool_option = showOption Bool.toString
  val showAlgorithm_option = showOption AlgUtils.showAlgorithm
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
val () = print
  (showStr_option (Jwt.getGrantsJson jwt (SOME (Jwt.Key "life"))) ^ "\n")
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
val () = print (showAlgorithm_option (Jwt.getAlg jwt) ^ "\n")
val privateKey =
  "-----BEGIN RSA PRIVATE KEY-----\n\
  \MIIEpQIBAAKCAQEA2EobPLULbXZNI9GBoXvX2X4Yplh4KIhDBWd33ll4id+Wsw6/\n\
  \vIvOKy2rB74zcTgmRi6ZVNArgX5jdC6+nJHer33DQl/CNls24n7H5b/gC9O253ro\n\
  \JjYQU9FiwMH4nsneAJimXizNc00E5pqhvMbCu1/ZoKb6hLBrcLF1KA3n38GTcmaq\n\
  \r9yI5TM65B2pKelNAbBaIB2oBWAKjPfvDLkOhyNrgAKV677LD3fsU+lC+ea9ylt/\n\
  \KPoicOAQFZer1kqYcI+IeouG2ePJcPEH3xpH0mFtaTzmJd5Hzr84kmM2NZRN+oOl\n\
  \OYOKFluSTWQ1aojPQBmhceQFnfLAKoOW4qS6VQIDAQABAoIBAQCh8NJ14KP+wD2/\n\
  \nMSvUNdrS6NPIRxOVL/BkxfHzjuXF2ZxCJD8rbyezaGpuXowwja+A3PgccCxQx1Z\n\
  \xwoGlp0hzkrdLm9uXVs5uG0ZE1G/6TOgG4En4wDUkQichF8PHNvwnFqsVmU5eCg8\n\
  \NPj2K+dvfbOnOn6FzMWU6flrFQZQm/HCB0igqyd85kfb9/Cj9iT2Jf9hRA1fhhBE\n\
  \q+VyHISSD9QOO3E3S8mrHMc6otZdIwT8MWMh0YaJsYSV4/cPe9nVODV9PLPkVgz4\n\
  \COZcGYfBDElvWo5IPZRcD47rdJx9j2eqnE4dhAOsFSH2qgsQKU566ZAX14DUUCZ6\n\
  \Pk+6uhRdAoGBAPCyoK94iZ5A9+wc9MdpgyRKlq7RA2zt0GR+47+Liv614+zJAnc1\n\
  \qIdEqIcDPdMILQbWBIMwtwxYiSQ1ILuL6IfMIsXz3Jpd+BGnV3EtJFg0/TshPu/U\n\
  \hQsgOjShajemzP8oT3AGcqWmCa6xH27wbPgT9gIa7XkS64kRqBOLZCATAoGBAOYK\n\
  \O3J0RDgUTWWWBT2INNIn9S1/B7TmHbER3ESCP+f0k5GRvK5LLAqWNrrdGWN5s/xQ\n\
  \tRWMYOfYDbkyAsolS3vKpo/m3upkTD/G8J0faA/P30wvq3XOEKstbqeiYlAofeVz\n\
  \TI1sHAutJx0OtOdQB9L/YDbb7JCqY3dBZqeG2Bj3AoGAWyF2fxknGZjFhUrtTnbf\n\
  \ZSUsaeHO5zYfGX2FYydFJ+zb7/GnElVpilVvbTbH+Jd23Mi5CqauF2mJ+wB2dSui\n\
  \jY+3drU+x99eJejyzXHm+dKOMg4DUzBmcvDvuK+IlKt9n/m2Idb/H0J/FfoPyaQT\n\
  \zdVY5jElyhpkvQ/HUCcNcKsCgYEAqUfQVTpP1UDDb8UFGDG6RQhYeOFo52sLYHk3\n\
  \MUb0BhpJ2a54PX5d63B81+fKPhSaKUuu5iuGSDYKa0TtHppxQKhxB6YqViv2nFwm\n\
  \RkmNR01+Ec9mimtYgs8NBdkOJdSWSJofNFbhEIqcJNrkru+Kwm9g+x29qPtp9KEx\n\
  \DIjDTyMCgYEAkdv4S187YxFAXGgcHAKVBP1awardfyspc1sUBa/ABGQl6JRLlI/W\n\
  \xNCvRhfRxa5mCCLYhCRXIm74JEQC7craX+K0ln83YZ7870HuwNEanuqkIRQhMP1g\n\
  \qA2xRVxCNmkZ/Ju6i1dXwmVomoECSAYRLqHbRHScSfqqFr2rAec9BQg=\n\
  \-----END RSA PRIVATE KEY-----"
val () = Jwt.setAlg jwt (SOME (Jwt.Key privateKey)) (SOME Jwt.RS256)
val () = print (showAlgorithm_option (Jwt.getAlg jwt) ^ "\n")
