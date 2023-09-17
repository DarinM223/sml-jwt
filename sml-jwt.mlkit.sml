structure Jwt: JWT =
struct
  open Jwt
  type t = foreignptr

  exception Exn
  fun getCtx () : foreignptr = prim ("__get_ctx", ())

  fun create () : t =
    prim ("c_jwt_new", (getCtx (), JwtError ("create", ~1)))
  fun free t = prim ("jwt_free", t)
  fun show t : string =
    prim ("c_jwt_show", (getCtx (), t, JwtError ("show", ~1)))
  fun getGrant t key : string option =
    SOME (prim ("c_jwt_get_grant", (getCtx (), t, key, Exn)))
    handle Exn => NONE
  fun getGrantInt t key : int option =
    SOME (prim ("c_jwt_get_grant_int", (getCtx (), t, key, Exn)))
    handle Exn => NONE
  fun getGrantBool t key : bool option =
    SOME (prim ("c_jwt_get_grant_bool", (getCtx (), t, key, Exn)))
    handle Exn => NONE
  fun getGrantsJson t key : string option =
    let
      val (key, key_len) =
        case key of
          SOME (Key key) => (key, String.size key)
        | NONE => (prim ("sml_null", ()), 0)
    in
      SOME (prim ("c_jwt_get_grants_json", (getCtx (), t, key, key_len, Exn)))
    end
    handle Exn => NONE
  fun addGrant t key value =
    prim
      ("c_jwt_add_grant", (getCtx (), t, key, value, JwtError ("addGrant", ~1)))
  fun addGrantInt t key value : unit =
    prim
      ( "c_jwt_add_grant_int"
      , (getCtx (), t, key, value, JwtError ("addGrantInt", ~1))
      )
  fun addGrantBool t key value =
    prim
      ( "c_jwt_add_grant_bool"
      , (getCtx (), t, key, value, JwtError ("addGrantBool", ~1))
      )
  fun addGrantsJson t json =
    prim
      ( "c_jwt_add_grants_json"
      , (getCtx (), t, json, String.size json, JwtError ("addGrantsJson", ~1))
      )
  fun delGrant t key =
    prim ("c_jwt_del_grants", (getCtx (), t, key, JwtError ("delGrant", ~1)))
  fun delGrants t =
    prim
      ( "c_jwt_del_grants"
      , (getCtx (), t, prim ("sml_null", ()), JwtError ("delGrants", ~1))
      )
  fun encode t : string =
    prim ("c_jwt_encode", (getCtx (), t, JwtError ("encode", ~1)))
  fun decode key s : t =
    let
      val (key, key_len) =
        case key of
          SOME (Key key) => (key, String.size key)
        | NONE => (prim ("sml_null", ()), 0)
    in
      prim
        ( "c_jwt_decode"
        , (getCtx (), s, String.size s, key, key_len, JwtError ("decode", ~1))
        )
    end
  fun setAlg t key alg =
    let
      val (key, key_len) =
        case key of
          SOME (Key key) => (key, String.size key)
        | NONE => (prim ("sml_null", ()), 0)
    in
      prim
        ( "c_jwt_set_alg"
        , ( getCtx ()
          , t
          , AlgUtils.toInt alg
          , key
          , key_len
          , JwtError ("setAlg", ~1)
          )
        )
    end
  fun getAlg t =
    AlgUtils.fromInt (prim ("c_jwt_get_alg", t))
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

val jwt: Jwt.t = Jwt.create ()
val () = print (Jwt.show jwt ^ "\n")
val () = Jwt.addGrant jwt "hello" "world"
val () = print (showStr_option (Jwt.getGrant jwt "hello") ^ "\n")
val () = Jwt.addGrantInt jwt "foo" 120
val () = print (showInt_option (Jwt.getGrantInt jwt "foo") ^ "\n")
val () = Jwt.addGrantBool jwt "bar" true
val () = print (showBool_option (Jwt.getGrantBool jwt "bar") ^ "\n")
val () = print
  (showStr_option (Jwt.getGrantsJson jwt (SOME (Jwt.Key "hello"))) ^ "\n")
val () = print (showStr_option (Jwt.getGrantsJson jwt NONE) ^ "\n")
val () = Jwt.addGrantsJson jwt "{\"blah\": 23, \"abc\": \"def\"}"
val () = print (showStr_option (Jwt.getGrantsJson jwt NONE) ^ "\n")

val () = print (Jwt.encode jwt ^ "\n")
val jwt' = Jwt.decode NONE (Jwt.encode jwt)
val () = print (showStr_option (Jwt.getGrantsJson jwt' NONE) ^ "\n")
val () = Jwt.free jwt'

val () = Jwt.delGrant jwt "hello"
val () = print (showStr_option (Jwt.getGrantsJson jwt NONE) ^ "\n")
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

val () = Jwt.free jwt
