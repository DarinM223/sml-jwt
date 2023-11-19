structure Jwt: JWT =
struct
  open Jwt
  type t = foreignptr

  exception Exn
  fun getCtx () : foreignptr = prim ("__get_ctx", ())

  val null: string = prim ("sml_null", ())

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
        | NONE => (null, 0)
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
    prim ("c_jwt_del_grants", (getCtx (), t, null, JwtError ("delGrants", ~1)))
  fun encode t : string =
    prim ("c_jwt_encode", (getCtx (), t, JwtError ("encode", ~1)))
  fun decode key s : t =
    let
      val (key, key_len) =
        case key of
          SOME (Key key) => (key, String.size key)
        | NONE => (null, 0)
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
        | NONE => (null, 0)
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

structure JwtValid: JWT_VALID =
struct
  open JwtValid
  type t = foreignptr
  type jwt = Jwt.t
  type algorithm = Jwt.algorithm
  type error = int
  exception ValidationError of error

  exception Exn
  fun getCtx () : foreignptr = prim ("__get_ctx", ())

  val null: string = prim ("sml_null", ())

  fun create alg : t =
    prim
      ( "c_jwt_valid_new"
      , (getCtx (), AlgUtils.toInt alg, JwtError ("create", ~1))
      )
  fun free t = prim ("jwt_valid_free", t)
  fun getGrant t key : string option =
    SOME (prim ("c_jwt_valid_get_grant", (getCtx (), t, key, Exn)))
    handle Exn => NONE
  fun getGrantInt t key : int option =
    SOME (prim ("c_jwt_valid_get_grant_int", (getCtx (), t, key, Exn)))
    handle Exn => NONE
  fun getGrantBool t key : bool option =
    SOME (prim ("c_jwt_valid_get_grant_bool", (getCtx (), t, key, Exn)))
    handle Exn => NONE
  fun getGrantsJson t key : string option =
    let
      val (key, key_len) =
        case key of
          SOME (Key key) => (key, String.size key)
        | NONE => (null, 0)
    in
      SOME (prim
        ("c_jwt_valid_get_grants_json", (getCtx (), t, key, key_len, Exn)))
    end
    handle Exn => NONE
  fun addGrant t key value =
    prim
      ( "c_jwt_valid_add_grant"
      , (getCtx (), t, key, value, JwtError ("addGrant", ~1))
      )
  fun addGrantInt t key value : unit =
    prim
      ( "c_jwt_valid_add_grant_int"
      , (getCtx (), t, key, value, JwtError ("addGrantInt", ~1))
      )
  fun addGrantBool t key value =
    prim
      ( "c_jwt_valid_add_grant_bool"
      , (getCtx (), t, key, value, JwtError ("addGrantBool", ~1))
      )
  fun addGrantsJson t json =
    prim
      ( "c_jwt_valid_add_grants_json"
      , (getCtx (), t, json, String.size json, JwtError ("addGrantsJson", ~1))
      )
  fun delGrant t key =
    prim
      ("c_jwt_valid_del_grants", (getCtx (), t, key, JwtError ("delGrant", ~1)))
  fun delGrants t =
    prim
      ( "c_jwt_valid_del_grants"
      , (getCtx (), t, null, JwtError ("delGrants", ~1))
      )
  fun getExpLeeway t : Time.time =
    Time.fromSeconds (prim ("c_jwt_valid_get_exp_leeway", t))
  fun setExpLeeway t (time: Time.time) : unit =
    prim
      ( "c_jwt_valid_set_exp_leeway"
      , (getCtx (), t, Time.toSeconds time, JwtError ("setExpLeeway", ~1))
      )
  fun getNbfLeeway t : Time.time =
    Time.fromSeconds (prim ("c_jwt_valid_get_nbf_leeway", t))
  fun setNbfLeeway t (time: Time.time) : unit =
    prim
      ( "c_jwt_valid_set_nbf_leeway"
      , (getCtx (), t, Time.toSeconds time, JwtError ("setNbfLeeway", ~1))
      )
  fun setNow t (time: Time.time) : unit =
    prim
      ( "c_jwt_valid_set_now"
      , (getCtx (), t, Time.toSeconds time, JwtError ("setNow", ~1))
      )
  fun validate jwt t =
    let val result = prim ("c_jwt_validate", (jwt, t))
    in if result = 0 then () else raise ValidationError result
    end
  fun hasError error valid_error =
    if
      Word.andb
        (Word.fromInt error, Word.fromInt (ValidUtils.toInt valid_error)) = 0w0
    then false
    else true
end
