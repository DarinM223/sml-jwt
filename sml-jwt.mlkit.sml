structure Jwt =
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
      val key =
        case key of
          SOME (Key key) => key
        | NONE => prim ("sml_null", ())
    in
      SOME (prim ("c_jwt_get_grants_json", (getCtx (), t, key, Exn)))
    end
    handle Exn => NONE
  fun addGrant t key value : unit =
    prim
      ("c_jwt_add_grant", (getCtx (), t, key, value, JwtError ("addGrant", ~1)))
  fun addGrantInt t key value : unit =
    prim
      ( "c_jwt_add_grant_int"
      , (getCtx (), t, key, value, JwtError ("addGrantInt", ~1))
      )
  fun addGrantBool t key value : unit =
    prim
      ( "c_jwt_add_grant_bool"
      , (getCtx (), t, key, value, JwtError ("addGrantBool", ~1))
      )
  fun addGrantsJson t json =
    prim
      ( "c_jwt_add_grants_json"
      , (getCtx (), t, json, JwtError ("addGrantsJson", ~1))
      )
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
val () = Jwt.free jwt
