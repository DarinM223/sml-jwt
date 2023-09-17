structure Jwt =
struct
  open Jwt
  type t = foreignptr

  exception Exn
  fun getCtx () : foreignptr = prim ("__get_ctx", ())

  fun create () : t =
    prim ("c_jwt_new", (getCtx (), Exn))
    handle Exn => raise JwtError ("create", ~1)
  fun free t = prim ("jwt_free", t)
  fun show t : string =
    prim ("c_jwt_show", (getCtx (), t, Exn))
    handle Exn => raise (JwtError ("show", ~1))
end

val jwt: Jwt.t = Jwt.create ()
val () = print (Jwt.show jwt ^ "\n")
val () = Jwt.free jwt
