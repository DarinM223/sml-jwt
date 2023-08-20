structure Jwt =
struct
  structure P = MLton.Pointer
  structure F = MLton.Finalizable
  exception JwtError of string * int
  type t = P.t F.t

  val c_jwt_new = _import "jwt_new" public : P.t -> int;
  val c_jwt_free = _import "jwt_free" public : P.t -> unit;
  val c_jwt_dump = _import "jwt_dump_str" public : P.t * bool -> string;

  fun create () =
    let
      val p = P.null
      val ret = c_jwt_new p
      val () = if ret <> 0 then raise JwtError ("jwt_create", ret) else ()
      val jwt_ptr = F.new (P.getPointer (p, 0))
    in
      F.addFinalizer (jwt_ptr, c_jwt_free);
      jwt_ptr
    end
  fun show t =
    F.withValue (t, fn t => c_jwt_dump (t, false))
end

val jwt = Jwt.create ()
val () = print (Jwt.show jwt ^ "\n")
