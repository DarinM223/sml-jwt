structure Jwt =
struct
  structure P = MLton.Pointer
  structure F = MLton.Finalizable
  exception JwtError of string * int
  type t = P.t F.t

  val c_jwt_new = _import "jwt_new" : P.t ref -> int;
  val c_jwt_free = _import "jwt_free" public : P.t -> unit;
  val c_jwt_dump = _import "jwt_dump_str" public : P.t * int -> P.t;

  fun create () =
    let
      val p = ref P.null
      val ret = c_jwt_new p
      val () = if ret <> 0 then raise JwtError ("jwt_create", ret) else ()
      val jwt_ptr = F.new (!p)
    in
      F.addFinalizer (jwt_ptr, c_jwt_free);
      jwt_ptr
    end

  local
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
  in
    fun show t =
      fetchCString (F.withValue (t, fn t => c_jwt_dump (t, 0)))
  end
end

val jwt = Jwt.create ()
val () = print (Jwt.show jwt ^ "\n")
