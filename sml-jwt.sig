signature JWT =
sig
  exception JwtError of string * int
  type t
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

  val create: unit -> t
  val show: t -> string

  val getGrant: t -> string -> string option
  val getGrantInt: t -> string -> int option
  val getGrantBool: t -> string -> bool option
  val getGrantsJson: t -> key option -> string option

  val addGrant: t -> string -> string -> unit
  val addGrantInt: t -> string -> int -> unit
  val addGrantBool: t -> string -> bool -> unit
  val addGrantsJson: t -> string -> unit

  val delGrant: t -> string -> unit
  val delGrants: t -> unit

  val encode: t -> string
  val decode: key option -> string -> t

  val setAlg: key -> t -> algorithm option -> unit
  val getAlg: t -> algorithm option
end
