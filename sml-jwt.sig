signature JWT_GRANTS =
sig
  type t
  datatype key = Key of string
  exception JwtError of string * int
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
end

signature JWT =
sig
  include JWT_GRANTS
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
  (* on implementations with finalizers, this is a noop *)
  val free: t -> unit
  val show: t -> string

  val encode: t -> string
  val decode: key option -> string -> t

  val setAlg: t -> key option -> algorithm option -> unit
  val getAlg: t -> algorithm option
end

signature JWT_VALID =
sig
  include JWT_GRANTS
  type jwt
  type algorithm

  datatype validation_error =
    Error
  | AlgMismatch
  | Expired
  | TooNew
  | IssMismatch
  | SubMismatch
  | AudMismatch
  | GrantMissing
  | GrantMismatch

  type error
  exception ValidationError of error

  val create: algorithm option -> t
  val free: t -> unit

  val getExpLeeway: t -> Time.time
  val setExpLeeway: t -> Time.time -> unit
  val getNbfLeeway: t -> Time.time
  val setNbfLeeway: t -> Time.time -> unit
  val setNow: t -> Time.time -> unit
  val validate: jwt -> t -> unit
  val hasError: error -> validation_error -> bool
end

structure Jwt =
struct
  datatype key = Key of string
  exception JwtError of string * int
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

  fun check s ret =
    if ret <> 0 then raise JwtError (s, ret) else ()
end

structure JwtValid =
struct
  datatype key = Key of string
  exception JwtError of string * int

  datatype validation_error =
    Error
  | AlgMismatch
  | Expired
  | TooNew
  | IssMismatch
  | SubMismatch
  | AudMismatch
  | GrantMissing
  | GrantMismatch

  fun check s ret =
    if ret <> 0 then raise JwtError (s, ret) else ()
end
