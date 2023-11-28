structure AlgUtils =
struct
  fun toInt NONE = 0
    | toInt (SOME Jwt.HS256) = 1
    | toInt (SOME Jwt.HS384) = 2
    | toInt (SOME Jwt.HS512) = 3
    | toInt (SOME Jwt.RS256) = 4
    | toInt (SOME Jwt.RS384) = 5
    | toInt (SOME Jwt.RS512) = 6
    | toInt (SOME Jwt.ES256) = 7
    | toInt (SOME Jwt.ES384) = 8
    | toInt (SOME Jwt.ES512) = 9
    | toInt (SOME Jwt.TERM) = 10

  fun fromInt 0 = NONE
    | fromInt 1 = (SOME Jwt.HS256)
    | fromInt 2 = (SOME Jwt.HS384)
    | fromInt 3 = (SOME Jwt.HS512)
    | fromInt 4 = (SOME Jwt.RS256)
    | fromInt 5 = (SOME Jwt.RS384)
    | fromInt 6 = (SOME Jwt.RS512)
    | fromInt 7 = (SOME Jwt.ES256)
    | fromInt 8 = (SOME Jwt.ES384)
    | fromInt 9 = (SOME Jwt.ES512)
    | fromInt 10 = (SOME Jwt.TERM)
    | fromInt _ =
        raise Jwt.JwtError ("fromInt", ~1)

  val showAlgorithm =
    fn Jwt.HS256 => "HS256"
     | Jwt.HS384 => "HS384"
     | Jwt.HS512 => "HS512"
     | Jwt.RS256 => "RS256"
     | Jwt.RS384 => "RS384"
     | Jwt.RS512 => "RS512"
     | Jwt.ES256 => "ES256"
     | Jwt.ES384 => "ES384"
     | Jwt.ES512 => "ES512"
     | Jwt.TERM => "TERM"
end

structure ValidUtils =
struct
  fun toInt JwtValid.Error = 0x0001
    | toInt JwtValid.AlgMismatch = 0x0002
    | toInt JwtValid.Expired = 0x0004
    | toInt JwtValid.TooNew = 0x0008
    | toInt JwtValid.IssMismatch = 0x0010
    | toInt JwtValid.SubMismatch = 0x0020
    | toInt JwtValid.AudMismatch = 0x0040
    | toInt JwtValid.GrantMissing = 0x0080
    | toInt JwtValid.GrantMismatch = 0x0100

  fun fromInt 0x0000 = NONE
    | fromInt 0x0001 = SOME JwtValid.Error
    | fromInt 0x0002 = SOME JwtValid.AlgMismatch
    | fromInt 0x0004 = SOME JwtValid.Expired
    | fromInt 0x0008 = SOME JwtValid.TooNew
    | fromInt 0x0010 = SOME JwtValid.IssMismatch
    | fromInt 0x0020 = SOME JwtValid.SubMismatch
    | fromInt 0x0040 = SOME JwtValid.AudMismatch
    | fromInt 0x0080 = SOME JwtValid.GrantMissing
    | fromInt 0x0100 = SOME JwtValid.GrantMismatch
    | fromInt _ =
        raise JwtValid.JwtError ("fromInt", ~1)
end
