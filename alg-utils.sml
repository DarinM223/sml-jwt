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
