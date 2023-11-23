local
  fun showOption f (SOME s) = "SOME " ^ f s
    | showOption _ NONE = "NONE"
in
  val showStr_option = showOption (fn t0 => "\"" ^ t0 ^ "\"")
  val showInt_option = showOption Int.toString
  val showBool_option = showOption Bool.toString
  val showAlgorithm_option = showOption AlgUtils.showAlgorithm
end

fun main () =
  let
    val jwt = Jwt.create ()
    val () = print (Jwt.show jwt ^ "\n")
    val () = Jwt.addGrant jwt "hello" "world"
    val () = print (showStr_option (Jwt.getGrant jwt "hello") ^ "\n")
    val () = print (showStr_option (Jwt.getGrant jwt "world") ^ "\n")
    val () = Jwt.addGrantInt jwt "life" 42
    val () = print (showInt_option (Jwt.getGrantInt jwt "life") ^ "\n")
    val () = Jwt.addGrantBool jwt "foo" true
    val () = print (showBool_option (Jwt.getGrantBool jwt "foo") ^ "\n")
    val () = print (showStr_option (Jwt.getGrantsJson jwt NONE) ^ "\n")
    val () = print
      (showStr_option (Jwt.getGrantsJson jwt (SOME (Jwt.Key "life"))) ^ "\n")
    val () = Jwt.addGrantsJson jwt "{\"a\": \"b\",\"c\": 100}"
    val () = print (showStr_option (Jwt.getGrantsJson jwt NONE) ^ "\n")
    val () = Jwt.delGrant jwt "c"
    val () = print (showStr_option (Jwt.getGrantsJson jwt NONE) ^ "\n")
    val s = Jwt.encode jwt
    val () = print (s ^ "\n")
    val jwt2 = Jwt.decode NONE s
    val () = print (showStr_option (Jwt.getGrantsJson jwt2 NONE) ^ "\n")
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

    val jwt_valid = JwtValid.create (SOME Jwt.RS256)
    val () = Jwt.addGrantInt jwt "exp" 0
    val () = JwtValid.setNow jwt_valid (Time.now ())

    (* Test that validation fails if the JWT token is expired *)
    val caughtError = ref false
    val () =
      JwtValid.validate jwt jwt_valid
      handle JwtValid.ValidationError e =>
        ( print "Got validation error\n"
        ; if JwtValid.hasError e JwtValid.Expired then
            (print "Error is expired, which is expected\n"; caughtError := true)
          else
            print "Error should be expired\n"
        )
    val () =
      if !caughtError then ()
      else raise Fail "First validation should throw expired error"

    (* Test that validation succeeds after the exp and nbf leeways are set *)
    val () = JwtValid.setNbfLeeway jwt_valid
      (Time.+ (Time.now (), Time.fromSeconds 100))
    val () = JwtValid.setExpLeeway jwt_valid
      (Time.+ (Time.now (), Time.fromSeconds 100))
    val () = JwtValid.validate jwt jwt_valid
  in
    print ("Validated JWT\n")
  end
