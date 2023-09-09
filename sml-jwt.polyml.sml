signature FINALIZABLE =
  sig
    type 'a t
    val new : 'a -> 'a t
    val addFinalizer : 'a t * ('a -> unit) -> unit
    val finalizeBefore : 'a t * 'b t -> unit
    val touch : 'a t -> unit
    val withValue : 'a t * ('a -> 'b) -> 'b
  end

structure Finalizable :> FINALIZABLE =
  struct
    datatype 'a t =
      T of {
        value : 'a ref,
        finalizers : ('a -> unit) list ref,
        afters : (unit -> unit) list ref
      }

    (* `touch (T {value, ...})` is an operation that requires `value` but
     * does nothing. *)
    fun touch (T {value, ...}) = Weak.touch value

    fun withValue (t as T {value, ...}, f) =
      f (!value) handle e => (touch t; raise e)

    fun addFinalizer (T {finalizers, ...}, f) =
      finalizers := f :: !finalizers

    fun finalizeBefore (T {afters, ...}, t) =
      afters := (fn () => touch t) :: !afters


    type pending = {isAlive : unit -> bool, runFinalizers : unit -> unit}

    local
      (* global state for finalizables that have not been finalized. *)
      val pendingList : pending list ref = ref []

      fun update f x =
        let
          val (y, pendingList') = f (x, !pendingList)
        in
          pendingList := pendingList';
          y
        end

      val mutex = Thread.Mutex.mutex ()
    in
      fun updatePendingList f = ThreadLib.protect mutex (update f)
    end


    fun add (ps', ps) = ((), ps' @ ps)

    fun clean ((), ps) =
      foldl
        (
          fn (p as {isAlive, runFinalizers}, (runNowFns, ps)) =>
            if isAlive ()
            then (runNowFns, p :: ps)
            else (runFinalizers :: runNowFns, ps)
        )
        ([], [])
        ps

    fun swap (a, b) = (b, a)


    fun reportExn e = (
      TextIO.output (
        TextIO.stdErr,
        concat["Warning: finalizer raised exception ", exnMessage e, "\n"]
      );
      TextIO.flushOut TextIO.stdErr
    ) handle _ => ()

    fun run f = f () handle e => reportExn e

    fun gcAndFinalize () =
      let
        fun loop ps =
          let
            val ps = updatePendingList swap [] @ ps

            val () = PolyML.fullGC ()  (* PolyML.fullGC is synchronous *)
            val (runNowFns, ps') = clean ((), ps)
          in
            app run runNowFns;
            if not (null runNowFns)
            then loop ps'
            else ps'
          end

        open Thread.Thread
        val attrs = getAttributes ()
        val () = setAttributes [InterruptState InterruptDefer]

        (* Empty the pending list so that the cleaning thread does not
         * start running finalizers too. *)
        val ps = updatePendingList swap []
        val ps' = loop ps

        (* Put back remaining pending items in `ps'`.  Swap first to add the
         * global pending list, which is likely to contain very few items if
         * any, onto the front of `ps'`. *)
        val () = updatePendingList (add o swap) ps'

        val () = setAttributes attrs
      in
        ()
      end

    local
      fun threadFn () = (
        Thread.Mutex.lock Weak.weakLock;
        while true do (
          app run (updatePendingList clean ());
          Thread.ConditionVar.wait (Weak.weakSignal, Weak.weakLock)
        )
      )

      fun startUp () = (
        Thread.Thread.fork (threadFn, []);
        OS.Process.atExit gcAndFinalize
      )
    in
        val () = PolyML.onEntry startUp; (* For future sessions *)
        val () = startUp() (* For this session *)
    end

    fun new (v : 'a) : 'a t =
      let
        val afters = ref []
        val finalizers = ref []
        val value = ref v
        val t =
          T {
            afters = afters,
            finalizers = finalizers,
            value = value
          }
        val weak = Weak.weak (SOME value)
        fun isAlive () = isSome (!weak)
        fun runFinalizers () = (
          List.app (fn f => f v) (!finalizers);
          List.app (fn f => f ()) (!afters)
        )
        val pending = {isAlive = isAlive, runFinalizers = runFinalizers}

        val () = updatePendingList add [pending]
      in
        t
      end
  end

signature LOAD_LIBRARY = sig
  val path : unit -> string
end

functor MkJwtFn (Library : LOAD_LIBRARY) : JWT = struct
  open Jwt
  open Foreign

  structure P = Memory
  structure F = Finalizable

  type t = P.voidStar F.t

  val lib = loadLibrary (Library.path ())

  val c_jwt_new = buildCall1 (getSymbol lib "jwt_new", cStar cPointer, cInt)
  val c_jwt_free = buildCall1 (getSymbol lib "jwt_free", cPointer, cVoid)
  val c_jwt_dump = buildCall2 (getSymbol lib "jwt_dump_str", (cPointer, cInt), cString)
  val c_jwt_get_grant = buildCall2 (getSymbol lib "jwt_get_grant", (cPointer, cString), cOptionPtr cString)
  val c_jwt_get_grant_int = buildCall2 (getSymbol lib "jwt_get_grant_int", (cPointer, cString), cLong)
  val c_jwt_get_grant_bool = buildCall2 (getSymbol lib "jwt_get_grant_bool", (cPointer, cString), cInt)
  val c_jwt_get_grants_json = buildCall2 (getSymbol lib "jwt_get_grants_json", (cPointer, cOptionPtr cString), cOptionPtr cString)
  val c_jwt_add_grant = buildCall3 (getSymbol lib "jwt_add_grant", (cPointer, cString, cString), cInt)
  val c_jwt_add_grant_int = buildCall3 (getSymbol lib "jwt_add_grant_int", (cPointer, cString, cLong), cInt)
  val c_jwt_add_grant_bool = buildCall3 (getSymbol lib "jwt_add_grant_bool", (cPointer, cString, cInt), cInt)
  val c_jwt_add_grants_json = buildCall2 (getSymbol lib "jwt_add_grants_json", (cPointer, cString), cInt)
  val c_jwt_del_grant = buildCall2 (getSymbol lib "jwt_del_grants", (cPointer, cString), cInt)
  val c_jwt_del_grants = buildCall2 (getSymbol lib "jwt_del_grants", (cPointer, cPointer), cInt)
  val c_jwt_encode = buildCall1 (getSymbol lib "jwt_encode_str", cPointer, cOptionPtr cString)
  val c_jwt_decode = buildCall4 (getSymbol lib "jwt_decode", (cStar cPointer, cString, cOptionPtr cString, cInt), cInt)
  val c_jwt_set_alg = buildCall4 (getSymbol lib "jwt_set_alg", (cPointer, cInt, cOptionPtr cString, cInt), cInt)
  val c_jwt_get_alg = buildCall1 (getSymbol lib "jwt_get_alg", cPointer, cInt)
  val c_errno = buildCall0 (getSymbol lib "custom_errno", (), cInt)
  val ENOENT = 2

  fun create () =
    let
      val p = ref P.null
      val () = check "create" (c_jwt_new p)
      val jwt_ptr = F.new (!p)
    in
      F.addFinalizer (jwt_ptr, c_jwt_free);
      jwt_ptr
    end
  fun show t = F.withValue (t, fn t => c_jwt_dump (t, 0))
  fun getGrant t key =
    F.withValue (t, fn t => c_jwt_get_grant (t, key))
  fun getGrantInt t key =
    F.withValue (t, fn t =>
      let val r = c_jwt_get_grant_int (t, key)
      in if c_errno () = ENOENT then NONE else SOME r
      end)
  fun getGrantBool t key =
    F.withValue (t, fn t =>
      let val r = c_jwt_get_grant_bool (t, key)
      in if c_errno () = ENOENT then NONE else SOME (if r = 0 then false else true)
      end)
  fun getGrantsJson t (SOME (Key key)) =
        F.withValue (t, fn t => c_jwt_get_grants_json (t, SOME key))
    | getGrantsJson t NONE =
        F.withValue (t, fn t => c_jwt_get_grants_json (t, NONE))
  fun addGrant t key value =
    F.withValue (t, fn t => check "addGrant" (c_jwt_add_grant (t, key, value)))
  fun addGrantInt t key value =
    F.withValue (t, fn t =>
      check "addGrantInt" (c_jwt_add_grant_int (t, key, value)))
  fun addGrantBool t key value =
    F.withValue (t, fn t =>
      check "addGrantBool" (c_jwt_add_grant_bool (t, key, if value then 1 else 0)))
  fun addGrantsJson t json =
    F.withValue (t, fn t =>
      check "addGrantsJson" (c_jwt_add_grants_json (t, json)))
  fun delGrant t key =
    F.withValue (t, fn t => check "delGrant" (c_jwt_del_grant (t, key)))
  fun delGrants t =
    F.withValue (t, fn t => check "delGrants" (c_jwt_del_grants (t, P.null)))
  fun encode t =
    F.withValue (t, fn t =>
      case c_jwt_encode t of
        NONE => raise JwtError ("encode", ~1)
      | SOME s => s)
  fun decode key s =
    let
      val p = ref P.null
      val (key, key_len) =
        case key of
          SOME (Key key) => (SOME key, String.size key)
        | NONE => (NONE, 0)
      val () = check "decode" (c_jwt_decode (p, s, key, key_len))
      val jwt_ptr = F.new (!p)
    in
      F.addFinalizer (jwt_ptr, c_jwt_free);
      jwt_ptr
    end
  fun setAlg t key alg =
    F.withValue (t, fn t =>
      let
        val (key, key_len) =
          case key of
            SOME (Key key) => (SOME key, String.size key)
          | NONE => (NONE, 0)
      in
        check "setAlg" (c_jwt_set_alg (t, AlgUtils.toInt alg, key, key_len))
      end)
  fun getAlg t =
    F.withValue (t, fn t => AlgUtils.fromInt (c_jwt_get_alg t))
end

structure Library = struct
  val pathRef = ref ""
  val path = fn () => !pathRef
end

val () = Library.pathRef := "/usr/lib/x86_64-linux-gnu/libjwt.so"
structure Jwt = MkJwtFn(Library)

(*
To test:

rlwrap poly
use "sml-jwt.sig";
use "alg-utils.sml";
use "sml-jwt.polyml.sml";

*)