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

functor MkJwtFn (Library : LOAD_LIBRARY) = struct
  open Jwt
  open Foreign

  structure P = Memory
  structure F = Finalizable

  type t = P.voidStar F.t

  val lib = loadLibrary (Library.path ())

  val c_jwt_new = buildCall1 (getSymbol lib "jwt_new", cStar cPointer, cInt)
  val c_jwt_free = buildCall1 (getSymbol lib "jwt_free", cPointer, cVoid)
  val c_jwt_dump = buildCall2 (getSymbol lib "jwt_dump_str", (cPointer, cInt), cString)

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
end

structure TestLibrary = struct
  val pathRef = ref ""
  val path = fn () => !pathRef
end

val () = TestLibrary.pathRef := "/usr/lib/x86_64-linux-gnu/libjwt.so"
structure TestJwt = MkJwtFn(TestLibrary)

(*
To test:

rlwrap poly
use "sml-jwt.sig";
use "sml-jwt.polyml.sml";

*)