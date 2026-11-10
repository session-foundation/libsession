# Runs a test binary and, if it dies on a signal, prints every thread's backtrace before letting
# Catch2 report the failure.  Exits with the binary's own status otherwise.
#
#   gdb -q -batch -nx -x utils/ci/backtrace-on-crash.gdb --args ./tests/testAll ...

set pagination off
set confirm off
set print thread-events off
set print inferior-events off
# Docker's default seccomp profile refuses the personality() call gdb uses to turn ASLR off.
set disable-randomization off
handle SIGPIPE nostop noprint pass

run

if !$_isvoid($_exitcode)
  quit $_exitcode
end
# Killed by a signal gdb passes straight through, so there is no stack left to show.
if !$_isvoid($_exitsignal)
  quit 128 + $_exitsignal
end

echo \n===== Fatal signal: the stopped thread in full, then every thread =====\n
bt full
echo \n
info threads
thread apply all bt
echo \n===== End of backtraces; Catch2's report follows =====\n
continue
quit 1
