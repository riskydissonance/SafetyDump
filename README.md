# SafetyDump

SafetyDump is an in-memory process memory dumper.

This uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output.
This allows the dump to be redirected to a file or straight back down C2 or through other tools.

Note as everything takes place in memory this can be memory intensive while the dumping is taking place.

See its integration with https://github.com/nettitude/PoshC2 for how it can be used to dump process memory down C2 without the executable or the dump touching disk.

## Usage

Running the compiled binary without any arguments will find and dump lsass.exe.

```
./SafetyDump.exe
```

Passing a PID to the program will instead dump that process.

```
./SafetyDump.exe <processIdToDump>
```