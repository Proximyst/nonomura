# nonomura

A Minecraft server proxy written in [Rust](https://rust-lang.org/).

## Usage

Compile the project on your server (important!) with `cargo build --release`.
If you don't supply `--release`, it will be extremely unoptimised and your
performance will stagnate significantly.

**Achtung**: This project is optimised towards hosting upwards of 40 players
concurrently. Any higher amount might not work as well as the lower amounts,
and any fixes are welcome for this so long as lower amounts do not become
worse in performance. Performance hits on higher player counts are unwelcome
but not disallowed; performance hits on lower player counts are both
unwelcome and disallowed.

The bound IP can be set in the environment variable `ADDRESS`.

The routes are to be created in the file pointed at by the environment variable
`ROUTES_FILE` (default `routes.json`) in the following key-value format:

```json
{
	"ip": "destination"
}
```

where the `ip` is the hostname the client uses, and `destination` is the actual
destination they get connected to. An example `routes.json` is attached in this
repository: [`routes.json`](./routes.json).

If this is connected to a BungeeCord/Waterfall server, it requires to enable
the `proxy-protocol` option in the listener configuration. This might also
require to disable connection throttling by setting it to 0.

## TODO

The following is the current TODO list:

  * [✔️- 2020-01-12] *Make routes modifyable at runtime (RPC?/REST?).*
  * [✔️- 2020-01-12] *Add support for a fallback server.*
  * [✔️- 2020-01-13] *Add support for HAProxy's PROXY protocol to avoid
  patching the Waterfall server.*
  * Make copying go around on a few select threads and spend at most `n`
  timeunits on it. This must have buckets of copying streams which will simply
  be added to as time goes on and more streams must be copied.

## Licence

This software is licensed under the [BSD 3-Clause Licence](./LICENCE).
This software is thereby considered [free software](https://www.gnu.org/philosophy/free-sw.en.html).
