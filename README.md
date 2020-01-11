# nonomura

A Minecraft server proxy written in [Rust](https://rust-lang.org/).

## Usage

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

If this is connected to a BungeeCord server, it requires [this patch](https://owo.whats-th.is/8Xe9QR6.patch)
to be applied to the BungeeCord server; the patch has been built for [Waterfall](https://github.com/papermc/waterfall)
and might thus only work on that. The BungeeCord server must also disable its
throttling (set the option to a value `<= 0`).

## TODO

The following is the current TODO list:

  * Make routes modifyable at runtime (RPC?/REST?).
  * Add support for a fallback server.

## Licence

This software is licensed under the [BSD 3-Clause Licence](./LICENCE).
This software is thereby considered [free software](https://www.gnu.org/philosophy/free-sw.en.html).
