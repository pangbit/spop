[![Test](https://github.com/nbari/spop/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/nbari/spop/actions/workflows/test.yml)

# spop

Library for parsing HAProxy SPOP protocol messages.

The protocol is described here: https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt

## Test

To test you need to have [just](https://github.com/casey/just), [podman](https://podman.io) and [rust](https://www.rust-lang.org/tools/install) installed.


To run haproxy in a container, only type  `just`, this will build the container and start it.

To compile and run the test agent, type:

```bash
just agent
```

> You need to install `cargo install cargo-watch` to run the agent in watch mode.

To send a request to the haproxy container, type:

```bash
just test
```
