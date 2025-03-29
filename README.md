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

The HAProxy configuration is in the `haproxy.cfg` file, and the SPOE
configuration is in the `spoe-test.conf` file.

## Example

```conf
global
    log stdout format raw local0
    daemon

defaults
    log     global
    mode    http
    option  httplog
    timeout client 30s
    timeout connect 10s
    timeout server 30s

frontend main
    bind :5000
    filter spoe engine test config /usr/local/etc/haproxy/spoe-test.conf

    http-after-response set-header X-SPOE-VAR %[var(txn.spoe_test.my_var)]

    default_backend app

backend spoe-test
    mode tcp
    server rust-agent 127.0.0.1:12345

backend app
    mode http
    http-request return status 200 content-type "text/plain" string "Hello"
```

And the spoe agent conf:

```conf
[test]
spoe-agent test
    messages    log-request
    option      var-prefix spoe_test
    option      continue-on-error
    timeout     processing 10ms
    use-backend spoe-test

spoe-message log-request
    args ip=src country=hdr(CF-IPCountry) user_agent=hdr(User-Agent)
    event on-frontend-http-request
```
