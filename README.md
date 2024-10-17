# `recursor` - CoreDNS Plugin  

The `recursor` resolves domains using defined IP addresses or resolving other mapped domains using defined resolvers. 

## Use Case

![](docs/flow.png)

## Config Syntax / Examples

The `recursor` configuration includes the following definitions:
- `zone`: The DNS zone for the recursor.
- `verbose`: The logging level for stdout:
  - `0`: minimal logging
  - `1`: moderate logging
  - `2`: detailed logging
- `resolvers`: Other DNS servers to use:
  - *map-key/id*: The name of the resolver. The `default` overrides the system's default resolver.
  - `urls`: A list of URL addresses, e.g., `udp://127.0.0.1:53` (the system default is represented by `://default`).
  - `timeout_ms`: The connection timeout for the resolver, in milliseconds.
- `aliases`: Domain aliases:
  - *map-key/id*: The alias name, a subdomain, or `*` if you want the recursor to act as a DNS repeater.
  - `ips`: A list of IP addresses to be returned as part of the response.
  - `hosts`: Domains that will be resolved, with the resulting IP addresses returned in the response.
  - `shuffle_ips`: Default is `false`. If set to `true`, IP addresses will be returned in random order.
  - `resolver_name`: The name of the resolver to use. The default is... well, `default`, of course :)
  - `ttl`: Time To Live for the DNS record, in seconds.

#### Corefile

```txt
recursor {   
    [external-yaml config-file-path]
    [external-json config-file-path]

    [verbose 0..2]
    zone: demo.svc
    resolver dns-c {
        urls udp://1.1.1.1:53 udp://1.0.0.1:53
        timeout_ms 500
    }
    resolver dns-g {
        urls udp://8.8.8.8:53 udp://8.8.4.4:53
    }  
    resolver demo {
        urls udp://10.0.0.1:53
    }  
    alias alias1 {
        hosts www.example.org www.example.com
        shuffle_ips true
        resolver_name dns-c
        ttl 11
    }
    alias alias2 {
        ips 10.0.0.1 10.0.0.2
        ttl 12
    }
    alias alias3 {
        ips 10.0.0.1 10.0.0.2
        hosts www.example.net
        resolver_name dns-g
        ttl 13
    }
    alias alias4 {
        hosts www.example.net
        ttl 14
    }  

    alias * {
        resolver_name demo
        ttl 15
    }  
}
```

#### External YAML

```yaml
        zone: demo.svc
        resolvers:
          dns-c:
            urls: [ udp://1.1.1.1:53, udp://1.0.0.1:53 ]
            timeout_ms: 500
          dns-g:
            urls: [ udp://8.8.8.8:53, udp://8.8.4.4:53 ]
          demo:
            urls: [ udp://10.0.0.1:53 ]
        aliases:
          alias1:
            hosts: [ www.example.org, www.example.com ]
            shuffle_ips: true
            resolver_name: dns-c
            ttl: 11
          alias2:
            ips: [ 10.0.0.1, 10.0.0.2 ]
            ttl: 12
          alias3:
            ips: [ 10.0.0.1, 10.0.0.2 ]
            hosts: [ www.example.net ]
            resolver_name: dns-g
            ttl: 13
          alias4:
            hosts: [ www.example.net ]
            ttl: 14
          "*":
            resolver_name: demo
            ttl: 15
```

#### External JSON

```json
{
  "zone": "demo.svc",
  "resolvers": {
    "dns-c": {
      "urls": [ "udp://1.1.1.1:53", "udp://1.0.0.1:53" ],
      "timeout_ms": 500
    },
    "dns-g": {
      "urls": [ "udp://8.8.8.8:53", "udp://8.8.4.4:53" ]
    },
    "demo": {
      "urls": [ "udp://10.0.0.1:53" ]
    }
  },
  "aliases": {
    "alias1": {
      "hosts": [ "www.example.org", "www.example.com" ],
      "shuffle_ips": true,
      "resolver_name": "dns-c",
      "ttl": 11
    },
    "alias2": {
      "ips": [ "10.0.0.1", "10.0.0.2" ],
      "ttl": 12
    },
    "alias3": {
      "ips": [ "10.0.0.1", "10.0.0.2" ],
      "hosts": [ "www.example.net" ],
      "resolver_name": "dns-g",
      "ttl": 13
    },
    "alias4": {
      "hosts": [ "www.example.net" ],
      "ttl": 14
    },
    "*": {
      "resolver_name": "demo",
      "ttl": 15
    }
  }
}
```

#### [More examples](examples)

## Metrics

- [Definition](metrics.go)
- [Grafana Dashboard](docs/dashboard.json)

![](docs/dashboard.png)


## Run It

### Build It

```bash
#!/bin/bash eu

# Extract coredns source code
tar xzvf coredns.src.tar.gz
pushd coredns
  # Add external plugins
  go get github.com/kinjelom/coredns-recursor@latest
  grep -q '^recursor:' plugin.cfg || echo -e "recursor:github.com/kinjelom/coredns-recursor" >> plugin.cfg
  # Build
  go generate
  go build
  ./coredns -plugins
popd
```

### Deployments Ready to Use

- [BOSH Release](https://github.com/kinjelom/coredns-boshrelease)

## Try it

Helpful commands:
```bash
dig alias1.demo.svc @127.0.0.1 -p 1053
nslookup -port=1053 -debug -type=A alias2.demo.svc 127.0.0.1
```
