# Real IP from Cloudflare Proxy/Tunnel with LAN Whitelist

This is a fork of `github.com/fma965/cloudflarewarp`, which was originally based on `github.com/BetterCorp/cloudflarewarp`. This version has been significantly enhanced to dynamically fetch and update Cloudflare's IP ranges from the official Cloudflare API. This ensures the plugin always uses the most current IP list, improving reliability and security.

If Traefik is behind a Cloudflare Proxy/Tunnel, it won't be able to get the real IP from the external client as well as other information.

This plugin solves this issue by overwriting the `X-Real-IP` and `X-Forwarded-For` headers with an IP from the `Cf-Connecting-Ip` header for requests coming from Cloudflare. The plugin also writes the `Cf-Visitor` scheme to the `X-Forwarded-Proto` header, which can fix infinite redirect issues with applications like WordPress.

## Key Improvements in this Fork

- **Dynamic Cloudflare IP Ranges:** Instead of relying on a static, hardcoded list of Cloudflare IPs, this version fetches the latest IP ranges directly from the Cloudflare API.
- **Automatic Updates:** The IP list is automatically refreshed at a configurable interval, ensuring that changes to Cloudflare's infrastructure are picked up without manual intervention.

## Configuration

### Configuration Options

| Setting         | Allowed values | Default | Description                                                                 |
| :-------------- | :------------- | :------ | :-------------------------------------------------------------------------- |
| `trustip`       | `[]string`     | `[]`    | A list of custom IP addresses or CIDR ranges to trust.                      |
| `refreshInterval` | `string`       | `24h`   | The interval at which to refresh the Cloudflare IP list (e.g., `12h`, `30m`). |

### Enable the Plugin

```yaml
experimental:
  plugins:
    cloudflarewarp:
      moduleName: github.com/fma965/cloudflarewarp
      version: v1.4.0 # Or the latest version
```

### Plugin Configuration Example

Here is an example of how to configure the plugin to trust your local network and automatically use the latest Cloudflare IPs.

```yaml
http:
  middlewares:
    cloudflarewarp:
      plugin:
        cloudflarewarp:
          refreshInterval: 12h
          trustip:
            - 10.0.0.0/8
            - 172.16.0.0/12
            - 192.168.0.0/16
  routers:
    my-router:
      rule: Path(`/whoami`)
      service: service-whoami
      entryPoints:
        - http
      middlewares:
        - cloudflarewarp

  services:
    service-whoami:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:5000
```

# Testing

[https://github.com/fma965/cloudflarewarp/tree/master/test](https://github.com/fma965/cloudflarewarp/tree/master/test)

We have written the following tests in this repo:

- golang linting
- yaegi tests (validate configuration matches what Traefik expects)
- General GO code coverage
- Virtual implementation tests (spin up traefik with yml/toml tests to make sure the plugin actually works)
- Live implementation tests (spin up traefik with the plugin definition as it would be for you, and run the same tests again)

These tests allow us to make sure the plugin is always functional with Traefik and Traefik version updates.

# Standing up the crowdsec bouncer plugin in traefik

See the following blog post for a walkthrough on how to stand up the crowdsec bouncer plugin in traefik: [https://bpto.li/H0JY11Zb](https://bpto.li/H0JY11Zb)