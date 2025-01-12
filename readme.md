# ei - _easy iptables_

An iptables wrapper that works in harmony with Docker.

## The Problem

Most firewalls either:

- Doesn't care about container networking
- Doesn't make sense when everything else using iptables and ipset
- Destroy docker iptables
- Require workarounds

## This does

- Create rules that doesn't break container-to-host networking (meaning container->wireguard work just fine), by only block internet port and doesn't make misleading stuff.
- Create a simple set of port-fowarding that is easy to understand
- Having essentially good protection presets ootb
- Intergrate and works (pretty) well with xcord xprotect, tailscale and more (if you send patches)
- Builtin prometheus exporter
- Literally simpler than ufw

## Run dependencies

- `ipset`
- `iptables`
- `ip`
- `ip6tables`

### System privileges

- `eidaemon` requires `CAP_NET_ADMIN` and `CAP_NET_RAW` capabilities.

## Configuration explain

`whitelist` and `blacklist` are the secondary way of adding port rule. while classic setup will block all internet incomming, `whitelist` and internal `ei-allowed-*-ports` ipset (configured dynamically through cli) will suppose to accept connection, while `blacklist` will block unwanted port by default, and most importantly `docker`

> `whitelist` and `blacklist` has its own port set because...config allows it to

## Usage

Basic commands:

- **List all ports**

  ```sh
  ei list
  ```

- **Add a port**

  ```sh
  ei add 8080 tcp
  ```

- **Remove a port**

  ```sh
  ei remove 8080 tcp
  ```

- **Reload daemon**

  ```sh
  ei reload
  ```

- **Show metrics**

  ```sh
  ei metrics
  ```
