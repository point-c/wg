# wg

[![Wireguard](https://img.shields.io/badge/wireguard-%2388171A.svg?logo=wireguard)](https://www.wireguard.com/)
[![Go Reference](https://img.shields.io/badge/godoc-reference-%23007d9c.svg)](https://point-c.github.io/wg)

wg is a library designed to facilitate the creation and management of userland WireGuard networks. It interfaces with various components of the wireguard-go library, offering a Go API for network operations.

## Features
- **Device Management**: Control over WireGuard devices, including creation, configuration, and teardown.
- **Network Configuration**: Tools for setting up and managing a network stack that communicates through wireguard.
- **Advanced Networking**: Dial as any address inside the tunnel, allowing remote applications to see the correct remote address.

## Installation

To use wg in your Go project, install it using `go get`:

```bash
go get github.com/point-c/wg
```

## Usage

Configuration is handled by the [wgapi](https://github.com/point-c/wgapi) library.

### Basic

```go
var cfg wgapi.Configurable // your configuration
var n *wg.Net
dev, err := wg.New(wg.OptionNetDevice(&n), wg.OptionConfig(cfg))
if err != nil {
	panic(err)
}
// Use `n` in place of built in tcp/udp networking
dev.Close() // Close the device to clean up resources
```

### Networking

#### TCP

##### Listen

```go
var n *wg.Net
// Listen on port 80 on address 192.168.99.1
l, err := n.Listen(&net.TCPAddr{IP: net.IPv4(192, 168, 99, 1), Port: 80})
if err != nil {
    panic(err)
}
defer l.Close()

for {
    conn, err := l.Accept()
    if err != nil {
        panic(err)
    }
    // Start a goroutine and handle conn
}
```

##### Dial

```go
var n *wg.Net
// Dial with address 192.168.99.2
d := n.Dialer(net.IPv4(192, 168, 99, 2), 0) // Recommended to use port 0, since that will dial with a random open port.
// Dial port 80 on 192.168.99.1
conn, err := d.DialTCP(ctx, &net.TCPAddr{IP: net.IPv4(192, 168, 99, 1), Port: 80})
if err != nil {
    panic(err)
}
defer conn.Close()
// Use conn
```

### Options

#### `OptionNop`

Does nothing.

#### `OptionErr`

Throws an error on device creation. Used internally.

#### `OptionDevice`

Use your own raw network device.
Either this option or `OptionNetDevice` is required.

#### `OptionBind`

Use your own UDP device.
If not specified `DefaultBind` is used.

#### `OptionLogger`

Specify a `device.Logger` to pass to the `wireguard-go` library.

##### Logger Utilities

- [**wgevents**](https://github.com/point-c/wgevents): Structured logging from the `wireguard-go` library.
- [**wglog**](https://github.com/point-c/wglog): Logging utilities for `wireguard-go`.

#### `OptionConfig`

Configuration to use when configuring `wireguard-go`.

#### `OptionNetDevice`

Automatically configure a `wg.Net` type for use with this device.
It will be closed when the device is closed.

```go
var n *wg.Net
dev, err := wg.New(wg.OptionNetDevice(&n))
```

#### `OptionCloser`

Adds a function to be called when closing the device.

## Testing

The package includes tests that demonstrate its functionality. Use Go's testing tools to run the tests:

```bash
go test
```

## Godocs

To regenerate godocs:

```bash
go generate -tags docs ./...
```