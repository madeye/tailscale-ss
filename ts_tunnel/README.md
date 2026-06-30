A secure packet tunnel over UDP.

This crate implements the [ShadowVPN](https://github.com/madeye/shadowvpn) data-plane protocol: a
pre-shared-key (PSK), user-mode VPN that uses the [shadowsocks.org AEAD **UDP** wire
scheme](https://shadowsocks.org/doc/aead.html), with optional QUIC carrier obfuscation. It replaces
the WireGuard handshake/session machinery this crate previously contained.

## Wire protocol

Each plaintext packet maps to exactly one UDP datagram:

```text
[ salt (salt_len bytes) ] ++ [ AEAD ciphertext ++ tag (16 bytes) ]
```

* **`salt_len == key_len`** of the cipher: 16 bytes for `aes-128-gcm`, 32 bytes for `aes-256-gcm`
  and `chacha20-poly1305`. A fresh random salt is generated for every datagram.
* **Subkey:** `subkey = HKDF-SHA1(ikm = master_key, salt = salt, info = "ss-subkey", L = key_len)`.
* **Nonce:** the all-zero 12-byte nonce. This is safe because each datagram has a unique random salt
  and therefore a unique subkey, so the `(subkey, nonce)` pair is never reused.
* **Master key:** the per-peer pre-shared key (`Psk`). It can also be derived from a password with
  shadowsocks' `EVP_BytesToKey` (see `evp_bytes_to_key`).
* **Plaintext:** the opaque packet handed to / from the tunnel. Datagram boundaries are the frame
  boundaries — no length prefix, no multiplexing, no reassembly, and (deliberately, unlike an
  ss-proxy) no SOCKS address header.

## Carrier obfuscation

By default datagrams are wrapped to resemble **QUIC 1-RTT short-header** packets (so the carrier
reads as HTTP/3), shaping the payload to evade naive protocol classification. Both ends must agree;
a mismatched peer just sees its traffic dropped. Other options are `base64` and `none`. See
`Obfuscator`. This is cosmetic framing only — it adds no security.

## Sans I/O

This crate is implemented in the [Sans I/O](https://sans-io.readthedocs.io/) style: an `Endpoint`
processes packets that are provided to it, but it does not juggle network sockets or perform any I/O
itself. The caller feeds packet bytes into an `Endpoint` and gets back a set of actions to perform
(transmit encrypted datagrams to a peer, deliver decrypted packets to the local system). Because the
ShadowVPN protocol is stateless per datagram, there is no handshake, no session rotation, no replay
window, and no timers.

## Security limitations

This crate has not been subjected to a code audit by expert cryptography engineers. Conservatively,
assume that there could be a critical security hole that exposes your traffic to attackers.

The PSK is a symmetric secret shared by both ends; anyone holding it can read and forge traffic, so
it must be distributed and stored securely. There is no forward secrecy: a compromised PSK exposes
past and future traffic.

This crate operates on packets with no awareness of IP protocols — packets are opaque byte sequences
to be encrypted/decrypted/dropped. It does not enforce a 1:1 association between an IP address and a
peer, nor track underlay endpoint addresses or roaming. The caller tags packets to be sent with the
destination peer ID; received datagrams carry no peer identifier, so they are trial-decrypted against
each configured peer's key and the AEAD tag authenticates the match. It is up to the caller to
validate source IPs and route to the correct destination peer.
