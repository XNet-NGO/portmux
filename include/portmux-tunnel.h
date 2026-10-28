/*
 ============================================================================
 Name        : portmux-tunnel.h
 Description : Userspace, no-TUN encrypted rendezvous tunnel for portmux.
 License     : MIT (portmux) + MIT (vendored noise-c, see third-part/noise-c)
 ============================================================================

 PURPOSE
 -------
 A "Scenario B" rendezvous tunnel: a CLIENT (e.g. a phone running Switchboard/
 switch-mcp, or the portmux CLI) makes ONE outbound, encrypted connection to a
 SERVER (a box the operator controls). The server exposes a plaintext local
 port; bytes written there are relayed, encrypted, to the client, which splices
 them to a local plaintext target (e.g. the phone's adbd on 127.0.0.1:5555).

     laptop  --(plain, localhost)-->  server:BRIDGE_PORT
                                          |            ^
                                          v            |  Noise-encrypted TCP
                                       (relay)          \  (one outbound conn
                                          |               \  from the client)
                                          +----------------> client
                                                              |  plain splice
                                                              v
                                                      target 127.0.0.1:5555 (adbd)

 No TUN, no VpnService, no root. The client's single outbound connection is
 NAT/firewall friendly. The outbound leg honors the route's PortmuxEgress, so
 the encrypted tunnel can itself be pinned to a chosen network (e.g. cellular).

 CRYPTO
 ------
 Noise handshake pattern NN with a pre-shared key (this vendored noise-c spells
 it with the legacy "NoisePSK_" prefix; it is the NNpsk0 construction):

     NoisePSK_NN_25519_<CIPHER>_BLAKE2s         CIPHER = AESGCM | ChaChaPoly

 - NN: ephemeral-ephemeral X25519 -> forward secrecy.
 - PSK: the 32-byte pre-shared key is the authenticator (IP + key only; no
   certificates, no PKI). A wrong PSK fails the handshake (no data flows).
 - Cipher: AESGCM is preferred where ARMv8 AES is present (it is on the target
   Pixel), ChaChaPoly otherwise. The initiator proposes; both ends are
   configured with the same suite for v1 (negotiation is a later refinement).

 WIRE FRAMING
 ------------
 Over the raw TCP stream, every message (handshake AND transport) is framed as:

     [ u16 length (big-endian) ][ length bytes of Noise message ]

 - Handshake: two framed messages (-> e ; <- e, ee), per Noise NN.
 - Transport: each framed payload is a Noise transport message (AEAD box).

 STREAM MUX (B1: transparent L4 port-map, no bridge)
 ---------------------------------------------------
 The decrypted payload of each transport frame is NOT a raw byte slice; it is a
 mux record so that MANY independent connections share ONE persistent Noise
 carrier (like WireGuard carries many flows over one UDP session, but done in
 userspace since there is no TUN):

     [ u8 type ][ u16 stream-id (BE) ][ payload ... ]

       type 0x01 OPEN   : server->client, open a new stream; client connects to
                          its local target (adbd). No payload.
       type 0x02 DATA   : either direction; payload is the stream's bytes.
       type 0x03 CLOSE  : either direction; the stream's socket closed. No payload.

 Topology (phone behind CGNAT still dials OUT; the box's public port is now the
 PLAINTEXT adb endpoint — true 1:1, no separate bridge port to think about):

     adb --(plain)--> box:PUBLIC  ──┐  (server assigns a stream-id,
                                    │   frames OPEN/DATA/CLOSE)
                      box:CARRIER <─┘  one persistent Noise session
                          ▲   │         (phone dialed in, held open)
            Noise-encrypted│   │
                           │   ▼
                         phone (carrier client) demuxes streams
                           │  plain connect per stream
                           ▼
                   target 127.0.0.1:5555 (adbd)

 - Max Noise message is 65535 bytes; the mux header is 3 bytes, so DATA payload
   per frame is capped at PM_TUNNEL_MAX_PLAINTEXT - 3; the relay chunks larger
   reads. Overhead is ~3 bytes per frame on top of the 16-byte AEAD tag.
 - A stream's clean close is an explicit CLOSE record (not TCP FIN), so one
   flow ending does not tear down the shared carrier.
 ============================================================================
*/

#ifndef __PORTMUX_TUNNEL_H__
#define __PORTMUX_TUNNEL_H__

#include "portmux.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Framing + crypto constants (shared by client and server). */
#define PM_TUNNEL_PSK_LEN       32
#define PM_TUNNEL_MAX_NOISE_MSG 65535
#define PM_TUNNEL_AEAD_TAG      16
#define PM_TUNNEL_MAX_PLAINTEXT (PM_TUNNEL_MAX_NOISE_MSG - PM_TUNNEL_AEAD_TAG)

/* Stream-mux record types (first byte of each decrypted transport payload). */
#define PM_MUX_OPEN   0x01
#define PM_MUX_DATA   0x02
#define PM_MUX_CLOSE  0x03
#define PM_MUX_HDR    3            /* 1B type + 2B stream-id (BE) */
#define PM_MUX_MAX_STREAMS 256     /* concurrent streams over one carrier */

/* Cipher suite selector for the Noise name. */
typedef enum
{
    PM_TUNNEL_CIPHER_AESGCM,     /* NoisePSK_NN_25519_AESGCM_BLAKE2s    */
    PM_TUNNEL_CIPHER_CHACHAPOLY, /* NoisePSK_NN_25519_ChaChaPoly_BLAKE2s */
} PmTunnelCipher;

/**
 * portmux_add_tunnel_client:
 * @self: a #Portmux
 * @listen_addr/@listen_port: OPTIONAL local plaintext listener. For Scenario B
 *   the client usually has NO local listener (it dials out and splices to a
 *   fixed target), so pass listen_port = 0 to disable it.
 * @server_addr/@server_port: the rendezvous server to dial (encrypted).
 * @target_addr/@target_port: the local plaintext service to expose through the
 *   tunnel (e.g. "127.0.0.1", 5555 for adbd).
 * @psk: PM_TUNNEL_PSK_LEN bytes.
 * @cipher: AEAD suite.
 * @egress: egress policy for the OUTBOUND (server) connection (may be NULL).
 *
 * Registers a tunnel client: dial @server, run the NoisePSK_NN initiator
 * handshake, then relay the decrypted stream to @target. Returns 0 on success.
 */
int portmux_add_tunnel_client (Portmux *self,
                               const char *listen_addr, int listen_port,
                               const char *server_addr, int server_port,
                               const char *target_addr, int target_port,
                               const unsigned char psk[PM_TUNNEL_PSK_LEN],
                               PmTunnelCipher cipher,
                               const PortmuxEgress *egress);

/**
 * portmux_add_tunnel_server:
 * @self: a #Portmux
 * @listen_addr/@listen_port: where CLIENTS connect (the encrypted Noise side).
 * @bridge_addr/@bridge_port: the plaintext local port a laptop's `adb connect`
 *   (or any client) uses; accepted connections are relayed into the tunnel.
 * @psk: PM_TUNNEL_PSK_LEN bytes (must match the client).
 * @cipher: AEAD suite (must match the client in v1).
 *
 * Registers a tunnel server: accept an encrypted client, run the responder
 * handshake, and bridge laptop<->client. Returns 0 on success.
 */
int portmux_add_tunnel_server (Portmux *self,
                               const char *listen_addr, int listen_port,
                               const char *bridge_addr, int bridge_port,
                               const unsigned char psk[PM_TUNNEL_PSK_LEN],
                               PmTunnelCipher cipher);

#ifdef __cplusplus
}
#endif

#endif /* __PORTMUX_TUNNEL_H__ */
