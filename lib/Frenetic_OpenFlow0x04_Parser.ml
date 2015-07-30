open Core.Std
open Printf
open Cstruct
open Cstruct.BE
open Frenetic_Packet
open Frenetic_OpenFlow0x04


type uint48 = uint64
type uint24 = int32
type uint128 = int64 * int64

let val_to_mask v =
  { m_value = v; m_mask = None }

let ip_to_mask (p,m) =
  if m = 32l then { m_value = p; m_mask = None }
  else
    let m = Int32.shift_left 0xffffffffl (Int32.to_int_exn (Int32.(32l - m))) in
    { m_value = p; m_mask = Some m }

exception Unparsable of string
let sym_num = ref 0

let sum (lst : int list) = List.fold_left ~f:(fun x y -> x + y) ~init:0 lst

    (* OKAY *)
    cenum msg_code {
    HELLO;
    ERROR;
    ECHO_REQ;
    ECHO_RESP;
    VENDOR;
    FEATURES_REQ;
    FEATURES_RESP;
    GET_CONFIG_REQ;
    GET_CONFIG_RESP;
    SET_CONFIG;
    PACKET_IN;
    FLOW_REMOVED;
    PORT_STATUS;
    PACKET_OUT;
    FLOW_MOD;
    GROUP_MOD;
    PORT_MOD;
    TABLE_MOD;
    MULTIPART_REQ;
    MULTIPART_RESP;
    BARRIER_REQ;
    BARRIER_RESP;
    QUEUE_GET_CONFIG_REQ;
    QUEUE_GET_CONFIG_RESP;
    ROLE_REQ;
    ROLE_RESP;
    GET_ASYNC_REQ;
    GET_ASYNC_REP;
    SET_ASYNC;
    METER_MOD
  } as uint8_t

  cstruct ofp_match {
    uint16_t typ;
    uint16_t length
  } as big_endian

let ofpp_in_port = 0xfffffff8l
let ofpp_flood = 0xfffffffbl
let ofpp_all = 0xfffffffcl
let ofpp_controller = 0xfffffffdl
let ofpp_any = 0xffffffffl

let ofp_no_buffer = 0xffffffffl

(* Not in the spec, comes from C headers. :rolleyes: *)
let ofpg_all = 0xfffffffcl
let ofpg_any = 0xffffffffl
let ofp_eth_alen = 6          (* Bytes in an Ethernet address. *)

    (* OKAY *)
    cenum ofp_oxm_class {
    OFPXMC_NXM_0          = 0x0000;    (* Backward compatibility with NXM *)
    OFPXMC_NXM_1          = 0x0001;    (* Backward compatibility with NXM *)
    OFPXMC_OPENFLOW_BASIC = 0x8000;    (* Basic class for OpenFlow *)
    OFPXMC_EXPERIMENTER   = 0xFFFF     (* Experimenter class *)
  } as uint16_t

  (* OKAY *)
  cenum oxm_ofb_match_fields {
    OFPXMT_OFB_IN_PORT        = 0;  (* Switch input port. *)
    OFPXMT_OFB_IN_PHY_PORT    = 1;  (* Switch physical input port. *)
    OFPXMT_OFB_METADATA       = 2;  (* Metadata passed between tables. *)
    OFPXMT_OFB_ETH_DST        = 3;  (* Ethernet destination address. *)
    OFPXMT_OFB_ETH_SRC        = 4;  (* Ethernet source address. *)
    OFPXMT_OFB_ETH_TYPE       = 5;  (* Ethernet frame type. *)
    OFPXMT_OFB_VLAN_VID       = 6;  (* VLAN id. *)
    OFPXMT_OFB_VLAN_PCP       = 7;  (* VLAN priority. *)
    OFPXMT_OFB_IP_DSCP        = 8;  (* IP DSCP (6 bits in ToS field). *)
    OFPXMT_OFB_IP_ECN         = 9;  (* IP ECN (2 bits in ToS field). *)
    OFPXMT_OFB_IP_PROTO       = 10; (* IP protocol. *)
    OFPXMT_OFB_IPV4_SRC       = 11; (* IPv4 source address. *)
    OFPXMT_OFB_IPV4_DST       = 12; (* IPv4 destination address. *)
    OFPXMT_OFB_TCP_SRC        = 13; (* TCP source port. *)
    OFPXMT_OFB_TCP_DST        = 14; (* TCP destination port. *)
    OFPXMT_OFB_UDP_SRC        = 15; (* UDP source port. *)
    OFPXMT_OFB_UDP_DST        = 16; (* UDP destination port. *)
    OFPXMT_OFB_SCTP_SRC       = 17; (* SCTP source port. *)
    OFPXMT_OFB_SCTP_DST       = 18; (* SCTP destination port. *)
    OFPXMT_OFB_ICMPV4_TYPE    = 19; (* ICMP type. *)
    OFPXMT_OFB_ICMPV4_CODE    = 20; (* ICMP code. *)
    OFPXMT_OFB_ARP_OP         = 21; (* ARP opcode. *)
    OFPXMT_OFB_ARP_SPA        = 22; (* ARP source IPv4 address. *)
    OFPXMT_OFB_ARP_TPA        = 23; (* ARP target IPv4 address. *)
    OFPXMT_OFB_ARP_SHA        = 24; (* ARP source hardware address. *)
    OFPXMT_OFB_ARP_THA        = 25; (* ARP target hardware address. *)
    OFPXMT_OFB_IPV6_SRC       = 26; (* IPv6 source address. *)
    OFPXMT_OFB_IPV6_DST       = 27; (* IPv6 destination address. *)
    OFPXMT_OFB_IPV6_FLABEL    = 28; (* IPv6 Flow Label *)
    OFPXMT_OFB_ICMPV6_TYPE    = 29; (* ICMPv6 type. *)
    OFPXMT_OFB_ICMPV6_CODE    = 30; (* ICMPv6 code. *)
    OFPXMT_OFB_IPV6_ND_TARGET = 31; (* Target address for ND. *)
    OFPXMT_OFB_IPV6_ND_SLL    = 32; (* Source link-layer for ND. *)
    OFPXMT_OFB_IPV6_ND_TLL    = 33; (* Target link-layer for ND. *)
    OFPXMT_OFB_MPLS_LABEL     = 34; (* MPLS label. *)
    OFPXMT_OFB_MPLS_TC        = 35; (* MPLS TC. *)
    OFPXMT_OFP_MPLS_BOS       = 36; (* MPLS BoS bit. *)
    OFPXMT_OFB_PBB_ISID       = 37; (* PBB I-SID. *)
    OFPXMT_OFB_TUNNEL_ID      = 38; (* Logical Port Metadata. *)
    OFPXMT_OFB_IPV6_EXTHDR    = 39  (* IPv6 Extension Header pseudo-field *)
  } as uint8_t

  cenum ofp_vlan_id {
    OFPVID_PRESENT = 0x1000; (* Bit that indicate that a VLAN id is set *)
    OFPVID_NONE    = 0x0000  (* No VLAN id was set. *)
  } as uint16_t

  cstruct ofp_switch_features {
    uint64_t datapath_id;
    uint32_t n_buffers;
    uint8_t n_tables;
    uint8_t auxiliary_id;
    uint8_t pad0;
    uint8_t pad1;
    uint32_t capabilities;
    uint32_t reserved
  } as big_endian

module PortConfig = struct

  type t = portConfig

  let config_to_int (config : t) : int32 =
    Int32.bit_or (if config.port_down then (Int32.shift_left 1l 0) else 0l)
      (Int32.bit_or (if config.no_recv then (Int32.shift_left 1l 2) else 0l)
         (Int32.bit_or (if config.no_fwd then (Int32.shift_left 1l 5) else 0l)
            (if config.no_packet_in then (Int32.shift_left 1l 6) else 0l)))

  let marshal (pc : t) : int32 = config_to_int pc


  let parse bits : t =
    { port_down     = Frenetic_Bits.test_bit 0 bits;
      no_recv       = Frenetic_Bits.test_bit 2 bits;
      no_fwd        = Frenetic_Bits.test_bit 5 bits;
      no_packet_in  = Frenetic_Bits.test_bit 6 bits
    }

end

module PortFeatures = struct

  type t = portFeatures

  let marshal (t : t) : int32 =
    Int32.bit_or (if t.rate_10mb_hd then (Int32.shift_left 1l 0) else 0l)
      (Int32.bit_or (if t.rate_10mb_fd then (Int32.shift_left 1l 1) else 0l)
         (Int32.bit_or (if t.rate_100mb_hd then (Int32.shift_left 1l 2) else 0l)
            (Int32.bit_or (if t.rate_100mb_fd then (Int32.shift_left 1l 3) else 0l)
               (Int32.bit_or (if t.rate_1gb_hd then (Int32.shift_left 1l 4) else 0l)
                  (Int32.bit_or (if t.rate_1gb_fd then (Int32.shift_left 1l 5) else 0l)
                     (Int32.bit_or (if t.rate_10gb_fd then (Int32.shift_left 1l 6) else 0l)
                        (Int32.bit_or (if t.rate_40gb_fd then (Int32.shift_left 1l 7) else 0l)
                           (Int32.bit_or (if t.rate_100gb_fd then (Int32.shift_left 1l 8) else 0l)
                              (Int32.bit_or (if t.rate_1tb_fd then (Int32.shift_left 1l 9) else 0l)
                                 (Int32.bit_or (if t.other then (Int32.shift_left 1l 10) else 0l)
                                    (Int32.bit_or (if t.copper then (Int32.shift_left 1l 11) else 0l)
                                       (Int32.bit_or (if t.fiber then (Int32.shift_left 1l 12) else 0l)
                                          (Int32.bit_or (if t.autoneg then (Int32.shift_left 1l 13) else 0l)
                                             (Int32.bit_or (if t.pause then (Int32.shift_left 1l 14) else 0l)
                                                (if t.pause_asym then (Int32.shift_left 1l 15) else 0l)))))))))))))))

  let parse (bits : int32) : t =
    { rate_10mb_hd  = Frenetic_Bits.test_bit 0 bits;
      rate_10mb_fd  = Frenetic_Bits.test_bit 1 bits;
      rate_100mb_hd = Frenetic_Bits.test_bit 2 bits;
      rate_100mb_fd = Frenetic_Bits.test_bit 3 bits;
      rate_1gb_hd   = Frenetic_Bits.test_bit 4 bits;
      rate_1gb_fd   = Frenetic_Bits.test_bit 5 bits;
      rate_10gb_fd  = Frenetic_Bits.test_bit 6 bits;
      rate_40gb_fd  = Frenetic_Bits.test_bit 7 bits;
      rate_100gb_fd = Frenetic_Bits.test_bit 8 bits;
      rate_1tb_fd   = Frenetic_Bits.test_bit 9 bits;
      other         = Frenetic_Bits.test_bit 10 bits;
      copper        = Frenetic_Bits.test_bit 11 bits;
      fiber         = Frenetic_Bits.test_bit 12 bits;
      autoneg       = Frenetic_Bits.test_bit 13 bits;
      pause         = Frenetic_Bits.test_bit 14 bits;
      pause_asym    = Frenetic_Bits.test_bit 15 bits
    }

end

module PortState = struct

  type t = portState

  let state_to_int (state : t) : int32 =
    Int32.bit_or (if state.link_down then (Int32.shift_left 1l 0) else 0l)
      (Int32.bit_or (if state.blocked then (Int32.shift_left 1l 1) else 0l)
         (if state.live then (Int32.shift_left 1l 2) else 0l))

  let marshal (ps : t) : int32 = state_to_int ps

  let parse bits : t =
    { link_down = Frenetic_Bits.test_bit 0 bits;
      blocked = Frenetic_Bits.test_bit 1 bits;
      live = Frenetic_Bits.test_bit 2 bits
    }

end

  cstruct ofp_port_stats_request {
  uint32_t port_no;
  uint8_t pad[4]
} as big_endian

cstruct ofp_queue_stats_request {
  uint32_t port_no;
  uint32_t queue_id
} as big_endian

cstruct ofp_group_stats_request {
  uint32_t group_id;
  uint8_t pad[4]
} as big_endian

cstruct ofp_meter_multipart_request {
  uint32_t meter_id;
  uint8_t pad[4]
} as big_endian

cstruct ofp_table_features {
  uint16_t length;
  uint8_t table_id;
  uint8_t pad[5];
  uint8_t name[32];
  uint64_t metadata_match;
  uint64_t metadata_write;
  uint32_t config;
  uint32_t max_entries
} as big_endian

(* Body of reply to OFPMP_PORT request. If a counter is unsupported, set
 * the field to all ones. *)
cstruct ofp_port_stats {
  uint32_t port_no;
  uint8_t pad[4]; (* Align to 64-bits. *)
  uint64_t rx_packets; (* Number of received packets. *)
  uint64_t tx_packets; (* Number of transmitted packets. *)
  uint64_t rx_bytes; (* Number of received bytes. *)
  uint64_t tx_bytes; (* Number of transmitted bytes. *)
  uint64_t rx_dropped; (* Number of packets dropped by RX. *)
  uint64_t tx_dropped; (* Number of packets dropped by TX. *)
  uint64_t rx_errors; (* Number of receive errors. This is a super-set
                               of more specific receive errors and should be
                               greater than or equal to the sum of all
                               rx_*_err values. *)
  uint64_t tx_errors; (* Number of transmit errors. This is a super-set
                               of more specific transmit errors and should be
                               greater than or equal to the sum of all
                               tx_*_err values (none currently defined.) *)
  uint64_t rx_frame_err; (* Number of frame alignment errors. *)
  uint64_t rx_over_err; (* Number of packets with RX overrun. *)
  uint64_t rx_crc_err; (* Number of CRC errors. *)
  uint64_t collisions; (* Number of collisions. *)
  uint32_t duration_sec; (* Time port has been alive in seconds. *)
  uint32_t duration_nsec (* Time port has been alive in nanoseconds beyond
                                       duration_sec. *)
} as big_endian

cstruct ofp_port {
  uint32_t port_no;
  uint32_t pad;
  uint8_t hw_addr[6];
  uint8_t pad2;
  uint8_t pad3;
  uint8_t name[16]; (* OFP_MAX_PORT_NAME_LEN, Null-terminated *)
  uint32_t config; (* Bitmap of OFPPC_* flags. *)
  uint32_t state; (* Bitmap of OFPPS_* flags. *)
  (* Bitmaps of OFPPF_* that describe features. All bits zeroed if
   * unsupported or unavailable. *)
  uint32_t curr; (* Current features. *)
  uint32_t advertised; (* Features being advertised by the port. *)
  uint32_t supported; (* Features supported by the port. *)
  uint32_t peer; (* Features advertised by peer. *)
  uint32_t curr_speed; (* Current port bitrate in kbps. *)
  uint32_t max_speed (* Max port bitrate in kbps *)
} as big_endian

cenum ofp_port_reason {
  OFPPR_ADD;
  OFPPR_DELETE;
  OFPPR_MODIFY
} as uint8_t

cstruct ofp_port_status {
  uint8_t reason;               (* One of OFPPR_* *)
  uint8_t pad[7]
} as big_endian

cenum ofp_table_config {
  OFPTC_DEPRECATED_MASK = 0x00000003l (* currently deprecated *)
} as uint32_t

cenum ofp_table_feature_prop_type {
  OFPTFPT_INSTRUCTIONS       = 0;
  OFPTFPT_INSTRUCTIONS_MISS  = 1;
  OFPTFPT_NEXT_TABLES        = 2;
  OFPTFPT_NEXT_TABLES_MISS   = 3;
  OFPTFPT_WRITE_ACTIONS      = 4;
  OFPTFPT_WRITE_ACTIONS_MISS  = 5;
  OFPTFPT_APPLY_ACTIONS       = 6;
  OFPTFPT_APPLY_ACTIONS_MISS  = 7;
  OFPTFPT_MATCH               = 8;
  OFPTFPT_WILDCARDS           = 10;
  OFPTFPT_WRITE_SETFIELD      = 12;
  OFPTFPT_WRITE_SETFIELD_MISS = 13;
  OFPTFPT_APPLY_SETFIELD      = 14;
  OFPTFPT_APPLY_SETFIELD_MISS = 15;
  OFPTFPT_EXPERIMENTER        = 0xFFFE;
  OFPTFPT_EXPERIMENTER_MISS   = 0xFFFF
} as uint16_t

cstruct ofp_table_feature_prop_header {
  uint16_t typ;
  uint16_t length
} as big_endian

cenum ofp_flow_mod_command {
  OFPFC_ADD            = 0; (* New flow. *)
  OFPFC_MODIFY         = 1; (* Modify all matching flows. *)
  OFPFC_MODIFY_STRICT  = 2; (* Modify entry strictly matching wildcards and
                               priority. *)
  OFPFC_DELETE         = 3; (* Delete all matching flows. *)
  OFPFC_DELETE_STRICT  = 4  (* Delete entry strictly matching wildcards and
                               priority. *)
} as uint8_t

cstruct ofp_flow_mod {
  uint64_t cookie;             (* Opaque controller-issued identifier. *)
  uint64_t cookie_mask;        (* Mask used to restrict the cookie bits
                                  that must match when the command is
                                  OFPFC_MODIFY* or OFPFC_DELETE*. A value
                                  of 0 indicates no restriction. *)

  (* Flow actions. *)
  uint8_t table_id;             (* ID of the table to put the flow in.
                                   For OFPFC_DELETE_* commands, OFPTT_ALL
                                   can also be used to delete matching
                                   flows from all tables. *)
  uint8_t command;              (* One of OFPFC_*. *)
  uint16_t idle_timeout;        (* Idle time before discarding (seconds). *)
  uint16_t hard_timeout;        (* Max time before discarding (seconds). *)
  uint16_t priority;            (* Priority level of flow entry. *)
  uint32_t buffer_id;           (* Buffered packet to apply to, or
                                   OFP_NO_BUFFER.
                                   Not meaningful for OFPFC_DELETE*. *)
  uint32_t out_port;            (* For OFPFC_DELETE* commands, require
                                   matching entries to include this as an
                                   output port.  A value of OFPP_ANY
                                   indicates no restriction. *)
  uint32_t out_group;           (* For OFPFC_DELETE* commands, require
                                   matching entries to include this as an
                                   output group.  A value of OFPG_ANY
                                   indicates no restriction. *)
  uint16_t flags;               (* One of OFPFF_*. *)
  uint8_t pad0;
  uint8_t pad1
} as big_endian

(* OKAY *)
cenum ofp_action_type {
  OFPAT_OUTPUT       = 0;  (* Output to switch port. *)
  OFPAT_COPY_TTL_OUT = 11; (* Copy TTL "outwards" -- from next-to-outermost
                              to outermost *)
  OFPAT_COPY_TTL_IN  = 12; (* Copy TTL "inwards" -- from outermost to
                              next-to-outermost *)
  OFPAT_SET_MPLS_TTL = 15; (* MPLS TTL *)
  OFPAT_DEC_MPLS_TTL = 16; (* Decrement MPLS TTL *)

  OFPAT_PUSH_VLAN    = 17; (* Push a new VLAN tag *)
  OFPAT_POP_VLAN     = 18; (* Pop the outer VLAN tag *)
  OFPAT_PUSH_MPLS    = 19; (* Push a new MPLS tag *)
  OFPAT_POP_MPLS     = 20; (* Pop the outer MPLS tag *)
  OFPAT_SET_QUEUE    = 21; (* Set queue id when outputting to a port *)
  OFPAT_GROUP        = 22; (* Apply group. *)
  OFPAT_SET_NW_TTL   = 23; (* IP TTL. *)
  OFPAT_DEC_NW_TTL   = 24; (* Decrement IP TTL. *)
  OFPAT_SET_FIELD    = 25; (* Set a header field using OXM TLV format. *)
  OFPAT_PUSH_PBB     = 26; (* Push a new PBB service tag (I-TAG) *)
  OFPAT_POP_PBB      = 27; (* Pop the outer PBB service tag (I-TAG) *)
  OFPAT_EXPERIMENTER = 0xffff
} as uint16_t

(* Action structure for OFPAT_OUTPUT, which sends packets out 'port'.
 * When the 'port' is the OFPP_CONTROLLER, 'max_len' indicates the max
 * number of bytes to send.  A 'max_len' of zero means no bytes of the
 * packet should be sent. A 'max_len' of OFPCML_NO_BUFFER means that
 * the packet is not buffered and the complete packet is to be sent to
 * the controller. *)
cstruct ofp_action_output {
  uint16_t typ;                   (* OFPAT_OUTPUT. *)
  uint16_t len;                   (* Length is 16. *)
  uint32_t port;                  (* Output port. *)
  uint16_t max_len;               (* Max length to send to controller. *)
  uint8_t pad0;                   (* Pad to 64 bits. *)
  uint8_t pad1;                   (* Pad to 64 bits. *)
  uint8_t pad2;                   (* Pad to 64 bits. *)
  uint8_t pad3;                   (* Pad to 64 bits. *)
  uint8_t pad4;                   (* Pad to 64 bits. *)
  uint8_t pad5                    (* Pad to 64 bits. *)
} as big_endian

(* Action structure for OFPAT_GROUP. *)
cstruct ofp_action_group {
  uint16_t typ;                   (* OFPAT_GROUP. *)
  uint16_t len;                   (* Length is 8. *)
  uint32_t group_id               (* Group identifier. *)
} as big_endian

(* Generic action header. Used for POP_VLAN *)
cstruct ofp_action_header {
  uint16_t typ;                   (* POP_VLAN. *)
  uint16_t len;                   (* Length is 8. *)
  uint8_t pad;
  uint8_t pad1;
  uint8_t pad2;
  uint8_t pad3
} as big_endian

(* Action structure for POP_MPLS *)
cstruct ofp_action_pop_mpls {
  uint16_t typ;                   (* POP_VLAN. *)
  uint16_t len;                   (* Length is 8. *)
  uint16_t ethertype;
  uint8_t pad0;                   (* Pad to 64 bits. *)
  uint8_t pad1                    (* Pad to 64 bits. *)
} as big_endian

(* Action structure for SET_NW_TTL *)
cstruct ofp_action_nw_ttl {
  uint16_t typ;                   (* SET_NW_TTL. *)
  uint16_t len;                   (* Length is 8. *)
  uint8_t nw_ttl;
  uint8_t pad;
  uint8_t pad1;
  uint8_t pad2
} as big_endian

(* Action structure for SET_MPLS_TTL *)
cstruct ofp_action_mpls_ttl {
  uint16_t typ;                   (* SET_MPLS_TTL. *)
  uint16_t len;                   (* Length is 8. *)
  uint8_t mpls_ttl;
  uint8_t pad[3];
} as big_endian

(* Action structure for *_PUSH *)
cstruct ofp_action_push {
  uint16_t typ;                   (* OFPAT_PUSH_VLAN/MPLS/PBB *)
  uint16_t len;                   (* Length is 8. *)
  uint16_t ethertype;             (* Pad to 64 bits. *)
  uint8_t pad0;                   (* Pad to 64 bits. *)
  uint8_t pad1                   (* Pad to 64 bits. *)
} as big_endian

(* Action structure for OFPAT_SET_FIELD. *)
cstruct ofp_action_set_field {
  uint16_t typ;                  (* OFPAT_SET_FIELD. *)
  uint16_t len                   (* Length is padded to 64 bits. *)
  (* Followed by:
   *   - Exactly oxm_len bytes containing a single OXM TLV, then
   *   - Exactly ((oxm_len + 4) + 7)/8*8 - (oxm_len + 4) (between 0 and 7)
   *     bytes of all-zero bytes
  *)
} as big_endian

(* Action structure for SET_QUEUE *)
cstruct ofp_action_set_queue {
  uint16_t typ;                   (* OFPAT_SET_QUEUE*)
  uint16_t len;                   (* Length is 8. *)
  uint32_t queue_id
} as big_endian

cstruct ofp_action_experimenter {
  uint16_t typ;
  uint16_t len;
  uint32_t experimenter
} as big_endian

(* Instruction header that is common to all instructions.  The length includes
 * the header and any padding used to make the instruction 64-bit aligned.
 * NB: The length of an instruction *must* always be a multiple of eight. *)
cstruct ofp_instruction {
  uint16_t typ;                 (* Instruction type *)
  uint16_t len                  (* Length of this struct in bytes. *)
} as big_endian

cenum ofp_instruction_type {
  OFPIT_GOTO_TABLE        = 1;
  OFPIT_WRITE_METADATA    = 2;
  OFPIT_WRITE_ACTIONS     = 3;
  OFPIT_APPLY_ACTIONS     = 4;
  OFPIT_CLEAR_ACTIONS     = 5;
  OFPIT_METER             = 6;
  OFPIT_EXPERIMENTER      = 0xFFFF;
} as uint16_t

(* Instruction structure for OFPIT_GOTO_TABLE *)
cstruct ofp_instruction_goto_table {
  uint16_t typ;                 (* OFPIT_GOTO_TABLE *)
  uint16_t len;                 (* Length of this struct in bytes. *)
  uint8_t table_id;             (* Set next table in the lookup pipeline *)
  uint8_t pad0;                 (* Pad to 64 bits. *)
  uint8_t pad1;
  uint8_t pad2
} as big_endian

(* Instruction structure for OFPIT_WRITE_METADATA *)
cstruct ofp_instruction_write_metadata {
  uint16_t typ;                 (* OFPIT_WRITE_METADATA *)
  uint16_t len;                 (* Length of this struct in bytes. *)
  uint8_t pad0;                 (* Align to 64-bits *)
  uint8_t pad1;
  uint8_t pad2;
  uint8_t pad3;
  uint64_t metadata;            (* Metadata value to write *)
  uint64_t metadata_mask        (* Metadata write bitmask *)
} as big_endian

(* Instruction structure for OFPIT_WRITE/APPLY/CLEAR_ACTIONS *)
cstruct ofp_instruction_actions {
  uint16_t typ;               (* One of OFPIT_*_ACTIONS *)
  uint16_t len;               (* Length of this struct in bytes. *)
  uint8_t pad0;               (* Align to 64-bits *)
  uint8_t pad1;
  uint8_t pad2;
  uint8_t pad3
} as big_endian

(* Instruction structure for OFPIT_METER *)
cstruct ofp_instruction_meter {
  uint16_t typ;                 (* OFPIT_METER *)
  uint16_t len;                 (* Length is 8. *)
  uint32_t meter_id             (* Meter instance. *)
} as big_endian

(* Instruction structure for experimental instructions *)
cstruct ofp_instruction_experimenter {
  uint16_t typ;               (* OFPIT_EXPERIMENTER *)
  uint16_t len;               (* Length of this struct in bytes *)
  uint32_t experimenter       (* Experimenter ID which takes the same form
                                 as in struct ofp_experimenter_header. *)
  (* Experimenter-defined arbitrary additional data. *)
} as big_endian


cenum ofp_group_type {
  OFPGT_ALL = 0; (* All (multicast/broadcast) group. *)
  OFPGT_SELECT = 1; (* Select group. *)
  OFPGT_INDIRECT = 2; (* Indirect group. *)
  OFPGT_FF = 3 (* Fast failover group. *)
} as uint16_t

(* Group setup and teardown (controller -> datapath). *)
cstruct ofp_group_mod {
  uint16_t command;             (* One of OFPGC_*. *)
  uint8_t typ;                 (* One of OFPGT_*. *)
  uint8_t pad;                  (* Pad to 64 bits. *)
  uint32_t group_id            (* Group identifier. *)
} as big_endian

(* Bucket for use in groups. *)
cstruct ofp_bucket {
  uint16_t len;                   (* Length the bucket in bytes, including
                                     this header and any padding to make it
                                     64-bit aligned. *)
  uint16_t weight;                (* Relative weight of bucket.  Only
                                     defined for select groups. *)
  uint32_t watch_port;            (* Port whose state affects whether this
                                     bucket is live.  Only required for fast
                                     failover groups. *)
  uint32_t watch_group;           (* Group whose state affects whether this
                                     bucket is live.  Only required for fast
                                     failover groups. *)
  uint8_t pad0;
  uint8_t pad1;
  uint8_t pad2;
  uint8_t pad3
} as big_endian

cstruct ofp_oxm {
  uint16_t oxm_class;
  uint8_t oxm_field_and_hashmask;
  uint8_t oxm_length
} as big_endian


cstruct ofp_meter_band_header {
  uint16_t typ;
  uint16_t len;
  uint32_t rate;
  uint32_t burst_size
} as big_endian

cstruct ofp_meter_band_drop {
  uint16_t typ;
  uint16_t len;
  uint32_t rate;
  uint32_t burst_size;
  uint8_t pad[4]
} as big_endian

cstruct ofp_meter_band_dscp_remark {
  uint16_t typ;
  uint16_t len;
  uint32_t rate;
  uint32_t burst_size;
  uint8_t prec_level;
  uint8_t pad[3]
} as big_endian

cstruct ofp_meter_band_experimenter {
  uint16_t typ;
  uint16_t len;
  uint32_t rate;
  uint32_t burst_size;
  uint32_t experimenter
} as big_endian

cenum ofp_meter_flags {
  OFPMF_KBPS = 1;
  OFPMF_PKTPS = 2;
  OFPMF_BURST = 4;
  OFPMF_STATS = 8;
} as uint32_t

cstruct ofp_multipart_request {
  uint16_t typ;   (* One of the OFPMP_* constants. *)
  uint16_t flags;  (* OFPMP_REQ_* flags (none yet defined). *)
  uint8_t pad[4];
  uint8_t body[0] (* Body of the request. *)
} as big_endian

cenum ofp_multipart_request_flags {
  OFPMPF_REQ_MORE = 1 (* More requests to follow. *)
} as uint16_t

cenum ofp_multipart_reply_flags {
  OFPMPF_REPLY_MORE  = 1  (* More replies to follow. *)
} as uint16_t

cstruct ofp_multipart_reply {
  uint16_t typ;   (* One of the OFPMP_* constants. *)
  uint16_t flags;  (* OFPMP_REPLY_* flags. *)
  uint8_t pad[4];
  uint8_t body[0] (* Body of the reply. *)
} as big_endian

cenum ofp_multipart_types {
  (* Description of this OpenFlow switch.
   * The request body is empty.
   * The reply body is struct ofp_desc. *)
  OFPMP_DESC = 0;
  (* Individual flow statistics.
   * The request body is struct ofp_flow_multipart_request.
   * The reply body is an array of struct ofp_flow_stats. *)
  OFPMP_FLOW = 1;
  (* Aggregate flow statistics.
   * The request body is struct ofp_aggregate_stats_request.
   * The reply body is struct ofp_aggregate_stats_reply. *)
  OFPMP_AGGREGATE = 2;
  (* Flow table statistics.
   * The request body is empty.
   * The reply body is an array of struct ofp_table_stats. *)
  OFPMP_TABLE = 3;
  (* Port statistics.
   * The request body is struct ofp_port_stats_request.
   * The reply body is an array of struct ofp_port_stats. *)
  OFPMP_PORT_STATS = 4;
  (* Queue statistics for a port
   * The request body is struct ofp_queue_stats_request.
   * The reply body is an array of struct ofp_queue_stats *)
  OFPMP_QUEUE = 5;
  (* Group counter statistics.
   * The request body is struct ofp_group_stats_request.
   * The reply is an array of struct ofp_group_stats. *)
  OFPMP_GROUP = 6;
  (* Group description statistics.
   * The request body is empty.
   * The reply body is an array of struct ofp_group_desc_stats. *)
  OFPMP_GROUP_DESC = 7;
  (* Group features.
   * The request body is empty.
   * The reply body is struct ofp_group_features_stats. *)
  OFPMP_GROUP_FEATURES = 8;
  (* Meter statistics.
   * The request body is struct ofp_meter_multipart_requests.
   * The reply body is an array of struct ofp_meter_stats. *)
  OFPMP_METER = 9;
  (* Meter configuration.
   * The request body is struct ofp_meter_multipart_requests.
   * The reply body is an array of struct ofp_meter_config. *)
  OFPMP_METER_CONFIG = 10;
  (* Meter features.
   * The request body is empty.
   * The reply body is struct ofp_meter_features. *)
  OFPMP_METER_FEATURES = 11;
  (* Table features.
   * The request body is either empty or contains an array of
   * struct ofp_table_features containing the controller’s
   * desired view of the switch. If the switch is unable to
   * set the specified view an error is returned.
   * The reply body is an array of struct ofp_table_features. *)
  OFPMP_TABLE_FEATURES = 12;
  (* Port description.
   * The request body is empty.
   * The reply body is an array of struct ofp_port. *)
  OFPMP_PORT_DESC = 13;
  (* Experimenter extension.
   * The request and reply bodies begin with
   * struct ofp_experimenter_stats_header.
   * The request and reply bodies are otherwise experimenter-defined. *)
  OFPMP_EXPERIMENTER = 0xffff
} as uint16_t

cstruct ofp_desc {
  uint8_t mfr_desc[256];
  uint8_t hw_desc[256];
  uint8_t sw_desc[256];
  uint8_t serial_num[32];
} as big_endian

cstruct ofp_uint8 {
  uint8_t value
} as big_endian

cstruct ofp_uint16 {
  uint16_t value
} as big_endian

cstruct ofp_uint24 {
  uint16_t high;
  uint8_t low
} as big_endian

cstruct ofp_uint32 {
  uint32_t value
} as big_endian

cstruct ofp_uint48 {
  uint32_t high;
  uint16_t low
} as big_endian

cstruct ofp_uint64 {
  uint64_t value
} as big_endian

cstruct ofp_uint128 {
  uint64_t high;
  uint64_t low
} as big_endian

(* TODO(arjun): WTF *)
let max_uint32 = 4294967296L (* = 2^32*)

(* TODO(arjun): WTF *)
let compare_uint32 a b =
  (* val compare_uint32 : uint32 -> uint32 -> bool ; return a < b, for a, b uint32  *)
  let a' = if a < 0l then
      Int64.(max_uint32 - (of_int32_exn (Int32.abs a)))
    else Int64.of_int32 a in
  let b' = if b < 0l then
      Int64.(max_uint32 - (of_int32_exn (Int32.abs b)))
    else Int64.of_int32 b in
  a' <= b'

let set_ofp_uint48_value (buf : Cstruct.t) (value : uint48) =
  let high = Int64.(to_int32_exn (shift_right_logical value 16)) in
  let low = Int64.to_int_exn value land 0xffff in
  set_ofp_uint48_high buf high;
  set_ofp_uint48_low buf low

let get_ofp_uint48_value (buf : Cstruct.t) : uint48 =
  let highBits = get_ofp_uint48_high buf in
  let high =
    if highBits < 0l then
      Int64.(max_uint32 - of_int32 (Int32.abs highBits))
    else
      Int64.(of_int32 highBits) in
  let high = Int64.shift_left high 16 in
  let low = Int64.of_int_exn (get_ofp_uint48_low buf) in
  Int64.bit_or low high

let get_ofp_uint24_value (buf : Cstruct.t) : uint24 =
  let high = Int32.(shift_left (of_int_exn (get_ofp_uint24_high buf)) 8) in
  let low = Int32.of_int_exn (get_ofp_uint24_low buf) in
  Int32.bit_or high low

let set_ofp_uint24_value (buf : Cstruct.t) (value : uint24) =
  let high = (Int32.to_int_exn value) lsr 8 in
  let low = (Int32.to_int_exn value) land 0xff in
  set_ofp_uint24_high buf high;
  set_ofp_uint24_low buf low

let set_ofp_uint128_value (buf : Cstruct.t) ((h,l) : uint128) =
  set_ofp_uint128_high buf h;
  set_ofp_uint128_low buf l

let get_ofp_uint128_value (buf : Cstruct.t) : uint128 =
  (get_ofp_uint128_high buf, get_ofp_uint128_low buf)

(* TODO(arjun): WTF use pattern-matching *)
let rec marshal_fields (buf: Cstruct.t) (fields : 'a list) (marshal_func : Cstruct.t -> 'a -> int ): int =
  if (fields = []) then 0
  else let size = marshal_func buf (List.hd_exn fields) in
    size + (marshal_fields (Cstruct.shift buf size) (List.tl_exn fields) marshal_func)

let parse_fields (bits : Cstruct.t) (parse_func : Cstruct.t -> 'a) (length_func : Cstruct.t -> int option) :'a list =
  let iter =
    Cstruct.iter
      length_func
      parse_func
      bits in
  List.rev (Cstruct.fold (fun acc bits -> bits :: acc) iter [])

let pad_to_64bits (n : int) : int =
  if n land 0x7 <> 0 then
    n + (8 - (n land 0x7))
  else
    n

let rec pad_with_zeros (buf : Cstruct.t) (pad : int) : int =
  if pad = 0 then 0
  else begin set_ofp_uint8_value buf 0;
    1 + pad_with_zeros (Cstruct.shift buf 1) (pad - 1) end

let test_bit16 (n:int) (x:int) : bool =
  (x lsr n) land 1 = 1

module Oxm = struct

  module IPv6ExtHdr = struct

    type t = oxmIPv6ExtHdr

    let marshal (hdr : t) : int16 =
      (if hdr.noext then 1 lsl 0 else 0) lor
      (if hdr.esp then 1 lsl 1 else 0) lor
      (if hdr.auth then 1 lsl 2 else 0) lor
      (if hdr.dest then 1 lsl 3 else 0) lor
      (if hdr.frac then 1 lsl 4 else 0) lor
      (if hdr.router then 1 lsl 5 else 0) lor
      (if hdr.hop then 1 lsl 6 else 0) lor
      (if hdr.unrep then 1 lsl 7 else 0) lor
      (if hdr.unseq then 1 lsl 8 else 0)

    let parse bits : t =
      { noext = test_bit16 0 bits
      ; esp = test_bit16 1 bits
      ; auth = test_bit16 2 bits
      ; dest = test_bit16 3 bits
      ; frac = test_bit16 4 bits
      ; router = test_bit16 5 bits
      ; hop = test_bit16 6 bits
      ; unrep = test_bit16 7 bits
      ; unseq = test_bit16 8 bits}

  end

  type t = oxm

  let field_length (oxm : oxm) : int = match oxm with
    | OxmInPort _ -> 4
    | OxmInPhyPort _ -> 4
    | OxmEthType  _ -> 2
    | OxmEthDst ethaddr ->
      (match ethaddr.m_mask with
       | None -> 6
       | Some _ -> 12)
    | OxmEthSrc ethaddr ->
      (match ethaddr.m_mask with
       | None -> 6
       | Some _ -> 12)
    | OxmVlanVId vid ->
      (match vid.m_mask with
       | None -> 2
       | Some _ -> 4)
    | OxmVlanPcp _ -> 1
    | OxmIP4Src ipaddr ->
      (match ipaddr.m_mask with
       | None -> 4
       | Some _ -> 8)
    | OxmIP4Dst ipaddr ->
      (match ipaddr.m_mask with
       | None -> 4
       | Some _ -> 8)
    | OxmTCPSrc _ -> 2
    | OxmTCPDst _ -> 2
    | OxmARPOp _ -> 2
    | OxmARPSpa t->
      (match t.m_mask with
       | None -> 4
       | Some _ -> 8)
    | OxmARPTpa t->
      (match t.m_mask with
       | None -> 4
       | Some _ -> 8)
    | OxmARPSha t->
      (match t.m_mask with
       | None -> 6
       | Some _ -> 12)
    | OxmARPTha t->
      (match t.m_mask with
       | None -> 6
       | Some _ -> 12)
    | OxmMPLSLabel _ -> 4
    | OxmMPLSTc _ -> 1
    | OxmMetadata t ->
      (match t.m_mask with
       | None -> 8
       | Some _ -> 16)
    | OxmIPProto _ -> 1
    | OxmIPDscp _ -> 1
    | OxmIPEcn _ -> 1
    | OxmICMPType _ -> 1
    | OxmICMPCode _ -> 1
    | OxmTunnelId t ->
      (match t.m_mask with
       | None -> 8
       | Some _ -> 16)
    | OxmUDPSrc _ -> 2
    | OxmUDPDst _ -> 2
    | OxmSCTPSrc _ -> 2
    | OxmSCTPDst _ -> 2
    | OxmIPv6Src t ->
      (match t.m_mask with
       | None -> 16
       | Some _ -> 32)
    | OxmIPv6Dst t ->
      (match t.m_mask with
       | None -> 16
       | Some _ -> 32)
    | OxmIPv6FLabel t ->
      (match t.m_mask with
       | None -> 4
       | Some _ -> 8)
    | OxmICMPv6Type _ -> 1
    | OxmICMPv6Code _ -> 1
    | OxmIPv6NDTarget t ->
      (match t.m_mask with
       | None -> 16
       | Some _ -> 32)
    | OxmIPv6NDSll _ -> 6
    | OxmIPv6NDTll _ -> 6
    | OxmMPLSBos _ -> 1
    | OxmPBBIsid t ->
      (match t.m_mask with
       | None -> 3
       | Some _ -> 6)
    | OxmIPv6ExtHdr t ->
      (match t.m_mask with
       | None -> 2
       | Some _ -> 4)

  let field_name (oxm : oxm) : string = match oxm with
    | OxmInPort _ -> "InPort"
    | OxmInPhyPort _ -> "InPhyPort"
    | OxmEthType  _ -> "EthType"
    | OxmEthDst ethaddr ->
      (match ethaddr.m_mask with
       | None -> "EthDst"
       | Some _ -> "EthDst/mask")
    | OxmEthSrc ethaddr ->
      (match ethaddr.m_mask with
       | None -> "EthSrc"
       | Some _ -> "EthSrc/mask")
    | OxmVlanVId vid ->
      (match vid.m_mask with
       | None -> "VlanVId"
       | Some _ -> "VlanVId/mask")
    | OxmVlanPcp _ -> "VlanPcp"
    | OxmIP4Src ipaddr ->
      (match ipaddr.m_mask with
       | None -> "IPSrc"
       | Some _ -> "IPSrc/mask")
    | OxmIP4Dst ipaddr ->
      (match ipaddr.m_mask with
       | None -> "IPDst"
       | Some _ -> "IPDst/mask")
    | OxmTCPSrc _ -> "TCPSrc"
    | OxmTCPDst _ -> "TCPDst"
    | OxmARPOp _ -> "ARPOp"
    | OxmARPSpa t->
      (match t.m_mask with
       | None -> "ARPSpa"
       | Some _ -> "ARPSpa/mask")
    | OxmARPTpa t->
      (match t.m_mask with
       | None -> "ARPTpa"
       | Some _ -> "ARPTpa/mask")
    | OxmARPSha t->
      (match t.m_mask with
       | None -> "ARPSha"
       | Some _ -> "ARPSha/mask")
    | OxmARPTha t->
      (match t.m_mask with
       | None -> "ARPTha"
       | Some _ -> "ARPTha/mask")
    | OxmMPLSLabel _ -> "MPLSLabel"
    | OxmMPLSTc _ -> "MplsTc"
    | OxmMetadata t ->
      (match t.m_mask with
       | None -> "Metadata"
       | Some _ -> "Metadata/mask")
    | OxmIPProto _ -> "IPProto"
    | OxmIPDscp _ -> "IPDscp"
    | OxmIPEcn _ -> "IPEcn"
    | OxmICMPType _ -> "ICMP Type"
    | OxmICMPCode _ -> "ICMP Code"
    | OxmTunnelId t ->
      (match t.m_mask with
       | None -> "Tunnel ID"
       | Some _ -> "Tunnel ID/mask")
    | OxmUDPSrc _ -> "UDPSrc"
    | OxmUDPDst _ -> "UDPDst"
    | OxmSCTPSrc _ -> "SCTPSrc"
    | OxmSCTPDst _ -> "SCTPDst"
    | OxmIPv6Src t ->
      (match t.m_mask with
       | None -> "IPv6Src"
       | Some _ -> "IPv6Src/mask")
    | OxmIPv6Dst t ->
      (match t.m_mask with
       | None -> "IPv6Dst"
       | Some _ -> "IPv6Dst/mask")
    | OxmIPv6FLabel t ->
      (match t.m_mask with
       | None -> "IPv6FlowLabel"
       | Some _ -> "IPv6FlowLabel/mask")
    | OxmICMPv6Type _ -> "ICMPv6Type"
    | OxmICMPv6Code _ -> "IPCMPv6Code"
    | OxmIPv6NDTarget t ->
      (match t.m_mask with
       | None -> "IPv6NeighborDiscoveryTarget"
       | Some _ -> "IPv6NeighborDiscoveryTarget/mask")
    | OxmIPv6NDSll _ -> "IPv6NeighborDiscoverySourceLink"
    | OxmIPv6NDTll _ -> "IPv6NeighborDiscoveryTargetLink"
    | OxmMPLSBos _ -> "MPLSBoS"
    | OxmPBBIsid t ->
      (match t.m_mask with
       | None -> "PBBIsid"
       | Some _ -> "PBBIsid/mask")
    | OxmIPv6ExtHdr t ->
      (match t.m_mask with
       | None -> "IPv6ExtHdr"
       | Some _ -> "IPv6ExtHdr/mask")

  let sizeof (oxm : oxm) : int =
    sizeof_ofp_oxm + field_length oxm

  let sizeof_header (oxml : oxm) : int =
    sizeof_ofp_oxm

  let set_ofp_oxm (buf : Cstruct.t) (c : ofp_oxm_class) (f : oxm_ofb_match_fields) (hm : int) (l : int) =
    let value = (0x7f land (oxm_ofb_match_fields_to_int f)) lsl 1 in
    let value = value lor (0x1 land hm) in
    set_ofp_oxm_oxm_class buf (ofp_oxm_class_to_int c);
    set_ofp_oxm_oxm_field_and_hashmask buf value;
    set_ofp_oxm_oxm_length buf l

  let marshal (buf : Cstruct.t) (oxm : oxm) : int =
    let l = field_length oxm in
    let ofc = OFPXMC_OPENFLOW_BASIC in
    let buf2 = Cstruct.shift buf sizeof_ofp_oxm in
    match oxm with
    | OxmInPort pid ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IN_PORT 0 l;
      set_ofp_uint32_value buf2 pid;
      sizeof_ofp_oxm + l
    | OxmInPhyPort pid ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IN_PHY_PORT 0 l;
      set_ofp_uint32_value buf2 pid;
      sizeof_ofp_oxm + l
    | OxmEthType ethtype ->
      set_ofp_oxm buf ofc OFPXMT_OFB_ETH_TYPE 0 l;
      set_ofp_uint16_value buf2 ethtype;
      sizeof_ofp_oxm + l
    | OxmEthDst ethaddr ->
      set_ofp_oxm buf ofc OFPXMT_OFB_ETH_DST (match ethaddr.m_mask with None -> 0 | _ -> 1) l;
      set_ofp_uint48_value buf2 ethaddr.m_value;
      begin match ethaddr.m_mask with
        | None ->
          sizeof_ofp_oxm + l
        | Some mask ->
          let buf3 = Cstruct.shift buf2 (l/2) in
          set_ofp_uint48_value buf3 mask;
          sizeof_ofp_oxm + l
      end
    | OxmEthSrc ethaddr ->
      set_ofp_oxm buf ofc OFPXMT_OFB_ETH_SRC (match ethaddr.m_mask with None -> 0 | _ -> 1) l;
      set_ofp_uint48_value buf2 ethaddr.m_value;
      begin match ethaddr.m_mask with
        | None ->
          sizeof_ofp_oxm + l
        | Some mask ->
          let buf3 = Cstruct.shift buf2 (l/2) in
          set_ofp_uint48_value buf3 mask;
          sizeof_ofp_oxm + l
      end
    | OxmIP4Src ipaddr ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IPV4_SRC (match ipaddr.m_mask with None -> 0 | _ -> 1) l;
      set_ofp_uint32_value buf2 ipaddr.m_value;
      begin match ipaddr.m_mask with
        | None ->
          sizeof_ofp_oxm + l
        | Some mask ->
          let buf3 = Cstruct.shift buf2 (l/2) in
          set_ofp_uint32_value buf3 mask;
          sizeof_ofp_oxm + l
      end
    | OxmIP4Dst ipaddr ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IPV4_DST (match ipaddr.m_mask with None -> 0 | _ -> 1) l;
      set_ofp_uint32_value buf2 ipaddr.m_value;
      begin match ipaddr.m_mask with
        | None ->
          sizeof_ofp_oxm + l
        | Some mask ->
          let buf3 = Cstruct.shift buf2 (l/2) in
          set_ofp_uint32_value buf3 mask;
          sizeof_ofp_oxm + l
      end
    | OxmVlanVId vid ->
      set_ofp_oxm buf ofc OFPXMT_OFB_VLAN_VID (match vid.m_mask with None -> 0 | _ -> 1) l;
      set_ofp_uint16_value buf2 vid.m_value;
      begin match vid.m_mask with
        | None ->
          sizeof_ofp_oxm + l
        | Some mask ->
          let buf3 = Cstruct.shift buf2 (l/2) in
          set_ofp_uint16_value buf3 mask;
          sizeof_ofp_oxm + l
      end
    | OxmVlanPcp vid ->
      set_ofp_oxm buf ofc OFPXMT_OFB_VLAN_PCP 0 l;
      set_ofp_uint8_value buf2 vid;
      sizeof_ofp_oxm + l
    | OxmMPLSLabel vid ->
      set_ofp_oxm buf ofc OFPXMT_OFB_MPLS_LABEL 0 l;
      set_ofp_uint32_value buf2 vid;
      sizeof_ofp_oxm + l
    | OxmMPLSTc vid ->
      set_ofp_oxm buf ofc OFPXMT_OFB_MPLS_TC 0 l;
      set_ofp_uint8_value buf2 vid;
      sizeof_ofp_oxm + l
    | OxmMetadata meta ->
      set_ofp_oxm buf ofc OFPXMT_OFB_METADATA  (match meta.m_mask with None -> 0 | _ -> 1)  l;
      set_ofp_uint64_value buf2 meta.m_value;
      begin match meta.m_mask with
        | None ->
          sizeof_ofp_oxm + l
        | Some mask ->
          let buf3 = Cstruct.shift buf2 (l/2) in
          set_ofp_uint64_value buf3 mask;
          sizeof_ofp_oxm + l
      end
    | OxmIPProto ipproto ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IP_PROTO 0 l;
      set_ofp_uint8_value buf2 ipproto;
      sizeof_ofp_oxm + l
    | OxmIPDscp ipdscp ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IP_DSCP 0 l;
      set_ofp_uint8_value buf2 ipdscp;
      sizeof_ofp_oxm + l
    | OxmIPEcn ipecn ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IP_ECN 0 l;
      set_ofp_uint8_value buf2 ipecn;
      sizeof_ofp_oxm + l
    | OxmTCPSrc port ->
      set_ofp_oxm buf ofc OFPXMT_OFB_TCP_SRC 0 l;
      set_ofp_uint16_value buf2 port;
      sizeof_ofp_oxm + l
    | OxmTCPDst port ->
      set_ofp_oxm buf ofc OFPXMT_OFB_TCP_DST 0 l;
      set_ofp_uint16_value buf2 port;
      sizeof_ofp_oxm + l
    | OxmARPOp arp ->
      set_ofp_oxm buf ofc OFPXMT_OFB_ARP_OP 0 l;
      set_ofp_uint16_value buf2 arp;
      sizeof_ofp_oxm + l
    | OxmARPSpa arp ->
      set_ofp_oxm buf ofc OFPXMT_OFB_ARP_SPA  (match arp.m_mask with None -> 0 | _ -> 1)  l;
      set_ofp_uint32_value buf2 arp.m_value;
      begin match arp.m_mask with
        | None ->
          sizeof_ofp_oxm + l
        | Some mask ->
          let buf3 = Cstruct.shift buf2 (l/2) in
          set_ofp_uint32_value buf3 mask;
          sizeof_ofp_oxm + l
      end
    | OxmARPTpa arp ->
      set_ofp_oxm buf ofc OFPXMT_OFB_ARP_TPA  (match arp.m_mask with None -> 0 | _ -> 1)  l;
      set_ofp_uint32_value buf2 arp.m_value;
      begin match arp.m_mask with
        | None ->
          sizeof_ofp_oxm + l
        | Some mask ->
          let buf3 = Cstruct.shift buf2 (l/2) in
          set_ofp_uint32_value buf3 mask;
          sizeof_ofp_oxm + l
      end
    | OxmARPSha arp ->
      set_ofp_oxm buf ofc OFPXMT_OFB_ARP_SHA  (match arp.m_mask with None -> 0 | _ -> 1)  l;
      set_ofp_uint48_value buf2 arp.m_value;
      begin match arp.m_mask with
        | None ->
          sizeof_ofp_oxm + l
        | Some mask ->
          let buf3 = Cstruct.shift buf2 (l/2) in
          set_ofp_uint48_value buf3 mask;
          sizeof_ofp_oxm + l
      end
    | OxmARPTha arp ->
      set_ofp_oxm buf ofc OFPXMT_OFB_ARP_THA  (match arp.m_mask with None -> 0 | _ -> 1)  l;
      set_ofp_uint48_value buf2 arp.m_value;
      begin match arp.m_mask with
        | None ->
          sizeof_ofp_oxm + l
        | Some mask ->
          let buf3 = Cstruct.shift buf2 (l/2) in
          set_ofp_uint48_value buf3 mask;
          sizeof_ofp_oxm + l
      end
    | OxmICMPType t ->
      set_ofp_oxm buf ofc OFPXMT_OFB_ICMPV4_TYPE 0 l;
      set_ofp_uint8_value buf2 t;
      sizeof_ofp_oxm + l
    | OxmICMPCode c->
      set_ofp_oxm buf ofc OFPXMT_OFB_ICMPV4_CODE 0 l;
      set_ofp_uint8_value buf2 c;
      sizeof_ofp_oxm + l
    | OxmTunnelId tun ->
      set_ofp_oxm buf ofc OFPXMT_OFB_TUNNEL_ID  (match tun.m_mask with None -> 0 | _ -> 1)  l;
      set_ofp_uint64_value buf2 tun.m_value;
      begin match tun.m_mask with
        | None ->
          sizeof_ofp_oxm + l
        | Some mask ->
          let buf3 = Cstruct.shift buf2 (l/2) in
          set_ofp_uint64_value buf3 mask;
          sizeof_ofp_oxm + l
      end
    | OxmUDPSrc port ->
      set_ofp_oxm buf ofc OFPXMT_OFB_UDP_SRC 0 l;
      set_ofp_uint16_value buf2 port;
      sizeof_ofp_oxm + l
    | OxmUDPDst port ->
      set_ofp_oxm buf ofc OFPXMT_OFB_UDP_DST 0 l;
      set_ofp_uint16_value buf2 port;
      sizeof_ofp_oxm + l
    | OxmSCTPSrc port ->
      set_ofp_oxm buf ofc OFPXMT_OFB_SCTP_SRC 0 l;
      set_ofp_uint16_value buf2 port;
      sizeof_ofp_oxm + l
    | OxmSCTPDst port ->
      set_ofp_oxm buf ofc OFPXMT_OFB_SCTP_DST 0 l;
      set_ofp_uint16_value buf2 port;
      sizeof_ofp_oxm + l
    | OxmIPv6Src addr ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_SRC (match addr.m_mask with None -> 0 | _ -> 1)  l;
      set_ofp_uint128_value buf2 addr.m_value;
      begin match addr.m_mask with
        | None ->
          sizeof_ofp_oxm + l
        | Some mask ->
          let buf3 = Cstruct.shift buf2 (l/2) in
          set_ofp_uint128_value buf3 mask;
          sizeof_ofp_oxm + l
      end
    | OxmIPv6Dst addr ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_DST (match addr.m_mask with None -> 0 | _ -> 1)  l;
      set_ofp_uint128_value buf2 addr.m_value;
      begin match addr.m_mask with
        | None ->
          sizeof_ofp_oxm + l
        | Some mask ->
          let buf3 = Cstruct.shift buf2 (l/2) in
          set_ofp_uint128_value buf3 mask;
          sizeof_ofp_oxm + l
      end
    | OxmIPv6FLabel label ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_FLABEL (match label.m_mask with None -> 0 | _ -> 1)  l;
      set_ofp_uint32_value buf2 label.m_value;
      begin match label.m_mask with
        | None ->
          sizeof_ofp_oxm + l
        | Some mask ->
          let buf3 = Cstruct.shift buf2 (l/2) in
          set_ofp_uint32_value buf3 mask;
          sizeof_ofp_oxm + l
      end
    | OxmICMPv6Type typ ->
      set_ofp_oxm buf ofc OFPXMT_OFB_ICMPV6_TYPE 0 l;
      set_ofp_uint8_value buf2 typ;
      sizeof_ofp_oxm + l
    | OxmICMPv6Code cod ->
      set_ofp_oxm buf ofc OFPXMT_OFB_ICMPV6_CODE 0 l;
      set_ofp_uint8_value buf2 cod;
      sizeof_ofp_oxm + l
    | OxmIPv6NDTarget addr ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_ND_TARGET (match addr.m_mask with None -> 0 | _ -> 1)  l;
      set_ofp_uint128_value buf2 addr.m_value;
      begin match addr.m_mask with
        | None ->
          sizeof_ofp_oxm + l
        | Some mask ->
          let buf3 = Cstruct.shift buf2 (l/2) in
          set_ofp_uint128_value buf3 mask;
          sizeof_ofp_oxm + l
      end
    | OxmIPv6NDSll sll ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_ND_SLL 0 l;
      set_ofp_uint48_value buf2 sll;
      sizeof_ofp_oxm + l
    | OxmIPv6NDTll tll ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_ND_TLL 0 l;
      set_ofp_uint48_value buf2 tll;
      sizeof_ofp_oxm + l
    | OxmMPLSBos boS ->
      set_ofp_oxm buf ofc OFPXMT_OFP_MPLS_BOS 0 l;
      (match boS with
       | true -> set_ofp_uint8_value buf2 1
       | false -> set_ofp_uint8_value buf2 0);
      sizeof_ofp_oxm + l
    | OxmPBBIsid sid ->
      set_ofp_oxm buf ofc OFPXMT_OFB_PBB_ISID (match sid.m_mask with None -> 0 | _ -> 1)  l;
      set_ofp_uint24_value buf2 sid.m_value;
      begin match sid.m_mask with
        | None ->
          sizeof_ofp_oxm + l
        | Some mask ->
          let buf3 = Cstruct.shift buf2 (l/2) in
          set_ofp_uint24_value buf3 mask;
          sizeof_ofp_oxm + l
      end
    | OxmIPv6ExtHdr hdr ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_EXTHDR (match hdr.m_mask with None -> 0 | _ -> 1)  l;
      set_ofp_uint16_value buf2 (IPv6ExtHdr.marshal hdr.m_value);
      begin match hdr.m_mask with
        | None ->
          sizeof_ofp_oxm + l
        | Some mask ->
          let buf3 = Cstruct.shift buf2 (l/2) in
          set_ofp_uint16_value buf3 (IPv6ExtHdr.marshal mask);
          sizeof_ofp_oxm + l
      end

  let marshal_header (buf : Cstruct.t) (oxm : oxm) : int =
    (* Same as marshal, but without the payload *)
    let l = field_length oxm in
    let ofc = OFPXMC_OPENFLOW_BASIC in
    match oxm with
    | OxmInPort _ ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IN_PORT 0 l;
      sizeof_ofp_oxm
    | OxmInPhyPort _ ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IN_PHY_PORT 0 l;
      sizeof_ofp_oxm
    | OxmEthType _ ->
      set_ofp_oxm buf ofc OFPXMT_OFB_ETH_TYPE 0 l;
      sizeof_ofp_oxm
    | OxmEthDst ethaddr ->
      set_ofp_oxm buf ofc OFPXMT_OFB_ETH_DST (match ethaddr.m_mask with None -> 0 | _ -> 1) l;
      sizeof_ofp_oxm
    | OxmEthSrc ethaddr ->
      set_ofp_oxm buf ofc OFPXMT_OFB_ETH_SRC (match ethaddr.m_mask with None -> 0 | _ -> 1) l;
      sizeof_ofp_oxm
    | OxmIP4Src ipaddr ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IPV4_SRC (match ipaddr.m_mask with None -> 0 | _ -> 1) l;
      sizeof_ofp_oxm
    | OxmIP4Dst ipaddr ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IPV4_DST (match ipaddr.m_mask with None -> 0 | _ -> 1) l;
      sizeof_ofp_oxm
    | OxmVlanVId vid ->
      set_ofp_oxm buf ofc OFPXMT_OFB_VLAN_VID (match vid.m_mask with None -> 0 | _ -> 1) l;
      sizeof_ofp_oxm
    | OxmVlanPcp vid ->
      set_ofp_oxm buf ofc OFPXMT_OFB_VLAN_PCP 0 l;
      sizeof_ofp_oxm
    | OxmMPLSLabel vid ->
      set_ofp_oxm buf ofc OFPXMT_OFB_MPLS_LABEL 0 l;
      sizeof_ofp_oxm
    | OxmMPLSTc vid ->
      set_ofp_oxm buf ofc OFPXMT_OFB_MPLS_TC 0 l;
      sizeof_ofp_oxm
    | OxmMetadata meta ->
      set_ofp_oxm buf ofc OFPXMT_OFB_METADATA  (match meta.m_mask with None -> 0 | _ -> 1)  l;
      sizeof_ofp_oxm
    | OxmIPProto ipproto ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IP_PROTO 0 l;
      sizeof_ofp_oxm
    | OxmIPDscp ipdscp ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IP_DSCP 0 l;
      sizeof_ofp_oxm
    | OxmIPEcn ipecn ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IP_ECN 0 l;
      sizeof_ofp_oxm
    | OxmTCPSrc port ->
      set_ofp_oxm buf ofc OFPXMT_OFB_TCP_SRC 0 l;
      sizeof_ofp_oxm
    | OxmTCPDst port ->
      set_ofp_oxm buf ofc OFPXMT_OFB_TCP_DST 0 l;
      sizeof_ofp_oxm
    | OxmARPOp arp ->
      set_ofp_oxm buf ofc OFPXMT_OFB_ARP_OP 0 l;
      sizeof_ofp_oxm
    | OxmARPSpa arp ->
      set_ofp_oxm buf ofc OFPXMT_OFB_ARP_SPA  (match arp.m_mask with None -> 0 | _ -> 1)  l;
      sizeof_ofp_oxm
    | OxmARPTpa arp ->
      set_ofp_oxm buf ofc OFPXMT_OFB_ARP_TPA  (match arp.m_mask with None -> 0 | _ -> 1)  l;
      sizeof_ofp_oxm
    | OxmARPSha arp ->
      set_ofp_oxm buf ofc OFPXMT_OFB_ARP_SHA  (match arp.m_mask with None -> 0 | _ -> 1)  l;
      sizeof_ofp_oxm
    | OxmARPTha arp ->
      set_ofp_oxm buf ofc OFPXMT_OFB_ARP_THA  (match arp.m_mask with None -> 0 | _ -> 1)  l;
      sizeof_ofp_oxm
    | OxmICMPType t ->
      set_ofp_oxm buf ofc OFPXMT_OFB_ICMPV4_TYPE 0 l;
      sizeof_ofp_oxm
    | OxmICMPCode c->
      set_ofp_oxm buf ofc OFPXMT_OFB_ICMPV4_CODE 0 l;
      sizeof_ofp_oxm
    | OxmTunnelId tun ->
      set_ofp_oxm buf ofc OFPXMT_OFB_TUNNEL_ID  (match tun.m_mask with None -> 0 | _ -> 1)  l;
      sizeof_ofp_oxm
    | OxmUDPSrc port ->
      set_ofp_oxm buf ofc OFPXMT_OFB_UDP_SRC 0 l;
      sizeof_ofp_oxm
    | OxmUDPDst port ->
      set_ofp_oxm buf ofc OFPXMT_OFB_UDP_DST 0 l;
      sizeof_ofp_oxm
    | OxmSCTPSrc port ->
      set_ofp_oxm buf ofc OFPXMT_OFB_SCTP_SRC 0 l;
      sizeof_ofp_oxm
    | OxmSCTPDst port ->
      set_ofp_oxm buf ofc OFPXMT_OFB_SCTP_DST 0 l;
      sizeof_ofp_oxm
    | OxmIPv6Src addr ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_SRC (match addr.m_mask with None -> 0 | _ -> 1)  l;
      sizeof_ofp_oxm
    | OxmIPv6Dst addr ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_DST (match addr.m_mask with None -> 0 | _ -> 1)  l;
      sizeof_ofp_oxm
    | OxmIPv6FLabel label ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_FLABEL (match label.m_mask with None -> 0 | _ -> 1)  l;
      sizeof_ofp_oxm
    | OxmICMPv6Type typ ->
      set_ofp_oxm buf ofc OFPXMT_OFB_ICMPV6_TYPE 0 l;
      sizeof_ofp_oxm
    | OxmICMPv6Code cod ->
      set_ofp_oxm buf ofc OFPXMT_OFB_ICMPV6_CODE 0 l;
      sizeof_ofp_oxm
    | OxmIPv6NDTarget addr ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_ND_TARGET (match addr.m_mask with None -> 0 | _ -> 1)  l;
      sizeof_ofp_oxm
    | OxmIPv6NDSll sll ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_ND_SLL 0 l;
      sizeof_ofp_oxm
    | OxmIPv6NDTll tll ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_ND_TLL 0 l;
      sizeof_ofp_oxm
    | OxmMPLSBos boS ->
      set_ofp_oxm buf ofc OFPXMT_OFP_MPLS_BOS 0 l;
      sizeof_ofp_oxm
    | OxmPBBIsid sid ->
      set_ofp_oxm buf ofc OFPXMT_OFB_PBB_ISID (match sid.m_mask with None -> 0 | _ -> 1)  l;
      sizeof_ofp_oxm
    | OxmIPv6ExtHdr hdr ->
      set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_EXTHDR (match hdr.m_mask with None -> 0 | _ -> 1)  l;
      sizeof_ofp_oxm



  let parse (bits : Cstruct.t) : oxm * Cstruct.t =
    (* printf "class= %d\n" (get_ofp_oxm_oxm_class bits); *)
    (* let c = match int_to_ofp_oxm_class (get_ofp_oxm_oxm_class bits) with *)
    (*   | Some n -> n *)
    (*   | None ->  *)
    (*     raise (Unparsable (sprintf "malformed class in oxm")) in *)
    (* TODO: assert c is OFPXMC_OPENFLOW_BASIC *)
    let value = get_ofp_oxm_oxm_field_and_hashmask bits in
    let f = match int_to_oxm_ofb_match_fields (value lsr 1) with
      | Some n -> n
      | None ->
        raise (Unparsable (sprintf "malformed field in oxm %d" (value lsr 1))) in
    let hm = value land 0x1 in
    let oxm_length = get_ofp_oxm_oxm_length bits in
    let bits = Cstruct.shift bits sizeof_ofp_oxm in
    let bits2 = Cstruct.shift bits oxm_length in
    match f with
    | OFPXMT_OFB_IN_PORT ->
      let pid = get_ofp_uint32_value bits in
      (OxmInPort pid, bits2)
    | OFPXMT_OFB_IN_PHY_PORT ->
      let pid = get_ofp_uint32_value bits in
      (OxmInPhyPort pid, bits2)
    | OFPXMT_OFB_METADATA ->
      let value = get_ofp_uint64_value bits in
      if hm = 1 then
        let bits = Cstruct.shift bits 8 in
        let mask = get_ofp_uint64_value bits in
        (OxmMetadata {m_value = value; m_mask = (Some mask)}, bits2)
      else
        (OxmMetadata {m_value = value; m_mask = None}, bits2)
    | OFPXMT_OFB_TUNNEL_ID ->
      let value = get_ofp_uint64_value bits in
      if hm = 1 then
        let bits = Cstruct.shift bits 8 in
        let mask = get_ofp_uint64_value bits in
        (OxmTunnelId {m_value = value; m_mask = (Some mask)}, bits2)
      else
        (OxmTunnelId {m_value = value; m_mask = None}, bits2)
    (* Ethernet destination address. *)
    | OFPXMT_OFB_ETH_DST ->
      let value = get_ofp_uint48_value bits in
      if hm = 1 then
        let bits = Cstruct.shift bits 6 in
        let mask = get_ofp_uint48_value bits in
        (OxmEthDst {m_value = value; m_mask = (Some mask)}, bits2)
      else
        (OxmEthDst {m_value = value; m_mask = None}, bits2)
    (* Ethernet source address. *)
    | OFPXMT_OFB_ETH_SRC ->
      let value = get_ofp_uint48_value bits in
      if hm = 1 then
        let bits = Cstruct.shift bits 6 in
        let mask = get_ofp_uint48_value bits in
        (OxmEthSrc {m_value = value; m_mask = (Some mask)}, bits2)
      else
        (OxmEthSrc {m_value = value; m_mask = None}, bits2)
    (* Ethernet frame type. *)
    | OFPXMT_OFB_ETH_TYPE ->
      let value = get_ofp_uint16_value bits in
      (OxmEthType value, bits2)
    (* IP protocol. *)
    | OFPXMT_OFB_IP_PROTO ->
      let value = get_ofp_uint8_value bits in
      (OxmIPProto value, bits2)
    (* IP DSCP (6 bits in ToS field). *)
    | OFPXMT_OFB_IP_DSCP ->
      let value = get_ofp_uint8_value bits in
      (OxmIPDscp (value land 63), bits2)
    (* IP ECN (2 bits in ToS field). *)
    |  OFPXMT_OFB_IP_ECN ->
      let value = get_ofp_uint8_value bits in
      (OxmIPEcn (value land 3), bits2)
    (* IPv4 source address. *)
    | OFPXMT_OFB_IPV4_SRC ->
      let value = get_ofp_uint32_value bits in
      if hm = 1 then
        let bits = Cstruct.shift bits 4 in
        let mask = get_ofp_uint32_value bits in
        (OxmIP4Src {m_value = value; m_mask = (Some mask)}, bits2)
      else
        (OxmIP4Src {m_value = value; m_mask = None}, bits2)
    (* IPv4 destination address. *)
    | OFPXMT_OFB_IPV4_DST ->
      let value = get_ofp_uint32_value bits in
      if hm = 1 then
        let bits = Cstruct.shift bits 4 in
        let mask = get_ofp_uint32_value bits in
        (OxmIP4Dst {m_value = value; m_mask = (Some mask)}, bits2)
      else
        (OxmIP4Dst {m_value = value; m_mask = None}, bits2)
    (* ARP opcode. *)
    | OFPXMT_OFB_ARP_OP ->
      let value = get_ofp_uint16_value bits in
      (OxmARPOp value, bits2)
    (* ARP source IPv4 address. *)
    | OFPXMT_OFB_ARP_SPA ->
      let value = get_ofp_uint32_value bits in
      if hm = 1 then
        let bits = Cstruct.shift bits 4 in
        let mask = get_ofp_uint32_value bits in
        (OxmARPSpa {m_value = value; m_mask = (Some mask)}, bits2)
      else
        (OxmARPSpa {m_value = value; m_mask = None}, bits2)
    (* ARP target IPv4 address. *)
    | OFPXMT_OFB_ARP_TPA ->
      let value = get_ofp_uint32_value bits in
      if hm = 1 then
        let bits = Cstruct.shift bits 4 in
        let mask = get_ofp_uint32_value bits in
        (OxmARPTpa {m_value = value; m_mask = (Some mask)}, bits2)
      else
        (OxmARPTpa {m_value = value; m_mask = None}, bits2)
    (* ARP source hardware address. *)
    | OFPXMT_OFB_ARP_SHA ->
      let value = get_ofp_uint48_value bits in
      if hm = 1 then
        let bits = Cstruct.shift bits 6 in
        let mask = get_ofp_uint48_value bits in
        (OxmARPSha {m_value = value; m_mask = (Some mask)}, bits2)
      else
        (OxmARPSha {m_value = value; m_mask = None}, bits2)
    (* ARP target hardware address. *)
    | OFPXMT_OFB_ARP_THA ->
      let value = get_ofp_uint48_value bits in
      if hm = 1 then
        let bits = Cstruct.shift bits 6 in
        let mask = get_ofp_uint48_value bits in
        (OxmARPTha {m_value = value; m_mask = (Some mask)}, bits2)
      else
        (OxmARPTha {m_value = value; m_mask = None}, bits2)
    (* ICMP Type *)
    | OFPXMT_OFB_ICMPV4_TYPE ->
      let value = get_ofp_uint8_value bits in
      (OxmICMPType value, bits2)
    (* ICMP code. *)
    |   OFPXMT_OFB_ICMPV4_CODE ->
      let value = get_ofp_uint8_value bits in
      (OxmICMPCode value, bits2)
    | OFPXMT_OFB_TCP_DST ->
      let value = get_ofp_uint16_value bits in
      (OxmTCPDst value, bits2)
    | OFPXMT_OFB_TCP_SRC ->
      let value = get_ofp_uint16_value bits in
      (OxmTCPSrc value, bits2)
    | OFPXMT_OFB_MPLS_LABEL ->
      let value = get_ofp_uint32_value bits in
      (OxmMPLSLabel value, bits2)
    | OFPXMT_OFB_VLAN_PCP ->
      let value = get_ofp_uint8_value bits in
      (OxmVlanPcp value, bits2)
    | OFPXMT_OFB_VLAN_VID ->
      let value = get_ofp_uint16_value bits in
      if hm = 1 then
        let bits = Cstruct.shift bits 2 in
        let mask = get_ofp_uint16_value bits in
        (OxmVlanVId {m_value = value; m_mask = (Some mask)}, bits2)
      else
        (OxmVlanVId {m_value = value; m_mask = None}, bits2)
    | OFPXMT_OFB_MPLS_TC ->
      let value = get_ofp_uint8_value bits in
      (OxmMPLSTc value, bits2)
    | OFPXMT_OFB_UDP_SRC ->
      let value = get_ofp_uint16_value bits in
      (OxmUDPSrc value, bits2)
    | OFPXMT_OFB_UDP_DST ->
      let value = get_ofp_uint16_value bits in
      (OxmUDPDst value, bits2)
    | OFPXMT_OFB_SCTP_SRC ->
      let value = get_ofp_uint16_value bits in
      (OxmSCTPSrc value, bits2)
    | OFPXMT_OFB_SCTP_DST ->
      let value = get_ofp_uint16_value bits in
      (OxmSCTPDst value, bits2)
    | OFPXMT_OFB_IPV6_SRC ->
      let value = get_ofp_uint128_value bits in
      if hm = 1 then
        let bits = Cstruct.shift bits 16 in
        let mask = get_ofp_uint128_value bits in
        (OxmIPv6Src {m_value = value; m_mask = (Some mask)}, bits2)
      else
        (OxmIPv6Src {m_value = value; m_mask = None}, bits2)
    | OFPXMT_OFB_IPV6_DST ->
      let value = get_ofp_uint128_value bits in
      if hm = 1 then
        let bits = Cstruct.shift bits 16 in
        let mask = get_ofp_uint128_value bits in
        (OxmIPv6Dst {m_value = value; m_mask = (Some mask)}, bits2)
      else
        (OxmIPv6Dst {m_value = value; m_mask = None}, bits2)
    | OFPXMT_OFB_IPV6_FLABEL ->
      let value = get_ofp_uint32_value bits in
      if hm = 1 then
        let bits = Cstruct.shift bits 4 in
        let mask = get_ofp_uint32_value bits in
        (OxmIPv6FLabel {m_value = value; m_mask = (Some mask)}, bits2)
      else
        (OxmIPv6FLabel {m_value = value; m_mask = None}, bits2)
    | OFPXMT_OFB_ICMPV6_TYPE ->
      let value = get_ofp_uint8_value bits in
      (OxmICMPv6Type value, bits2)
    | OFPXMT_OFB_ICMPV6_CODE ->
      let value = get_ofp_uint8_value bits in
      (OxmICMPv6Code value, bits2)
    | OFPXMT_OFB_IPV6_ND_TARGET ->
      let value = get_ofp_uint128_value bits in
      if hm = 1 then
        let bits = Cstruct.shift bits 16 in
        let mask = get_ofp_uint128_value bits in
        (OxmIPv6NDTarget {m_value = value; m_mask = (Some mask)}, bits2)
      else
        (OxmIPv6NDTarget {m_value = value; m_mask = None}, bits2)
    | OFPXMT_OFB_IPV6_ND_SLL ->
      let value = get_ofp_uint48_value bits in
      (OxmIPv6NDSll value, bits2)
    | OFPXMT_OFB_IPV6_ND_TLL ->
      let value = get_ofp_uint48_value bits in
      (OxmIPv6NDTll value, bits2)
    | OFPXMT_OFP_MPLS_BOS ->
      let value = get_ofp_uint8_value bits in
      (OxmMPLSBos ((value land 1) = 1), bits2)
    | OFPXMT_OFB_PBB_ISID ->
      let value = get_ofp_uint24_value bits in
      if hm = 1 then
        let bits = Cstruct.shift bits 3 in
        let mask = get_ofp_uint24_value bits in
        (OxmPBBIsid {m_value = value; m_mask = (Some mask)}, bits2)
      else
        (OxmPBBIsid {m_value = value; m_mask = None}, bits2)
    | OFPXMT_OFB_IPV6_EXTHDR ->
      let value = IPv6ExtHdr.parse (get_ofp_uint16_value bits) in
      if hm = 1 then
        let bits = Cstruct.shift bits 2 in
        let mask = IPv6ExtHdr.parse (get_ofp_uint16_value bits) in
        (OxmIPv6ExtHdr {m_value = value; m_mask = (Some mask)}, bits2)
      else
        (OxmIPv6ExtHdr {m_value = value; m_mask = None}, bits2)

  let parse_header (bits : Cstruct.t) : oxm * Cstruct.t =
    (* parse Oxm header function for TableFeatureProp. Similar to parse, but without
       parsing the payload *)
    let value = get_ofp_oxm_oxm_field_and_hashmask bits in
    let f = match int_to_oxm_ofb_match_fields (value lsr 1) with
      | Some n -> n
      | None -> raise (Unparsable (sprintf "malformed field in oxm %d" (value lsr 1))) in
    let hm = value land 0x1 in
    let bits2 = Cstruct.shift bits sizeof_ofp_oxm in
    match f with
    | OFPXMT_OFB_IN_PORT ->
      (OxmInPort 0l, bits2)
    | OFPXMT_OFB_IN_PHY_PORT ->
      (OxmInPhyPort 0l, bits2)
    | OFPXMT_OFB_METADATA ->
      if hm = 1 then
        (OxmMetadata {m_value = 0L; m_mask = (Some 0L)}, bits2)
      else
        (OxmMetadata {m_value = 0L; m_mask = None}, bits2)
    | OFPXMT_OFB_TUNNEL_ID ->
      if hm = 1 then
        (OxmTunnelId {m_value = 0L; m_mask = (Some 0L)}, bits2)
      else
        (OxmTunnelId {m_value = 0L; m_mask = None}, bits2)
    (* Ethernet destination address. *)
    | OFPXMT_OFB_ETH_DST ->
      if hm = 1 then
        (OxmEthDst {m_value = 0L; m_mask = (Some 0L)}, bits2)
      else
        (OxmEthDst {m_value = 0L; m_mask = None}, bits2)
    (* Ethernet source address. *)
    | OFPXMT_OFB_ETH_SRC ->
      if hm = 1 then
        (OxmEthSrc {m_value = 0L; m_mask = (Some 0L)}, bits2)
      else
        (OxmEthSrc {m_value = 0L; m_mask = None}, bits2)
    (* Ethernet frame type. *)
    | OFPXMT_OFB_ETH_TYPE ->
      (OxmEthType 0, bits2)
    (* IP protocol. *)
    | OFPXMT_OFB_IP_PROTO ->
      (OxmIPProto 0, bits2)
    (* IP DSCP (6 bits in ToS field). *)
    | OFPXMT_OFB_IP_DSCP ->
      (OxmIPDscp (0 land 63), bits2)
    (* IP ECN (2 bits in ToS field). *)
    |  OFPXMT_OFB_IP_ECN ->
      (OxmIPEcn (0 land 3), bits2)
    (* IPv4 source address. *)
    | OFPXMT_OFB_IPV4_SRC ->
      if hm = 1 then
        (OxmIP4Src {m_value = 0l; m_mask = (Some 0l)}, bits2)
      else
        (OxmIP4Src {m_value = 0l; m_mask = None}, bits2)
    (* IPv4 destination address. *)
    | OFPXMT_OFB_IPV4_DST ->
      if hm = 1 then
        (OxmIP4Dst {m_value = 0l; m_mask = (Some 0l)}, bits2)
      else
        (OxmIP4Dst {m_value = 0l; m_mask = None}, bits2)
    (* ARP opcode. *)
    | OFPXMT_OFB_ARP_OP ->
      (OxmARPOp 0, bits2)
    (* ARP source IPv4 address. *)
    | OFPXMT_OFB_ARP_SPA ->
      if hm = 1 then
        (OxmARPSpa {m_value = 0l; m_mask = (Some 0l)}, bits2)
      else
        (OxmARPSpa {m_value = 0l; m_mask = None}, bits2)
    (* ARP target IPv4 address. *)
    | OFPXMT_OFB_ARP_TPA ->
      if hm = 1 then
        (OxmARPTpa {m_value = 0l; m_mask = (Some 0l)}, bits2)
      else
        (OxmARPTpa {m_value = 0l; m_mask = None}, bits2)
    (* ARP source hardware address. *)
    | OFPXMT_OFB_ARP_SHA ->
      if hm = 1 then
        (OxmARPSha {m_value = 0L; m_mask = (Some 0L)}, bits2)
      else
        (OxmARPSha {m_value = 0L; m_mask = None}, bits2)
    (* ARP target hardware address. *)
    | OFPXMT_OFB_ARP_THA ->
      if hm = 1 then
        (OxmARPTha {m_value = 0L; m_mask = (Some 0L)}, bits2)
      else
        (OxmARPTha {m_value = 0L; m_mask = None}, bits2)
    (* ICMP Type *)
    | OFPXMT_OFB_ICMPV4_TYPE ->
      (OxmICMPType 0, bits2)
    (* ICMP code. *)
    |   OFPXMT_OFB_ICMPV4_CODE ->
      (OxmICMPCode 0, bits2)
    | OFPXMT_OFB_TCP_DST ->
      (OxmTCPDst 0, bits2)
    | OFPXMT_OFB_TCP_SRC ->
      (OxmTCPSrc 0, bits2)
    | OFPXMT_OFB_MPLS_LABEL ->
      (OxmMPLSLabel 0l, bits2)
    | OFPXMT_OFB_VLAN_PCP ->
      (OxmVlanPcp 0, bits2)
    | OFPXMT_OFB_VLAN_VID ->
      if hm = 1 then
        (OxmVlanVId {m_value = 0; m_mask = (Some 0)}, bits2)
      else
        (OxmVlanVId {m_value = 0; m_mask = None}, bits2)
    | OFPXMT_OFB_MPLS_TC ->
      (OxmMPLSTc 0, bits2)
    | OFPXMT_OFB_UDP_SRC ->
      (OxmUDPSrc 0, bits2)
    | OFPXMT_OFB_UDP_DST ->
      (OxmUDPDst 0, bits2)
    | OFPXMT_OFB_SCTP_SRC ->
      (OxmSCTPSrc 0, bits2)
    | OFPXMT_OFB_SCTP_DST ->
      (OxmSCTPDst 0, bits2)
    | OFPXMT_OFB_IPV6_SRC ->
      if hm = 1 then
        (OxmIPv6Src {m_value = (0L,0L); m_mask = (Some (0L,0L))}, bits2)
      else
        (OxmIPv6Src {m_value = (0L,0L); m_mask = None}, bits2)
    | OFPXMT_OFB_IPV6_DST ->
      if hm = 1 then
        (OxmIPv6Dst {m_value = (0L,0L); m_mask = (Some (0L,0L))}, bits2)
      else
        (OxmIPv6Dst {m_value = (0L,0L); m_mask = None}, bits2)
    | OFPXMT_OFB_IPV6_FLABEL ->
      if hm = 1 then
        (OxmIPv6FLabel {m_value = 0l; m_mask = (Some 0l)}, bits2)
      else
        (OxmIPv6FLabel {m_value = 0l; m_mask = None}, bits2)
    | OFPXMT_OFB_ICMPV6_TYPE ->
      (OxmICMPv6Type 0, bits2)
    | OFPXMT_OFB_ICMPV6_CODE ->
      (OxmICMPv6Code 0, bits2)
    | OFPXMT_OFB_IPV6_ND_TARGET ->
      if hm = 1 then
        (OxmIPv6NDTarget {m_value = (0L,0L); m_mask = (Some (0L,0L))}, bits2)
      else
        (OxmIPv6NDTarget {m_value = (0L,0L); m_mask = None}, bits2)
    | OFPXMT_OFB_IPV6_ND_SLL ->
      (OxmIPv6NDSll 0L, bits2)
    | OFPXMT_OFB_IPV6_ND_TLL ->
      (OxmIPv6NDTll 0L, bits2)
    | OFPXMT_OFP_MPLS_BOS ->
      (OxmMPLSBos false, bits2)
    | OFPXMT_OFB_PBB_ISID ->
      if hm = 1 then
        (OxmPBBIsid {m_value = 0l; m_mask = (Some 0l)}, bits2)
      else
        (OxmPBBIsid {m_value = 0l; m_mask = None}, bits2)
    | OFPXMT_OFB_IPV6_EXTHDR ->
      let nul = {noext = false; esp = false; auth = false; dest = false; frac = false; router = false; hop = false; unrep = false; unseq = false } in
      if hm = 1 then
        (OxmIPv6ExtHdr {m_value = nul; m_mask = (Some nul)}, bits2)
      else
        (OxmIPv6ExtHdr {m_value = nul; m_mask = None}, bits2)

  let rec parse_headers (bits : Cstruct.t) : oxmMatch*Cstruct.t =
    if Cstruct.len bits < sizeof_ofp_oxm then ([], bits)
    else let field, bits2 = parse_header bits in
      let fields, bits3 = parse_headers bits2 in
      (List.append [field] fields, bits3)

end

module PseudoPort = struct
  type t = pseudoPort

      cenum ofp_port_no {
      (* Maximum number of physical and logical switch ports. *)
      OFPP_MAX        = 0xffffff00l;

      (* Reserved OpenFlow Port (fake output "ports"). *)
      OFPP_IN_PORT    = 0xfffffff8l; (* Send the packet out the input port. This
                                        reserved port must be explicitly used
                                        in order to send back out of the input
                                        port.*)
      OFPP_TABLE      = 0xfffffff9l; (* Submit the packet to the first flow table
                                        NB: This destination port can only be
                                        used in packet-out messages. *)
      OFPP_NORMAL     = 0xfffffffal; (* Process with normal L2/L3 switching. *)
      OFPP_FLOOD      = 0xfffffffbl; (* All physical ports in VLAN, except input
                                        port and those blocked or link down. *)
      OFPP_ALL        = 0xfffffffcl; (* All physical ports except input port. *)
      OFPP_CONTROLLER = 0xfffffffdl; (* Send to controller. *)
      OFPP_LOCAL      = 0xfffffffel; (* Local openflow "port". *)
      OFPP_ANY        = 0xffffffffl  (* Wildcard port used only for flow mod
                                        (delete) and flow stats requests. Selects
                                        all flows regardless of output port
                                        (including flows with no output port). *)
    } as uint32_t

  let size_of _ = 4

  let marshal (t : t) : int32 = match t with
    | PhysicalPort(p) -> p
    | InPort -> ofp_port_no_to_int OFPP_IN_PORT
    | Table -> ofp_port_no_to_int OFPP_TABLE
    | Normal -> ofp_port_no_to_int OFPP_NORMAL
    | Flood -> ofp_port_no_to_int  OFPP_FLOOD
    | AllPorts -> ofp_port_no_to_int OFPP_ALL
    | Controller(_) -> ofp_port_no_to_int  OFPP_CONTROLLER
    | Local -> ofp_port_no_to_int  OFPP_LOCAL
    | Any -> ofp_port_no_to_int  OFPP_ANY

  let make ofp_port_no_code len =
    match int_to_ofp_port_no ofp_port_no_code with
    | Some OFPP_IN_PORT -> InPort
    | Some OFPP_TABLE -> Table
    | Some OFPP_NORMAL -> Normal
    | Some OFPP_FLOOD -> Flood
    | Some OFPP_ALL -> AllPorts
    | Some OFPP_CONTROLLER -> Controller len
    | Some OFPP_LOCAL -> Local
    | Some OFPP_ANY -> Any
    | _ ->
      if compare_uint32 ofp_port_no_code (ofp_port_no_to_int OFPP_MAX) then
        PhysicalPort ofp_port_no_code
      else
        raise
          (Unparsable (sprintf "unsupported port number (%lu)" ofp_port_no_code))

end

module QueueDesc = struct

  cstruct ofp_packet_queue {
    uint32_t queue_id;
    uint32_t port;
    uint16_t len;
    uint8_t pad[6]
  } as big_endian

  module QueueProp = struct

    cstruct ofp_queue_prop_header {
      uint16_t property;
      uint16_t len;
      uint8_t pad[4]
    } as big_endian

    cenum ofp_queue_properties {
      OFPQT_MIN_RATE = 1;
      OFPQT_MAX_RATE = 2;
      OFPQT_EXPERIMENTER = 0xffff
    } as uint16_t

    cstruct ofp_queue_prop_min_rate {
      uint16_t property;
      uint16_t len;
      uint8_t pad[4];
      uint16_t rate;
      uint8_t pad[6]
    } as big_endian

    cstruct ofp_queue_prop_max_rate {
      uint16_t property;
      uint16_t len;
      uint8_t pad[4];
      uint16_t rate;
      uint8_t pad[6]
    } as big_endian

    cstruct ofp_queue_prop_experimenter {
      uint16_t property;
      uint16_t len;
      uint8_t pad[4];
      uint32_t experimenter;
      uint8_t pad[4]
    } as big_endian

    type t = queueProp

    let sizeof (qp : t) : int =
      match qp with
      | MinRateProp _ -> sizeof_ofp_queue_prop_min_rate
      | MaxRateProp _-> sizeof_ofp_queue_prop_max_rate
      | ExperimenterProp _ -> sizeof_ofp_queue_prop_experimenter

    let length_func (buf : Cstruct.t) : int option =
      if Cstruct.len buf < sizeof_ofp_queue_prop_header then None
      else Some (get_ofp_queue_prop_header_len buf)

    let marshal (buf : Cstruct.t) (qp : t) : int =
      match qp with
      | MinRateProp rate ->
        set_ofp_queue_prop_min_rate_property buf (ofp_queue_properties_to_int OFPQT_MIN_RATE);
        set_ofp_queue_prop_min_rate_len buf 16; (* fixed by specification *)
        set_ofp_queue_prop_min_rate_rate buf (
          match rate with
          | Rate n -> n
          | Disabled -> 0xffff);
        sizeof_ofp_queue_prop_min_rate
      | MaxRateProp rate ->
        set_ofp_queue_prop_max_rate_property buf (ofp_queue_properties_to_int OFPQT_MAX_RATE);
        set_ofp_queue_prop_max_rate_len buf 16; (* fixed by specification *)
        set_ofp_queue_prop_max_rate_rate buf (
          match rate with
          | Rate n -> n
          | Disabled -> 0xffff);
        sizeof_ofp_queue_prop_max_rate
      | ExperimenterProp id ->
        set_ofp_queue_prop_experimenter_property buf (ofp_queue_properties_to_int OFPQT_EXPERIMENTER);
        set_ofp_queue_prop_experimenter_len buf 16; (* fixed by specification *)
        set_ofp_queue_prop_experimenter_experimenter buf id;
        sizeof_ofp_queue_prop_experimenter

    let parse (bits : Cstruct.t) : t =
      let typ = int_to_ofp_queue_properties (get_ofp_queue_prop_header_property bits) in
      match typ with
      | Some OFPQT_MIN_RATE ->
        let rate = get_ofp_queue_prop_min_rate_rate bits in
        if rate > 1000 then MinRateProp Disabled
        else MinRateProp (Rate rate)
      | Some OFPQT_MAX_RATE ->
        let rate = get_ofp_queue_prop_max_rate_rate bits in
        if rate > 1000 then MaxRateProp Disabled
        else MaxRateProp (Rate rate)
      | Some OFPQT_EXPERIMENTER ->
        let exp_id = get_ofp_queue_prop_experimenter_experimenter bits
        in ExperimenterProp exp_id
      | None -> raise (Unparsable (sprintf "malformed property"))
  end

  type t = queueDesc

  let sizeof (qd : t) : int =
    sizeof_ofp_packet_queue + sum (List.map ~f:QueueProp.sizeof qd.properties)

  let length_func (buf : Cstruct.t) : int option =
    if Cstruct.len buf < sizeof_ofp_packet_queue then None
    else Some (get_ofp_packet_queue_len buf)

  let marshal (buf : Cstruct.t) (qd : t) : int =
    set_ofp_packet_queue_queue_id buf qd.queue_id;
    set_ofp_packet_queue_port buf qd.port;
    set_ofp_packet_queue_len buf qd.len;
    let propBuf = Cstruct.sub buf sizeof_ofp_packet_queue (qd.len - sizeof_ofp_packet_queue) in
    sizeof_ofp_packet_queue + (marshal_fields propBuf qd.properties QueueProp.marshal)

  let parse (bits : Cstruct.t) : t =
    let queue_id = get_ofp_packet_queue_queue_id bits in
    let port = get_ofp_packet_queue_port bits in
    let len = get_ofp_packet_queue_len bits in
    let propBits = Cstruct.sub bits sizeof_ofp_packet_queue (len - sizeof_ofp_packet_queue) in
    let properties = parse_fields propBits QueueProp.parse QueueProp.length_func in
    { queue_id; port; len; properties}

end

module SwitchConfig = struct

  cstruct ofp_switch_config {
    uint16_t flags;
    uint16_t miss_send_len
  } as big_endian

  module Flags = struct

    cenum ofp_config_flags {
      OFPC_FRAG_NORMAL = 0;
      OFPC_FRAG_DROP = 1;
      OFPC_FRAG_REASM = 2;
      OFPC_FRAG_MASK = 3
    } as uint16_t

    let marshal (flags : switchFlags) : int =
      match flags with
      | NormalFrag -> ofp_config_flags_to_int OFPC_FRAG_NORMAL
      | DropFrag -> ofp_config_flags_to_int OFPC_FRAG_DROP
      | ReasmFrag -> ofp_config_flags_to_int OFPC_FRAG_REASM
      | MaskFrag -> ofp_config_flags_to_int OFPC_FRAG_MASK

    let parse t : switchFlags =
      match int_to_ofp_config_flags t with
      | Some OFPC_FRAG_NORMAL -> NormalFrag
      | Some OFPC_FRAG_DROP -> DropFrag
      | Some OFPC_FRAG_REASM -> ReasmFrag
      | Some OFPC_FRAG_MASK -> MaskFrag
      | None -> raise (Unparsable (sprintf "Malformed flags"))
  end

  type t = switchConfig

  let sizeof (sc : switchConfig) : int =
    sizeof_ofp_switch_config

  let marshal (buf : Cstruct.t) (sc : switchConfig) : int =
    set_ofp_switch_config_flags buf (Flags.marshal sc.flags);
    set_ofp_switch_config_miss_send_len buf sc.miss_send_len;
    sizeof_ofp_switch_config

  let parse (bits : Cstruct.t) : switchConfig =
    let flags = Flags.parse (get_ofp_switch_config_flags bits) in
    let miss_send_len = get_ofp_switch_config_miss_send_len bits in
    { flags; miss_send_len }

end

module OfpMatch = struct

  type t = oxmMatch

  let sizeof (om : t) : int =
    let n = sizeof_ofp_match + sum (List.map ~f:Oxm.sizeof om) in
    pad_to_64bits n

  let marshal (buf : Cstruct.t) (om : t) : int =
    let size = sizeof om in
    set_ofp_match_typ buf 1; (* OXPMT_OXM *)
    set_ofp_match_length buf (sizeof_ofp_match + sum (List.map ~f:Oxm.sizeof om)); (* Length of ofp_match (excluding padding) *)
    let buf = Cstruct.shift buf sizeof_ofp_match in
    let oxm_size = marshal_fields buf om Oxm.marshal in
    let pad = size - (sizeof_ofp_match + oxm_size) in
    if pad > 0 then
      let buf = Cstruct.shift buf oxm_size in
      let _ = pad_with_zeros buf pad in
      size
    else size

  let rec parse_fields (bits : Cstruct.t) : t * Cstruct.t =
    if Cstruct.len bits <= sizeof_ofp_oxm then ([], bits)
    else let field, bits2 = Oxm.parse bits in
      let fields, bits3 = parse_fields bits2 in
      (List.append [field] fields, bits3)

  let parse (bits : Cstruct.t) : t * Cstruct.t =
    let length = get_ofp_match_length bits in
    let oxm_bits = Cstruct.sub bits sizeof_ofp_match (length - sizeof_ofp_match) in
    let fields, _ = parse_fields oxm_bits in
    let bits = Cstruct.shift bits (pad_to_64bits length) in
    (fields, bits)

end

module Action = struct

  type t = action
  type sequence = actionSequence

  let sizeof (act : t) : int = match act with
    | Output _ -> sizeof_ofp_action_output
    | Group _ -> sizeof_ofp_action_group
    | PopVlan -> sizeof_ofp_action_header
    | PushVlan -> sizeof_ofp_action_push
    | PopMpls -> sizeof_ofp_action_pop_mpls
    | PushMpls -> sizeof_ofp_action_push
    | SetField oxm -> pad_to_64bits (sizeof_ofp_action_set_field + Oxm.sizeof oxm)
    | CopyTtlOut -> sizeof_ofp_action_header
    | CopyTtlIn -> sizeof_ofp_action_header
    | SetNwTtl _ -> sizeof_ofp_action_nw_ttl
    | DecNwTtl -> sizeof_ofp_action_header
    | PushPbb -> sizeof_ofp_action_push
    | PopPbb -> sizeof_ofp_action_header
    | SetMplsTtl _ -> sizeof_ofp_action_push
    | DecMplsTtl -> sizeof_ofp_action_header
    | SetQueue _ -> sizeof_ofp_action_set_queue
    | Experimenter _ -> sizeof_ofp_action_experimenter

  let marshal (buf : Cstruct.t) (act : t) : int =
    let size = sizeof act in
    match act with
    | Output port ->
      set_ofp_action_output_typ buf 0; (* OFPAT_OUTPUT *)
      set_ofp_action_output_len buf size;
      set_ofp_action_output_port buf (PseudoPort.marshal port);
      set_ofp_action_output_max_len buf
        (match port with
         | Controller max_len -> max_len
         | _ -> 0);
      set_ofp_action_output_pad0 buf 0;
      set_ofp_action_output_pad1 buf 0;
      set_ofp_action_output_pad2 buf 0;
      set_ofp_action_output_pad3 buf 0;
      set_ofp_action_output_pad4 buf 0;
      set_ofp_action_output_pad5 buf 0;
      size
    | PushVlan ->
      set_ofp_action_push_typ buf 17; (* PUSH_VLAN *)
      set_ofp_action_push_len buf size;
      set_ofp_action_push_ethertype buf 0x8100;
      size
    | PopVlan ->
      set_ofp_action_header_typ buf 18; (* POP_VLAN *)
      set_ofp_action_header_len buf size;
      set_ofp_action_header_pad buf 0;
      set_ofp_action_header_pad1 buf 0;
      set_ofp_action_header_pad2 buf 0;
      set_ofp_action_header_pad3 buf 0;
      size
    | PushMpls ->
      set_ofp_action_push_typ buf 19; (* PUSH_MPLS *)
      set_ofp_action_push_len buf size;
      set_ofp_action_push_ethertype buf 0x8847;
      size
    | PopMpls ->
      set_ofp_action_pop_mpls_typ buf 20; (* POP_MPLS *)
      set_ofp_action_pop_mpls_len buf size;
      set_ofp_action_pop_mpls_ethertype buf 0x800;
      size
    | Group gid ->
      set_ofp_action_group_typ buf 22; (* OFPAT_GROUP *)
      set_ofp_action_group_len buf size;
      set_ofp_action_group_group_id buf gid;
      size
    | SetField oxm ->
      set_ofp_action_set_field_typ buf 25; (* OFPAT_SET_FIELD *)
      set_ofp_action_set_field_len buf size;
      let buf = Cstruct.shift buf sizeof_ofp_action_set_field in
      let oxm_size = Oxm.marshal buf oxm in
      let pad = size - (sizeof_ofp_action_set_field + oxm_size) in
      (* printf "pad = %d\n" pad; *)
      if pad > 0 then
        let buf = Cstruct.shift buf oxm_size in
        let _ = pad_with_zeros buf pad in
        size
      else size
    | CopyTtlOut ->
      set_ofp_action_header_typ buf 11; (* OFPAT_COPY_TTL_OUT *)
      set_ofp_action_header_len buf size;
      set_ofp_action_header_pad buf 0;
      set_ofp_action_header_pad1 buf 0;
      set_ofp_action_header_pad2 buf 0;
      set_ofp_action_header_pad3 buf 0;
      size
    | CopyTtlIn ->
      set_ofp_action_header_typ buf 12; (* OFPAT_COPY_TTL_IN *)
      set_ofp_action_header_len buf size;
      set_ofp_action_header_pad buf 0;
      set_ofp_action_header_pad1 buf 0;
      set_ofp_action_header_pad2 buf 0;
      set_ofp_action_header_pad3 buf 0;
      size
    | SetNwTtl newTtl ->
      set_ofp_action_nw_ttl_typ buf 23; (* OFPAT_SET_NW_TTL *)
      set_ofp_action_nw_ttl_len buf size;
      set_ofp_action_nw_ttl_nw_ttl buf newTtl;
      set_ofp_action_nw_ttl_pad buf 0;
      set_ofp_action_nw_ttl_pad1 buf 0;
      set_ofp_action_nw_ttl_pad2 buf 0;
      size
    | DecNwTtl ->
      set_ofp_action_header_typ buf 24; (* OFPAT_DEC_NW_TTL *)
      set_ofp_action_header_len buf size;
      set_ofp_action_header_pad buf 0;
      set_ofp_action_header_pad1 buf 0;
      set_ofp_action_header_pad2 buf 0;
      set_ofp_action_header_pad3 buf 0;
      size
    | PushPbb ->
      set_ofp_action_push_typ buf 26; (* OFPAT_PUSH_PBB *)
      set_ofp_action_push_len buf size;
      set_ofp_action_push_ethertype buf 0x88a8; (* Not sure, maybe need to redefine*)
      size
    | PopPbb ->
      set_ofp_action_header_typ buf 27; (* OFPAT_POP_PBB *)
      set_ofp_action_header_len buf size;
      set_ofp_action_header_pad buf 0;
      set_ofp_action_header_pad1 buf 0;
      set_ofp_action_header_pad2 buf 0;
      set_ofp_action_header_pad3 buf 0;
      size
    | SetMplsTtl newTtl ->
      set_ofp_action_mpls_ttl_typ buf 15; (* OFPAT_SET_MPLS_TTL *)
      set_ofp_action_mpls_ttl_len buf size;
      set_ofp_action_mpls_ttl_mpls_ttl buf newTtl;
      size
    | DecMplsTtl ->
      set_ofp_action_header_typ buf 16; (* OFPAT_DEC_MPLS_TTL *)
      set_ofp_action_header_len buf size;
      set_ofp_action_header_pad buf 0;
      set_ofp_action_header_pad1 buf 0;
      set_ofp_action_header_pad2 buf 0;
      set_ofp_action_header_pad3 buf 0;
      size
    | SetQueue queueId ->
      set_ofp_action_set_queue_typ buf 21; (* OFPAT_SET_QUEUE *)
      set_ofp_action_set_queue_len buf size;
      set_ofp_action_set_queue_queue_id buf queueId;
      size
    | Experimenter exp ->
      set_ofp_action_experimenter_typ buf 0xffff; (* OFPAT_EXPERIMENTER *)
      set_ofp_action_experimenter_len buf size;
      set_ofp_action_experimenter_experimenter buf exp;
      size

  let parse (bits : Cstruct.t) : t =
    match int_to_ofp_action_type (get_ofp_action_header_typ bits) with
    | Some OFPAT_OUTPUT -> Output (PseudoPort.make (get_ofp_action_output_port bits)  (get_ofp_action_output_max_len bits))
    | Some OFPAT_COPY_TTL_OUT -> CopyTtlOut
    | Some OFPAT_COPY_TTL_IN -> CopyTtlIn
    | Some OFPAT_SET_MPLS_TTL -> SetMplsTtl (get_ofp_action_mpls_ttl_mpls_ttl bits)
    | Some OFPAT_DEC_MPLS_TTL -> DecMplsTtl
    | Some OFPAT_PUSH_VLAN -> PushVlan
    | Some OFPAT_POP_VLAN -> PopVlan
    | Some OFPAT_PUSH_MPLS -> PushMpls
    | Some OFPAT_POP_MPLS -> PopMpls
    | Some OFPAT_SET_QUEUE -> SetQueue (get_ofp_action_set_queue_queue_id bits)
    | Some OFPAT_GROUP -> Group (get_ofp_action_group_group_id bits)
    | Some OFPAT_SET_NW_TTL -> SetNwTtl (get_ofp_action_nw_ttl_nw_ttl bits)
    | Some OFPAT_DEC_NW_TTL -> DecNwTtl
    | Some OFPAT_SET_FIELD -> let field,_ = Oxm.parse (
        Cstruct.shift bits 4) in
      SetField (field)
    | Some OFPAT_PUSH_PBB -> PushPbb
    | Some OFPAT_POP_PBB -> PopPbb
    | Some OFPAT_EXPERIMENTER -> Experimenter (get_ofp_action_experimenter_experimenter bits)
    | None -> failwith "None type"

  let rec parse_fields (bits : Cstruct.t) : sequence * Cstruct.t =
    if Cstruct.len bits < sizeof_ofp_action_header then ([], bits)
    else let field = parse bits in
      let bits2 = Cstruct.shift bits (sizeof field) in
      let fields, bits3 = parse_fields bits2 in
      (List.append [field] fields, bits3)

  let parse_sequence (bits : Cstruct.t) : sequence =
    let fields, _ = parse_fields bits in
    fields

end

module Bucket = struct

  type t = bucket

  let sizeof (bucket : bucket) : int =
    let n = sizeof_ofp_bucket + sum (List.map ~f:Action.sizeof bucket.bu_actions) in
    pad_to_64bits n

  let length_func (buf : Cstruct.t) : int option =
    if Cstruct.len buf < sizeof_ofp_bucket then None
    else Some (pad_to_64bits (get_ofp_bucket_len buf))

  let marshal (buf : Cstruct.t) (bucket : bucket) : int =
    let size = sizeof bucket in
    set_ofp_bucket_len buf size;
    set_ofp_bucket_weight buf bucket.bu_weight;
    set_ofp_bucket_watch_port buf
      (match bucket.bu_watch_port with
       | None -> ofpg_any
       | Some port -> port);
    set_ofp_bucket_watch_group buf
      (match bucket.bu_watch_group with
       | None -> ofpg_any
       | Some group_id -> group_id);
    set_ofp_bucket_pad0 buf 0;
    set_ofp_bucket_pad1 buf 0;
    set_ofp_bucket_pad2 buf 0;
    set_ofp_bucket_pad3 buf 0;
    let action_marshal buf act =
      match act with
      | Output Table ->
        failwith "OFPP_TABLE not allowed in installed flow"
      | _ -> Action.marshal buf act in
    let buf = Cstruct.shift buf sizeof_ofp_bucket in
    (sizeof_ofp_bucket + (marshal_fields buf bucket.bu_actions action_marshal))

  let parse (bits : Cstruct.t) : bucket =
    let len = get_ofp_bucket_len bits in
    let bu_weight = get_ofp_bucket_weight bits in
    let bu_watch_port = match get_ofp_bucket_watch_port bits with
      | 0xffffffffl -> None (* ofpp_any *)
      | n -> Some n in
    let bu_watch_group = match get_ofp_bucket_watch_group bits with
      | 0xffffffffl -> None (* ofpg_any *)
      | n -> Some n in
    let bu_actions = Action.parse_sequence (Cstruct.sub bits sizeof_ofp_bucket (len - sizeof_ofp_bucket)) in
    {bu_weight; bu_watch_port; bu_watch_group; bu_actions}
end

module FlowModCommand = struct

  type t = flowModCommand

  let n = ref 0L

  let sizeof _ = 1

  let marshal (t : t) : int = match t with
    | AddFlow -> n := Int64.succ !n; ofp_flow_mod_command_to_int OFPFC_ADD
    | ModFlow -> ofp_flow_mod_command_to_int OFPFC_MODIFY
    | ModStrictFlow -> ofp_flow_mod_command_to_int OFPFC_MODIFY_STRICT
    | DeleteFlow -> ofp_flow_mod_command_to_int OFPFC_DELETE
    | DeleteStrictFlow -> ofp_flow_mod_command_to_int OFPFC_DELETE_STRICT

  let parse bits : flowModCommand =
    match (int_to_ofp_flow_mod_command bits) with
    | Some OFPFC_ADD -> AddFlow
    | Some OFPFC_MODIFY -> ModFlow
    | Some OFPFC_MODIFY_STRICT -> ModStrictFlow
    | Some OFPFC_DELETE -> DeleteFlow
    | Some OFPFC_DELETE_STRICT -> DeleteStrictFlow
    | None -> raise (Unparsable (sprintf "malformed command"))

end

module GroupType = struct

  type t = groupType

  let n = ref 0L

  let marshal (t : t) : int = match t with
    | All -> ofp_group_type_to_int OFPGT_ALL
    | Select -> ofp_group_type_to_int OFPGT_SELECT
    | Indirect -> ofp_group_type_to_int OFPGT_INDIRECT
    | FF -> ofp_group_type_to_int OFPGT_FF

  let parse (bits : int) : t =
    match int_to_ofp_group_type bits with
    | Some OFPGT_ALL -> All
    | Some OFPGT_SELECT  -> Select
    | Some OFPGT_INDIRECT -> Indirect
    | Some OFPGT_FF  -> FF
    | None -> raise (Unparsable (sprintf "malformed ofp_group_type"))

end

module GroupMod = struct

  cenum ofp_group_mod_command {
    OFPGC_ADD = 0;
    OFPGC_MODIFY = 1;
    OFPGC_DELETE = 2
  } as uint16_t

  type t = groupMod

  let sizeof (gm: groupMod) : int =
    match gm with
    | AddGroup (typ, gid, buckets) ->
      sizeof_ofp_group_mod + sum (List.map ~f:Bucket.sizeof buckets)
    | DeleteGroup (typ, gid) ->
      sizeof_ofp_group_mod
    | ModifyGroup (typ, _, buckets) ->
      sizeof_ofp_group_mod + sum (List.map ~f:Bucket.sizeof buckets)

  let marshal (buf : Cstruct.t) (gm : groupMod) : int =
    match gm with
    | AddGroup (typ, gid, buckets) ->
      set_ofp_group_mod_command buf 0; (* OFPGC_ADD *)
      set_ofp_group_mod_typ buf (GroupType.marshal typ);
      set_ofp_group_mod_pad buf 0;
      set_ofp_group_mod_group_id buf gid;
      sizeof_ofp_group_mod + (marshal_fields (Cstruct.shift buf sizeof_ofp_group_mod) buckets Bucket.marshal)
    | DeleteGroup (typ, gid) ->
      set_ofp_group_mod_command buf 1; (* OFPGC_DEL *)
      set_ofp_group_mod_typ buf (GroupType.marshal typ);
      set_ofp_group_mod_pad buf 0;
      set_ofp_group_mod_group_id buf gid;
      sizeof_ofp_group_mod
    | ModifyGroup (typ, gid, buckets) ->
      set_ofp_group_mod_command buf 2; (* OFPGC_MODIFY *)
      set_ofp_group_mod_typ buf (GroupType.marshal typ);
      set_ofp_group_mod_pad buf 0;
      set_ofp_group_mod_group_id buf gid;
      sizeof_ofp_group_mod + (marshal_fields (Cstruct.shift buf sizeof_ofp_group_mod) buckets Bucket.marshal)

  let parse (bits : Cstruct.t) : groupMod =
    let typ = GroupType.parse (get_ofp_group_mod_typ bits) in
    let gid = get_ofp_group_mod_group_id bits in
    let command = get_ofp_group_mod_command bits in
    match int_to_ofp_group_mod_command command with
    | Some OFPGC_ADD ->
      let bucket = parse_fields (Cstruct.shift bits sizeof_ofp_group_mod) Bucket.parse (Bucket.length_func) in
      AddGroup (typ,gid,bucket)
    | Some OFPGC_MODIFY -> DeleteGroup (typ,gid)
    | Some OFPGC_DELETE ->
      let bucket = parse_fields (Cstruct.shift bits sizeof_ofp_group_mod) Bucket.parse (Bucket.length_func) in
      ModifyGroup (typ,gid,bucket)
    | None -> raise (Unparsable (sprintf "malformed group command"))
end

module PortMod = struct

  cstruct ofp_port_mod {
    uint32_t port_no;
    uint8_t pad[4];
    uint8_t hw_addr[6];
    uint8_t pad2[2];
    uint32_t config;
    uint32_t mask;
    uint32_t advertise;
    uint8_t pad3[4]
  } as big_endian

  type t = portMod

  let sizeof pm : int =
    sizeof_ofp_port_mod

  let marshal (buf : Cstruct.t) (pm : t) : int =
    set_ofp_port_mod_port_no buf pm.mpPortNo;
    set_ofp_port_mod_hw_addr (bytes_of_mac pm.mpHw_addr) 0 buf;
    set_ofp_port_mod_config buf (PortConfig.marshal pm.mpConfig);
    set_ofp_port_mod_mask buf (PortConfig.marshal pm.mpMask);
    set_ofp_port_mod_advertise buf (PortState.marshal pm.mpAdvertise);
    sizeof_ofp_port_mod

  let parse (bits : Cstruct.t) : t =
    let mpPortNo = get_ofp_port_mod_port_no bits in
    let mpHw_addr = mac_of_bytes (copy_ofp_port_mod_hw_addr bits) in
    let mpConfig = PortConfig.parse (get_ofp_port_mod_config bits) in
    let mpMask = PortConfig.parse (get_ofp_port_mod_mask bits) in
    let mpAdvertise = PortState.parse (get_ofp_port_mod_advertise bits) in
    { mpPortNo; mpHw_addr; mpConfig; mpMask; mpAdvertise}

end

module MeterBand = struct

  cenum ofp_meter_band_type {
    OFPMBT_DROP = 1;
    OFPMBT_DSCP_REMARK = 2;
    OFPMBT_EXPERIMENTER = 0xffff
  } as uint16_t

  type t = meterBand

  let sizeof (mb : meterBand) : int =
    match mb with
    | Drop _ -> sizeof_ofp_meter_band_drop
    | DscpRemark _ -> sizeof_ofp_meter_band_dscp_remark
    | ExpMeter _ ->  sizeof_ofp_meter_band_experimenter

  let length_fun (buf : Cstruct.t) : int option =
    if Cstruct.len buf < sizeof_ofp_meter_band_header then None
    else Some (get_ofp_meter_band_header_len buf)

  let marshal (buf : Cstruct.t) (mb : meterBand) : int =
    match mb with
    | Drop (r,b) ->
      set_ofp_meter_band_drop_typ buf 1; (* OFPMBT_DROP *)
      set_ofp_meter_band_drop_len buf sizeof_ofp_meter_band_drop;
      set_ofp_meter_band_drop_rate buf r;
      set_ofp_meter_band_drop_burst_size buf b;
      sizeof_ofp_meter_band_drop
    | DscpRemark (r,b,p) ->
      set_ofp_meter_band_dscp_remark_typ buf 2; (* OFPMBT_DSCP_REMARK *)
      set_ofp_meter_band_dscp_remark_len buf sizeof_ofp_meter_band_dscp_remark;
      set_ofp_meter_band_dscp_remark_rate buf r;
      set_ofp_meter_band_dscp_remark_burst_size buf b;
      set_ofp_meter_band_dscp_remark_prec_level buf p;
      sizeof_ofp_meter_band_dscp_remark
    | ExpMeter (r,b,e) ->
      set_ofp_meter_band_experimenter_typ buf 0xffff; (* OFPMBT_EXPERIMENTER *)
      set_ofp_meter_band_experimenter_len buf sizeof_ofp_meter_band_experimenter;
      set_ofp_meter_band_experimenter_rate buf r;
      set_ofp_meter_band_experimenter_burst_size buf b;
      set_ofp_meter_band_experimenter_experimenter buf e;
      sizeof_ofp_meter_band_experimenter

  let parse (bits : Cstruct.t) : meterBand =
    let rate = get_ofp_meter_band_header_rate bits in
    let burst = get_ofp_meter_band_header_burst_size bits in
    let typ = get_ofp_meter_band_header_typ bits in
    match int_to_ofp_meter_band_type typ with
    | Some OFPMBT_DROP ->
      Drop (rate,burst)
    | Some OFPMBT_DSCP_REMARK ->
      let p = get_ofp_meter_band_dscp_remark_prec_level bits in
      DscpRemark (rate,burst,p)
    | Some OFPMBT_EXPERIMENTER ->
      let e = get_ofp_meter_band_experimenter_experimenter bits in
      ExpMeter (rate,burst,e)
    | None -> raise (Unparsable (sprintf "malformed typ"))

end

module MeterFlags = struct

  let marshal (mfm : meterFlags) : int =
    (if mfm.kbps then 1 lsl 0 else 0) lor
    (if mfm.pktps then 1 lsl 1 else 0) lor
    (if mfm.burst then 1 lsl 2 else 0) lor
    (if mfm.stats then 1 lsl 3 else 0)

  let parse bits : meterFlags =
    { kbps = test_bit16 0 bits
    ; pktps = test_bit16 1 bits
    ; burst = test_bit16 2 bits
    ; stats = test_bit16 3 bits }

end

module MeterMod = struct

  cstruct ofp_meter_mod {
    uint16_t commands;
    uint16_t flags;
    uint32_t meter_id
  } as big_endian

  module Command = struct

    cenum ofp_meter_mod_command {
      OFPMC_ADD;
      OFPMC_MODIFY;
      OFPMC_DELETE
    } as uint16_t

    let marshal (t : meterCommand) : int =
      match t with
      | AddMeter -> ofp_meter_mod_command_to_int OFPMC_ADD
      | ModifyMeter -> ofp_meter_mod_command_to_int OFPMC_MODIFY
      | DeleteMeter -> ofp_meter_mod_command_to_int OFPMC_DELETE

    let parse t : meterCommand =
      match int_to_ofp_meter_mod_command t with
      | Some OFPMC_ADD -> AddMeter
      | Some OFPMC_MODIFY -> ModifyMeter
      | Some OFPMC_DELETE -> DeleteMeter
      | None -> raise (Unparsable (sprintf "malformed command"))
  end

  type t = meterMod

  let sizeof (mm : t) : int =
    sizeof_ofp_meter_mod + (sum (List.map ~f:MeterBand.sizeof mm.bands))

  let marshal (buf : Cstruct.t) (mm : t) : int =
    set_ofp_meter_mod_commands buf (Command.marshal mm.command);
    set_ofp_meter_mod_flags buf (MeterFlags.marshal mm.flags);
    set_ofp_meter_mod_meter_id buf mm.meter_id;
    sizeof_ofp_meter_mod + (marshal_fields (Cstruct.shift buf sizeof_ofp_meter_mod) mm.bands MeterBand.marshal)

  let parse (bits : Cstruct.t) : t =
    let command = Command.parse (get_ofp_meter_mod_commands bits) in
    let flags = MeterFlags.parse (get_ofp_meter_mod_flags bits) in
    let meter_id = get_ofp_meter_mod_meter_id bits in
    let bandsBits = Cstruct.shift bits sizeof_ofp_meter_mod in
    let bands = parse_fields bandsBits MeterBand.parse MeterBand.length_fun in
    { command; flags; meter_id; bands }

end

module Instruction = struct

  type t = instruction

  let sizeof (ins : t) : int =
    match ins with
    | GotoTable _ ->
      sizeof_ofp_instruction_goto_table
    | ApplyActions actions ->
      sizeof_ofp_instruction_actions + sum (List.map ~f:Action.sizeof actions)
    | WriteActions actions ->
      sizeof_ofp_instruction_actions + sum (List.map ~f:Action.sizeof actions)
    | WriteMetadata _ -> sizeof_ofp_instruction_write_metadata
    | Clear -> sizeof_ofp_instruction_actions
    | Meter _ -> sizeof_ofp_instruction_meter
    | Experimenter _ -> sizeof_ofp_instruction_experimenter

  let marshal (buf : Cstruct.t) (ins : t) : int =
    let size = sizeof ins in
    match ins with
    | GotoTable table_id ->
      set_ofp_instruction_goto_table_typ buf 1; (* OFPIT_GOTO_TABLE *)
      set_ofp_instruction_goto_table_len buf size;
      set_ofp_instruction_goto_table_table_id buf table_id;
      set_ofp_instruction_goto_table_pad0 buf 0;
      set_ofp_instruction_goto_table_pad1 buf 0;
      set_ofp_instruction_goto_table_pad2 buf 0;
      size
    | WriteActions actions ->
      set_ofp_instruction_actions_typ buf 3; (* OFPIT_WRITE_ACTIONS *)
      set_ofp_instruction_actions_len buf size;
      set_ofp_instruction_actions_pad0 buf 0;
      set_ofp_instruction_actions_pad1 buf 0;
      set_ofp_instruction_actions_pad2 buf 0;
      set_ofp_instruction_actions_pad3 buf 0;
      sizeof_ofp_instruction_actions + (
        marshal_fields
          (Cstruct.shift buf sizeof_ofp_instruction_actions)
          actions
          Action.marshal)
    | ApplyActions actions ->
      set_ofp_instruction_actions_typ buf 4; (* OFPIT_APPLY_ACTIONS *)
      set_ofp_instruction_actions_len buf size;
      set_ofp_instruction_actions_pad0 buf 0;
      set_ofp_instruction_actions_pad1 buf 0;
      set_ofp_instruction_actions_pad2 buf 0;
      set_ofp_instruction_actions_pad3 buf 0;
      sizeof_ofp_instruction_actions + (marshal_fields (Cstruct.shift buf sizeof_ofp_instruction_actions) actions Action.marshal)
    | WriteMetadata metadata ->
      set_ofp_instruction_write_metadata_typ buf 2; (* OFPIT_WRITE_METADATA *)
      set_ofp_instruction_write_metadata_len buf size;
      set_ofp_instruction_write_metadata_pad0 buf 0;
      set_ofp_instruction_write_metadata_pad1 buf 0;
      set_ofp_instruction_write_metadata_pad2 buf 0;
      set_ofp_instruction_write_metadata_pad3 buf 0;
      set_ofp_instruction_write_metadata_metadata buf metadata.m_value;
      set_ofp_instruction_write_metadata_metadata_mask buf (
        match metadata.m_mask with
        | None -> 0L
        | Some mask -> mask);
      size
    | Clear ->
      set_ofp_instruction_actions_typ buf 5; (* OFPIT_CLEAR_ACTIONS *)
      set_ofp_instruction_actions_len buf size;
      set_ofp_instruction_actions_pad0 buf 0;
      set_ofp_instruction_actions_pad1 buf 0;
      set_ofp_instruction_actions_pad2 buf 0;
      set_ofp_instruction_actions_pad3 buf 0;
      size
    | Meter meterId->
      set_ofp_instruction_meter_typ buf 6; (* OFPIT_METER *)
      set_ofp_instruction_meter_len buf size;
      set_ofp_instruction_meter_meter_id buf meterId;
      size
    | Experimenter experimenterId->
      set_ofp_instruction_experimenter_typ buf 0xffff; (* OFPIT_EXPERIMENTER *)
      set_ofp_instruction_experimenter_len buf size;
      set_ofp_instruction_experimenter_experimenter buf experimenterId;
      size


  let parse (bits : Cstruct.t) : t =
    let typ = get_ofp_instruction_typ bits in
    let len = get_ofp_instruction_len bits in
    match (int_to_ofp_instruction_type typ) with
    | Some OFPIT_GOTO_TABLE -> GotoTable (
        get_ofp_instruction_goto_table_table_id bits)
    | Some OFPIT_WRITE_METADATA ->
      let value = get_ofp_instruction_write_metadata_metadata bits in
      let mask = get_ofp_instruction_write_metadata_metadata_mask bits in
      if mask <> 0L then
        WriteMetadata ({m_value = value; m_mask = Some mask})
      else
        WriteMetadata ({m_value = value; m_mask = None})
    | Some OFPIT_WRITE_ACTIONS -> WriteActions (
        Action.parse_sequence (Cstruct.sub bits sizeof_ofp_instruction_actions (len-sizeof_ofp_instruction_actions)))
    | Some OFPIT_APPLY_ACTIONS -> ApplyActions (
        Action.parse_sequence (Cstruct.sub bits sizeof_ofp_instruction_actions (len-sizeof_ofp_instruction_actions)))
    | Some OFPIT_CLEAR_ACTIONS -> Clear
    | Some OFPIT_METER -> Meter (get_ofp_instruction_meter_meter_id bits)
    | Some OFPIT_EXPERIMENTER -> Experimenter (
        get_ofp_instruction_experimenter_experimenter bits)
    | _ -> raise (Unparsable (sprintf "Unkown instruction message"))

end

module Instructions = struct

  type t = instruction list

  let sizeof (inss : t) : int =
    sum (List.map ~f:Instruction.sizeof inss)

  let marshal (buf : Cstruct.t) (inss : t) : int =
    if sizeof inss <> 0 then
      marshal_fields buf inss Instruction.marshal
    else 0

  let rec parse_field (bits : Cstruct.t) : t * Cstruct.t =
    if Cstruct.len bits < sizeof_ofp_instruction then [],bits
    else let field = Instruction.parse bits in
      let bits2 = Cstruct.shift bits (Instruction.sizeof field) in
      let fields, bits3 = parse_field bits2 in
      (List.append [field] fields, bits3)

  let parse (bits : Cstruct.t) : t =
    let field,_ = parse_field bits in
    field

end

module FlowMod = struct

  type t = flowMod

  let sizeof (fm : t) =
    sizeof_ofp_flow_mod + (OfpMatch.sizeof fm.mfOfp_match) + (Instructions.sizeof fm.mfInstructions)

  module Flags = struct

    let marshal (f : flowModFlags) =
      (if f.fmf_send_flow_rem then 1 lsl 0 else 0) lor
      (if f.fmf_check_overlap then 1 lsl 1 else 0) lor
      (if f.fmf_reset_counts then 1 lsl 2 else 0) lor
      (if f.fmf_no_pkt_counts then 1 lsl 3 else 0) lor
      (if f.fmf_no_byt_counts then 1 lsl 4 else 0)

    let parse bits : flowModFlags =
      { fmf_send_flow_rem = test_bit16  0 bits
      ; fmf_check_overlap = test_bit16  1 bits
      ; fmf_reset_counts = test_bit16  2 bits
      ; fmf_no_pkt_counts = test_bit16  3 bits
      ; fmf_no_byt_counts = test_bit16  4 bits
      }

  end

  let marshal (buf : Cstruct.t) (fm : t) : int =
    set_ofp_flow_mod_cookie buf fm.mfCookie.m_value;
    set_ofp_flow_mod_cookie_mask buf (
      match fm.mfCookie.m_mask with
      | None -> 0L
      | Some mask -> mask);
    set_ofp_flow_mod_table_id buf fm.mfTable_id;
    set_ofp_flow_mod_command buf (FlowModCommand.marshal fm.mfCommand);
    set_ofp_flow_mod_idle_timeout buf
      (match fm.mfIdle_timeout with
       | Permanent -> 0
       | ExpiresAfter value -> value);
    set_ofp_flow_mod_hard_timeout buf
      (match fm.mfHard_timeout with
       | Permanent -> 0
       | ExpiresAfter value -> value);
    set_ofp_flow_mod_priority buf fm.mfPriority;
    set_ofp_flow_mod_buffer_id buf
      (match fm.mfBuffer_id with
       | None -> ofp_no_buffer
       | Some bid -> bid);
    set_ofp_flow_mod_out_port buf
      (match fm.mfOut_port with
       | None -> 0l
       | Some port -> PseudoPort.marshal port);
    set_ofp_flow_mod_out_group buf
      (match fm.mfOut_group with
       | None -> 0l
       | Some gid -> gid);
    set_ofp_flow_mod_flags buf (Flags.marshal fm.mfFlags);
    set_ofp_flow_mod_pad0 buf 0;
    set_ofp_flow_mod_pad1 buf 0;

    let size = sizeof_ofp_flow_mod +
               OfpMatch.marshal
                 (Cstruct.sub buf sizeof_ofp_flow_mod (OfpMatch.sizeof fm.mfOfp_match))
                 fm.mfOfp_match in
    size + Instructions.marshal (Cstruct.shift buf size) fm.mfInstructions

  let parse (bits : Cstruct.t) : t =
    let mfMask = get_ofp_flow_mod_cookie_mask bits in
    let mfCookie =
      if mfMask <> 0L then
        {m_value = get_ofp_flow_mod_cookie bits;
         m_mask = (Some (get_ofp_flow_mod_cookie_mask bits))}
      else {m_value = get_ofp_flow_mod_cookie bits;
            m_mask = None}
    in
    let mfTable_id = get_ofp_flow_mod_table_id bits in
    let mfCommand = FlowModCommand.parse (get_ofp_flow_mod_command bits) in
    let mfIdle_timeout = match (get_ofp_flow_mod_idle_timeout bits) with
      | 0 -> Permanent
      | n -> ExpiresAfter n in
    let mfHard_timeout = match (get_ofp_flow_mod_hard_timeout bits) with
      | 0 -> Permanent
      | n -> ExpiresAfter n in
    let mfPriority = get_ofp_flow_mod_priority bits in
    let mfBuffer_id = match (get_ofp_flow_mod_buffer_id bits) with
      | 0xffffffffl -> None
      | n -> Some n in
    let mfOut_port = match (get_ofp_flow_mod_out_port bits) with
      | 0l -> None
      | _ -> Some (PseudoPort.make (get_ofp_flow_mod_out_port bits) 0) in
    let mfOut_group = match (get_ofp_flow_mod_out_group bits) with
      | 0l -> None
      | n -> Some n in
    let mfFlags = Flags.parse (get_ofp_flow_mod_flags bits) in
    let mfOfp_match,instructionsBits = OfpMatch.parse (Cstruct.shift bits sizeof_ofp_flow_mod) in
    let mfInstructions = Instructions.parse instructionsBits in
    { mfCookie; mfTable_id;
      mfCommand; mfIdle_timeout;
      mfHard_timeout; mfPriority;
      mfBuffer_id;
      mfOut_port;
      mfOut_group; mfFlags;
      mfOfp_match; mfInstructions}

end

module Capabilities = struct

  type t = capabilities

  let to_int32 (capa : t) : int32 =
    Int32.bit_or (if capa.flow_stats then (Int32.shift_left 1l 0) else 0l)
      (Int32.bit_or (if capa.table_stats then (Int32.shift_left 1l 1) else 0l)
         (Int32.bit_or (if capa.port_stats then (Int32.shift_left 1l 2) else 0l)
            (Int32.bit_or (if capa.group_stats then (Int32.shift_left 1l 3) else 0l)
               (Int32.bit_or (if capa.ip_reasm then (Int32.shift_left 1l 5) else 0l)
                  (Int32.bit_or (if capa.queue_stats then (Int32.shift_left 1l 6) else 0l)
                     (if capa.port_blocked then (Int32.shift_left 1l 8) else 0l))))))

  let parse (bits : int32) : t =
    { port_blocked = Frenetic_Bits.test_bit 8 bits;
      queue_stats = Frenetic_Bits.test_bit 6 bits;
      ip_reasm = Frenetic_Bits.test_bit 5 bits;
      group_stats = Frenetic_Bits.test_bit 3 bits;
      port_stats = Frenetic_Bits.test_bit 2 bits;
      table_stats = Frenetic_Bits.test_bit 1 bits;
      flow_stats = Frenetic_Bits.test_bit 0 bits;
    }

end

module SwitchFeatures = struct

  type t = switchFeatures

  let sizeof (sw : t) : int =
    sizeof_ofp_switch_features

  let marshal (buf : Cstruct.t) (features : t) : int =
    set_ofp_switch_features_datapath_id buf features.datapath_id;
    set_ofp_switch_features_n_buffers buf features.num_buffers;
    set_ofp_switch_features_n_tables buf features.num_tables;
    set_ofp_switch_features_auxiliary_id buf features.aux_id;
    set_ofp_switch_features_pad0 buf 0;
    set_ofp_switch_features_pad1 buf 0;
    set_ofp_switch_features_capabilities buf (Capabilities.to_int32 features.supported_capabilities);
    sizeof_ofp_switch_features

  let parse (bits : Cstruct.t) : t =
    let datapath_id = get_ofp_switch_features_datapath_id bits in
    let num_buffers = get_ofp_switch_features_n_buffers bits in
    let num_tables = get_ofp_switch_features_n_tables bits in
    let aux_id = get_ofp_switch_features_auxiliary_id bits in
    let supported_capabilities = Capabilities.parse
        (get_ofp_switch_features_capabilities bits) in
    { datapath_id;
      num_buffers;
      num_tables;
      aux_id;
      supported_capabilities }

end

module PortDesc = struct

  type t = portDesc

  let sizeof (_ : t) =
    sizeof_ofp_port

  let marshal (buf : Cstruct.t) (desc : t) : int =
    let size = sizeof_ofp_port in
    set_ofp_port_port_no buf desc.port_no;
    set_ofp_port_pad buf 0l;
    set_ofp_port_hw_addr (bytes_of_mac desc.hw_addr) 0 buf;
    set_ofp_port_pad2 buf 0;
    set_ofp_port_pad3 buf 0;
    set_ofp_port_name desc.name 0 buf;
    set_ofp_port_config buf (PortConfig.marshal desc.config);
    set_ofp_port_state buf (PortState.marshal desc.state);
    set_ofp_port_curr buf (PortFeatures.marshal desc.curr);
    set_ofp_port_advertised buf (PortFeatures.marshal desc.advertised);
    set_ofp_port_supported buf (PortFeatures.marshal desc.supported);
    set_ofp_port_peer buf (PortFeatures.marshal desc.peer);
    set_ofp_port_curr_speed buf desc.curr_speed;
    set_ofp_port_max_speed buf desc.max_speed;
    size

  let parse (bits : Cstruct.t) : t =
    let port_no = get_ofp_port_port_no bits in
    let hw_addr = mac_of_bytes (copy_ofp_port_hw_addr bits) in
    let name = copy_ofp_port_name bits in
    let state = PortState.parse (get_ofp_port_state bits) in
    let config = PortConfig.parse (get_ofp_port_config bits) in
    let curr = PortFeatures.parse (get_ofp_port_curr bits) in
    let advertised = PortFeatures.parse (get_ofp_port_advertised bits) in
    let supported = PortFeatures.parse (get_ofp_port_supported bits) in
    let peer = PortFeatures.parse (get_ofp_port_peer bits) in
    let curr_speed = get_ofp_port_curr_speed bits in
    let max_speed = get_ofp_port_max_speed bits in
    { port_no;
      hw_addr;
      name;
      config;
      state;
      curr;
      advertised;
      supported;
      peer;
      curr_speed;
      max_speed }

  let length_func = (fun buf -> Some sizeof_ofp_port)
end

module PortStatus = struct

  type t = portStatus

  let sizeof (_ : t) : int =
    sizeof_ofp_port_status + sizeof_ofp_port

  module Reason = struct

    let marshal (pr : portReason) : int =
      match pr with
      | PortAdd -> ofp_port_reason_to_int OFPPR_ADD
      | PortDelete -> ofp_port_reason_to_int OFPPR_DELETE
      | PortModify -> ofp_port_reason_to_int OFPPR_MODIFY

    let parse t : portReason =
      match int_to_ofp_port_reason t with
      | Some OFPPR_ADD -> PortAdd
      | Some OFPPR_DELETE -> PortDelete
      | Some OFPPR_MODIFY -> PortModify
      | None -> raise (Unparsable (sprintf "unexpected port reason"))
  end

  let marshal (buf : Cstruct.t) (status : t) : int =
    set_ofp_port_status_reason buf (Reason.marshal status.reason);
    let size = sizeof_ofp_port_status +
               PortDesc.marshal (Cstruct.shift buf sizeof_ofp_port_status) status.desc in
    size

  let parse (bits : Cstruct.t) : t =
    let reason = Reason.parse (get_ofp_port_status_reason bits)in
    let bits = Cstruct.shift bits sizeof_ofp_port_status in
    let desc = PortDesc.parse bits in
    { reason;
      desc }
end

module PacketIn = struct

  type t = packetIn

  module Reason = struct

    cenum ofp_packet_in_reason {
      NO_MATCH = 0;
      ACTION = 1;
      INVALID_TTL = 2
    } as uint8_t

    type t = packetInReason

    let marshal t : int =
      match t with
      | NoMatch -> ofp_packet_in_reason_to_int NO_MATCH
      | ExplicitSend -> ofp_packet_in_reason_to_int ACTION
      | InvalidTTL -> ofp_packet_in_reason_to_int INVALID_TTL

    let parse t : packetInReason =
      match int_to_ofp_packet_in_reason t with
      | Some NO_MATCH -> NoMatch
      | Some ACTION -> ExplicitSend
      | Some INVALID_TTL -> InvalidTTL
      | None -> raise (Unparsable (sprintf "bad reason in packet_in (%d)" t))
  end

    cstruct ofp_packet_in {
    uint32_t buffer_id;
    uint16_t total_len;
    uint8_t reason;
    uint8_t table_id;
    uint64_t cookie
  } as big_endian

  let sizeof (pi : t) : int =
    pi.pi_total_len + (OfpMatch.sizeof pi.pi_ofp_match) + sizeof_ofp_packet_in + 2 (*2 bytes of pad*)

  let marshal (buf : Cstruct.t) (pi : t) : int =
    let bufMatch = Cstruct.shift buf sizeof_ofp_packet_in in
    let size = pi.pi_total_len + (OfpMatch.marshal bufMatch pi.pi_ofp_match) +
               sizeof_ofp_packet_in in
    let buffer_id,bytes = match pi.pi_payload with
      | Buffered (n,bytes) -> n, bytes
      | NotBuffered bytes -> -1l, bytes in
    set_ofp_uint8_value (Cstruct.shift bufMatch (OfpMatch.sizeof pi.pi_ofp_match)) 0; (*pad*)
    set_ofp_uint8_value (Cstruct.shift bufMatch (OfpMatch.sizeof pi.pi_ofp_match + 1)) 0; (*pad*)
    Cstruct.blit bytes 0 bufMatch (2 + OfpMatch.sizeof pi.pi_ofp_match) pi.pi_total_len;
    set_ofp_packet_in_buffer_id buf buffer_id;
    set_ofp_packet_in_total_len buf pi.pi_total_len;
    set_ofp_packet_in_reason buf (Reason.marshal pi.pi_reason);
    set_ofp_packet_in_table_id buf pi.pi_table_id;
    set_ofp_packet_in_cookie buf pi.pi_cookie;
    size

  let parse (bits : Cstruct.t) : t =
    (* let oc = open_out "test-msg-1.3-msg3-bits" in *)
    (* let str = Cstruct.to_string bits in *)
    (* fprintf oc "%s" str; *)
    (* close_out oc; *)
    let bufId = match get_ofp_packet_in_buffer_id bits with
      | -1l -> None
      | n -> Some n in
    let total_len = get_ofp_packet_in_total_len bits in
    let reason_code = get_ofp_packet_in_reason bits in
    let reason = Reason.parse (reason_code) in
    let table_id = get_ofp_packet_in_table_id bits in
    let cookie = get_ofp_packet_in_cookie bits in
    let ofp_match_bits = Cstruct.shift bits sizeof_ofp_packet_in in
    let ofp_match, pkt_bits = OfpMatch.parse ofp_match_bits in
    let pkt_bits = Cstruct.sub pkt_bits 2 total_len in (* pad bytes *)
    let final_bits = Cstruct.create total_len in
    (* create a new Cstruct to set the offset to 0 *)
    Cstruct.blit pkt_bits 0 final_bits 0 total_len;
    (* printf "len = %d\n" (Cstruct.len pkt_bits); *)
    let pkt = match bufId with
      | None -> NotBuffered final_bits
      | Some n -> Buffered (n,final_bits)
    in
    { pi_total_len = total_len;
      pi_reason = reason;
      pi_table_id = table_id;
      pi_cookie = cookie;
      pi_ofp_match = ofp_match;
      pi_payload = pkt
    }

end

module PacketOut = struct

  cstruct ofp_packet_out {
    uint32_t buffer_id;           (* ID assigned by datapath (OFP_NO_BUFFER
                                     if none). *)
    uint32_t in_port;             (* Packet's input port or OFPP_CONTROLLER. *)
    uint16_t actions_len;         (* Size of action array in bytes. *)
    uint8_t pad0;
    uint8_t pad1;
    uint8_t pad2;
    uint8_t pad3;
    uint8_t pad4;
    uint8_t pad5
    (* struct ofp_action_header actions[0]; *) (* Action list. *)
    (* uint8_t data[0]; *)        (* Packet data.  The length is inferred
                                     from the length field in the header.
                                     (Only meaningful if buffer_id == -1.) *)
  } as big_endian

  type t = packetOut

  let sizeof (po : t) =
    sizeof_ofp_packet_out + sum (List.map ~f:Action.sizeof po.po_actions) +
    (match po.po_payload with
     | Buffered _ -> 0
     | NotBuffered bytes -> Cstruct.len bytes)

  let marshal (buf : Cstruct.t) (po : t) : int =
    let size = sizeof po in
    set_ofp_packet_out_buffer_id buf (
      match po.po_payload with
      | NotBuffered _ -> 0xffffffffl
      | Buffered (buffer_id, _) -> buffer_id);
    set_ofp_packet_out_in_port buf
      (match po.po_port_id with
       | None -> 0l
       | Some(port_id) -> port_id);
    set_ofp_packet_out_actions_len buf (sum (List.map ~f:Action.sizeof po.po_actions));
    set_ofp_packet_out_pad0 buf 0;
    set_ofp_packet_out_pad1 buf 0;
    set_ofp_packet_out_pad2 buf 0;
    set_ofp_packet_out_pad3 buf 0;
    set_ofp_packet_out_pad4 buf 0;
    set_ofp_packet_out_pad5 buf 0;
    let buf = Cstruct.shift buf sizeof_ofp_packet_out in
    let act_size = marshal_fields buf po.po_actions Action.marshal in
    match po.po_payload with
    | Buffered _ -> size
    | NotBuffered pkt_buf ->
      Cstruct.blit pkt_buf 0 buf act_size (Cstruct.len pkt_buf);
      size

  let parse (bits : Cstruct.t) : t =
    let bufId = match get_ofp_packet_out_buffer_id bits with
      | -1l -> None
      | n -> Some n in
    let po_port_id = match get_ofp_packet_out_in_port bits with
      | 0l -> None
      | n -> Some n in
    let actions_size = get_ofp_packet_out_actions_len bits in
    let bits = Cstruct.shift bits sizeof_ofp_packet_out in
    let po_actions = Action.parse_sequence (Cstruct.sub bits 0 actions_size) in
    let po_payload = match bufId with
      | None ->
        let data_bits = Cstruct.shift bits actions_size in
        let final_bits = Cstruct.create (Cstruct.len data_bits) in
        Cstruct.blit data_bits 0 final_bits 0 (Cstruct.len data_bits);
        NotBuffered final_bits
      | Some n ->
        let final_bits = Cstruct.create 0 in
        Buffered (n,final_bits) in
    { po_payload; po_port_id; po_actions }

end

module FlowRemoved = struct

  module RemovedReason = struct

    cenum ofp_flow_removed_reason {
      OFPRR_IDLE_TIMEOUT = 0;
      OFPRR_HARD_TIMEOUT = 1;
      OFPRR_DELETE = 2;
      OFPRR_GROUP_DELETE = 3
    } as uint8_t

    type t = flowReason

    let marshal (t : flowReason) : int8 =
      match t with
      | FlowIdleTimeout -> ofp_flow_removed_reason_to_int OFPRR_IDLE_TIMEOUT
      | FlowHardTiemout -> ofp_flow_removed_reason_to_int OFPRR_HARD_TIMEOUT
      | FlowDelete -> ofp_flow_removed_reason_to_int OFPRR_DELETE
      | FlowGroupDelete -> ofp_flow_removed_reason_to_int OFPRR_GROUP_DELETE

    let parse bits : flowReason =
      match (int_to_ofp_flow_removed_reason bits) with
      | Some OFPRR_IDLE_TIMEOUT -> FlowIdleTimeout
      | Some OFPRR_HARD_TIMEOUT -> FlowHardTiemout
      | Some OFPRR_DELETE -> FlowDelete
      | Some OFPRR_GROUP_DELETE -> FlowGroupDelete
      | None -> raise (Unparsable (sprintf "malformed reason"))

  end

    cstruct ofp_flow_removed {
    uint64_t cookie;
    uint16_t priority;
    uint8_t reason;
    uint8_t table_id;
    uint32_t duration_sec;
    uint32_t duration_nsec;
    uint16_t idle_timeout;
    uint16_t hard_timeout;
    uint64_t packet_count;
    uint64_t byte_count
  } as big_endian

  type t = flowRemoved

  let sizeof (f : flowRemoved) : int =
    sizeof_ofp_flow_removed + (OfpMatch.sizeof f.oxm)

  let marshal (buf : Cstruct.t) (f : flowRemoved) : int =
    set_ofp_flow_removed_cookie buf f.cookie;
    set_ofp_flow_removed_priority buf f.priority;
    set_ofp_flow_removed_reason buf (RemovedReason.marshal f.reason);
    set_ofp_flow_removed_table_id buf f.table_id;
    set_ofp_flow_removed_duration_sec buf f.duration_sec;
    set_ofp_flow_removed_duration_nsec buf f.duration_nsec;
    set_ofp_flow_removed_idle_timeout buf (match f.idle_timeout with
        | Permanent -> 0
        | ExpiresAfter v -> v);
    set_ofp_flow_removed_hard_timeout buf (match f.hard_timeout with
        | Permanent -> 0
        | ExpiresAfter v -> v);
    set_ofp_flow_removed_packet_count buf f.packet_count;
    set_ofp_flow_removed_byte_count buf f.byte_count;
    let oxm_buf = Cstruct.shift buf sizeof_ofp_flow_removed in
    sizeof_ofp_flow_removed + (OfpMatch.marshal oxm_buf f.oxm)

  let parse (bits : Cstruct.t) : flowRemoved =
    let cookie = get_ofp_flow_removed_cookie bits in
    let priority = get_ofp_flow_removed_priority bits in
    let reason = RemovedReason.parse (get_ofp_flow_removed_reason bits) in
    let table_id = get_ofp_flow_removed_table_id bits in
    let duration_sec = get_ofp_flow_removed_duration_sec bits in
    let duration_nsec = get_ofp_flow_removed_duration_nsec bits in
    let idle_timeout = match (get_ofp_flow_removed_idle_timeout bits) with
      | 0 -> Permanent
      | n -> ExpiresAfter n in
    let hard_timeout = match (get_ofp_flow_removed_hard_timeout bits) with
      | 0 -> Permanent
      | n -> ExpiresAfter n in
    let packet_count = get_ofp_flow_removed_packet_count bits in
    let byte_count = get_ofp_flow_removed_byte_count bits in
    let oxm,_ = OfpMatch.parse (Cstruct.shift bits sizeof_ofp_flow_removed) in
    { cookie; priority; reason; table_id; duration_sec; duration_nsec; idle_timeout;
      hard_timeout; packet_count; byte_count; oxm }


end

module FlowRequest = struct

  cstruct ofp_flow_stats_request {
    uint8_t table_id;
    uint8_t pad[3];
    uint32_t out_port;
    uint32_t out_group;
    uint8_t pad2[4];
    uint64_t cookie;
    uint64_t cookie_mask;
  } as big_endian

  type t = flowRequest

  let sizeof (fr : flowRequest) : int =
    sizeof_ofp_flow_stats_request + (OfpMatch.sizeof fr.fr_match)

  let marshal (buf : Cstruct.t) (fr : flowRequest) : int =
    set_ofp_flow_stats_request_table_id buf fr.fr_table_id;
    set_ofp_flow_stats_request_out_port buf fr.fr_out_port;
    set_ofp_flow_stats_request_out_group buf fr.fr_out_group;
    set_ofp_flow_stats_request_cookie buf fr.fr_cookie.m_value;
    set_ofp_flow_stats_request_cookie_mask buf (
      match fr.fr_cookie.m_mask with
      | None -> 0L
      | Some mask -> mask);
    sizeof_ofp_flow_stats_request + (OfpMatch.marshal
                                       (Cstruct.shift buf sizeof_ofp_flow_stats_request) fr.fr_match)


  let parse (bits : Cstruct.t) : flowRequest =
    let tableId = get_ofp_flow_stats_request_table_id bits in
    let out_port = get_ofp_flow_stats_request_out_port bits in
    let out_group = get_ofp_flow_stats_request_out_group bits in
    let cookie = get_ofp_flow_stats_request_cookie bits in
    let mask = get_ofp_flow_stats_request_cookie_mask bits in
    let fr_cookie = match mask with
      | 0L -> {m_value = cookie; m_mask = None}
      | n -> {m_value = cookie; m_mask = Some n} in
    let oxmMatch,_ = OfpMatch.parse (Cstruct.shift bits sizeof_ofp_flow_stats_request) in
    { fr_table_id = tableId
    ; fr_out_port = out_port
    ; fr_out_group = out_group
    ; fr_cookie = fr_cookie
    ; fr_match = oxmMatch}

end

module QueueRequest = struct

  type t = queueRequest

  let marshal (buf : Cstruct.t) (qr : t) : int =
    set_ofp_queue_stats_request_port_no buf qr.port_number;
    set_ofp_queue_stats_request_queue_id buf qr.queue_id;
    sizeof_ofp_queue_stats_request

  let parse (bits : Cstruct.t) : t =
    let portNumber = get_ofp_queue_stats_request_port_no bits in
    let queueId = get_ofp_queue_stats_request_queue_id bits in
    { port_number = portNumber
    ; queue_id = queueId}

  let sizeof _ =
    sizeof_ofp_queue_stats_request

end

module InstructionHdr = struct
  (* Same as Instruction, but only on ofp_instruction, without additional payload *)
  type t = instructionHdr

  let sizeof (ins : t) =
    match ins with
    | GotoTableHdr
    | ApplyActionsHdr
    | WriteActionsHdr
    | WriteMetadataHdr
    | ClearHdr
    | MeterHdr -> 4
    | ExperimenterHdr _ ->  8

  let marshal (buf : Cstruct.t) (ins : t) : int =
    match ins with
    | GotoTableHdr ->
      set_ofp_instruction_typ buf (ofp_instruction_type_to_int OFPIT_GOTO_TABLE);
      set_ofp_instruction_len buf 4;
      sizeof_ofp_instruction
    | ApplyActionsHdr ->
      set_ofp_instruction_typ buf (ofp_instruction_type_to_int OFPIT_APPLY_ACTIONS);
      set_ofp_instruction_len buf 4;
      sizeof_ofp_instruction
    | WriteActionsHdr ->
      set_ofp_instruction_typ buf (ofp_instruction_type_to_int OFPIT_WRITE_ACTIONS);
      set_ofp_instruction_len buf 4;
      sizeof_ofp_instruction
    | WriteMetadataHdr ->
      set_ofp_instruction_typ buf (ofp_instruction_type_to_int OFPIT_WRITE_METADATA);
      set_ofp_instruction_len buf 4;
      sizeof_ofp_instruction
    | ClearHdr ->
      set_ofp_instruction_typ buf (ofp_instruction_type_to_int OFPIT_CLEAR_ACTIONS);
      set_ofp_instruction_len buf 4;
      sizeof_ofp_instruction
    | MeterHdr ->
      set_ofp_instruction_typ buf (ofp_instruction_type_to_int OFPIT_METER);
      set_ofp_instruction_len buf 4;
      sizeof_ofp_instruction
    | ExperimenterHdr e ->
      set_ofp_instruction_typ buf (ofp_instruction_type_to_int OFPIT_EXPERIMENTER);
      set_ofp_instruction_len buf 8;
      set_ofp_instruction_experimenter_experimenter buf e;
      sizeof_ofp_instruction_experimenter

  let parse (bits : Cstruct.t) : t =
    let typ = int_to_ofp_instruction_type (get_ofp_instruction_typ bits) in
    match typ with
    | Some OFPIT_GOTO_TABLE -> GotoTableHdr
    | Some OFPIT_APPLY_ACTIONS -> ApplyActionsHdr
    | Some OFPIT_WRITE_ACTIONS -> WriteActionsHdr
    | Some OFPIT_WRITE_METADATA -> WriteMetadataHdr
    | Some OFPIT_CLEAR_ACTIONS -> ClearHdr
    | Some OFPIT_METER -> MeterHdr
    | Some OFPIT_EXPERIMENTER -> ExperimenterHdr (get_ofp_instruction_experimenter_experimenter bits)
    | None -> raise (Unparsable (sprintf "malfomed typ"))

  let length_func (buf : Cstruct.t) : int option =
    if Cstruct.len buf < sizeof_ofp_instruction then None
    else Some (get_ofp_instruction_len buf)

end

module ActionHdr = struct
  (* Same as Action, but only on ofp_action_header, without additional payload  *)
  type t = actionHdr

  let sizeof (act : t) =
    match act with
    | OutputHdr
    | GroupHdr
    | PopVlanHdr
    | PushVlanHdr
    | PopMplsHdr
    | PushMplsHdr
    | SetFieldHdr
    | CopyTtlOutHdr
    | CopyTtlInHdr
    | SetNwTtlHdr
    | DecNwTtlHdr
    | PushPbbHdr
    | PopPbbHdr
    | SetMplsTtlHdr
    | DecMplsTtlHdr
    | SetQueueHdr -> 4
    | ExperimenterAHdr _ -> 8

  let marshal (buf : Cstruct.t) (act : t) : int =
    match act with
    | OutputHdr ->
      set_ofp_action_header_typ buf (ofp_action_type_to_int OFPAT_OUTPUT);
      set_ofp_action_header_len buf 4;
      4 (* ofp_action_header without the padding *)
    | CopyTtlOutHdr ->
      set_ofp_action_header_typ buf (ofp_action_type_to_int OFPAT_COPY_TTL_OUT);
      set_ofp_action_header_len buf 4;
      4
    | CopyTtlInHdr ->
      set_ofp_action_header_typ buf (ofp_action_type_to_int OFPAT_COPY_TTL_IN);
      set_ofp_action_header_len buf 4;
      4
    | SetMplsTtlHdr ->
      set_ofp_action_header_typ buf (ofp_action_type_to_int OFPAT_SET_MPLS_TTL);
      set_ofp_action_header_len buf 4;
      4
    | DecMplsTtlHdr ->
      set_ofp_action_header_typ buf (ofp_action_type_to_int OFPAT_DEC_MPLS_TTL);
      set_ofp_action_header_len buf 4;
      4
    | PushVlanHdr ->
      set_ofp_action_header_typ buf (ofp_action_type_to_int OFPAT_PUSH_VLAN);
      set_ofp_action_header_len buf 4;
      4
    | PopVlanHdr ->
      set_ofp_action_header_typ buf (ofp_action_type_to_int OFPAT_POP_VLAN);
      set_ofp_action_header_len buf 4;
      4
    | PushMplsHdr ->
      set_ofp_action_header_typ buf (ofp_action_type_to_int OFPAT_PUSH_MPLS);
      set_ofp_action_header_len buf 4;
      4
    | PopMplsHdr ->
      set_ofp_action_header_typ buf (ofp_action_type_to_int OFPAT_POP_MPLS);
      set_ofp_action_header_len buf 4;
      4
    | SetQueueHdr ->
      set_ofp_action_header_typ buf (ofp_action_type_to_int OFPAT_SET_QUEUE);
      set_ofp_action_header_len buf 4;
      4
    | GroupHdr ->
      set_ofp_action_header_typ buf (ofp_action_type_to_int OFPAT_GROUP);
      set_ofp_action_header_len buf 4;
      4
    | SetNwTtlHdr ->
      set_ofp_action_header_typ buf (ofp_action_type_to_int OFPAT_SET_NW_TTL);
      set_ofp_action_header_len buf 4;
      4
    | DecNwTtlHdr ->
      set_ofp_action_header_typ buf (ofp_action_type_to_int OFPAT_DEC_NW_TTL);
      set_ofp_action_header_len buf 4;
      4
    | SetFieldHdr ->
      set_ofp_action_header_typ buf (ofp_action_type_to_int OFPAT_SET_FIELD);
      set_ofp_action_header_len buf 4;
      4
    | PushPbbHdr ->
      set_ofp_action_header_typ buf (ofp_action_type_to_int OFPAT_PUSH_PBB);
      set_ofp_action_header_len buf 4;
      4
    | PopPbbHdr ->
      set_ofp_action_header_typ buf (ofp_action_type_to_int OFPAT_POP_PBB);
      set_ofp_action_header_len buf 4;
      4
    | ExperimenterAHdr e ->
      set_ofp_action_header_typ buf (ofp_action_type_to_int OFPAT_EXPERIMENTER);
      set_ofp_action_header_len buf 8;
      set_ofp_action_experimenter_experimenter buf e;
      sizeof_ofp_action_experimenter

  let parse (bits : Cstruct.t) : t =
    match (int_to_ofp_action_type (get_ofp_action_header_typ bits)) with
    | Some OFPAT_OUTPUT -> OutputHdr
    | Some OFPAT_COPY_TTL_OUT -> CopyTtlOutHdr
    | Some OFPAT_COPY_TTL_IN -> CopyTtlInHdr
    | Some OFPAT_SET_MPLS_TTL -> SetMplsTtlHdr
    | Some OFPAT_DEC_MPLS_TTL -> DecMplsTtlHdr
    | Some OFPAT_PUSH_VLAN -> PushVlanHdr
    | Some OFPAT_POP_VLAN -> PopVlanHdr
    | Some OFPAT_PUSH_MPLS -> PushMplsHdr
    | Some OFPAT_POP_MPLS -> PopMplsHdr
    | Some OFPAT_SET_QUEUE -> SetQueueHdr
    | Some OFPAT_GROUP -> GroupHdr
    | Some OFPAT_SET_NW_TTL -> SetNwTtlHdr
    | Some OFPAT_DEC_NW_TTL -> DecNwTtlHdr
    | Some OFPAT_SET_FIELD -> SetFieldHdr
    | Some OFPAT_PUSH_PBB -> PushPbbHdr
    | Some OFPAT_POP_PBB -> PopPbbHdr
    | Some OFPAT_EXPERIMENTER -> ExperimenterAHdr (get_ofp_action_experimenter_experimenter bits)
    | None -> failwith "None type"

  let length_func (buf : Cstruct.t) : int option =
    if Cstruct.len buf < 4 (* ofp_action_header without padding *) then None
    else Some (get_ofp_action_header_len buf)

end

module TableFeatureProp = struct

  cstruct ofp_table_feature_prop_experimenter {
    uint16_t typ;
    uint16_t length;
    uint32_t experimenter;
    uint32_t exp_typ
  } as big_endian

  type t = tableFeatureProp

  let length_func (buf : Cstruct.t) : int option =
    if Cstruct.len buf < sizeof_ofp_table_feature_prop_header then None
    else Some (pad_to_64bits (get_ofp_table_feature_prop_header_length buf))

  let sizeof tfp : int =
    let size = sizeof_ofp_table_feature_prop_header + (match tfp with
        | TfpInstruction ins ->
          sum (List.map ~f:InstructionHdr.sizeof ins)
        | TfpInstructionMiss ins ->
          sum (List.map ~f:InstructionHdr.sizeof ins)
        | TfpNextTable t ->
          List.length t
        | TfpNextTableMiss t ->
          List.length t
        | TfpWriteAction act ->
          sum (List.map ~f:ActionHdr.sizeof act)
        | TfpWriteActionMiss act ->
          sum (List.map ~f:ActionHdr.sizeof act)
        | TfpApplyAction act ->
          sum (List.map ~f:ActionHdr.sizeof act)
        | TfpApplyActionMiss act ->
          sum (List.map ~f:ActionHdr.sizeof act)
        | TfpMatch ox ->
          sum (List.map ~f:Oxm.sizeof_header ox)
        | TfpWildcard ox ->
          sum (List.map ~f:Oxm.sizeof_header ox)
        | TfpWriteSetField ox->
          sum (List.map ~f:Oxm.sizeof_header ox)
        | TfpWriteSetFieldMiss ox ->
          sum (List.map ~f:Oxm.sizeof_header ox)
        | TfpApplySetField ox ->
          sum (List.map ~f:Oxm.sizeof_header ox)
        | TfpApplySetFieldMiss ox ->
          sum (List.map ~f:Oxm.sizeof_header ox)
        | TfpExperimenter (_,by) ->
          Cstruct.len by
        | TfpExperimenterMiss (_,by) ->
          Cstruct.len by
      ) in
    pad_to_64bits size

  let marshal (buf : Cstruct.t) (tfp : tableFeatureProp) =
    let buf_payload = Cstruct.shift buf sizeof_ofp_table_feature_prop_header in
    let size = sizeof_ofp_table_feature_prop_header +
               (match tfp with
                | TfpInstruction ins ->
                  set_ofp_table_feature_prop_header_typ buf (ofp_table_feature_prop_type_to_int OFPTFPT_INSTRUCTIONS);
                  marshal_fields buf_payload ins InstructionHdr.marshal
                | TfpInstructionMiss ins ->
                  set_ofp_table_feature_prop_header_typ buf (ofp_table_feature_prop_type_to_int OFPTFPT_INSTRUCTIONS_MISS);
                  marshal_fields buf_payload ins InstructionHdr.marshal
                | TfpNextTable t ->
                  set_ofp_table_feature_prop_header_typ buf (ofp_table_feature_prop_type_to_int OFPTFPT_NEXT_TABLES);
                  let marsh (buf : Cstruct.t) (id : uint8) : int =
                    set_uint8 buf 0 id;
                    1 in
                  marshal_fields buf_payload t marsh
                | TfpNextTableMiss t ->
                  set_ofp_table_feature_prop_header_typ buf (ofp_table_feature_prop_type_to_int OFPTFPT_NEXT_TABLES_MISS);
                  let marsh (buf : Cstruct.t) (id : uint8) : int =
                    set_uint8 buf 0 id;
                    1 in
                  marshal_fields buf_payload t marsh
                | TfpWriteAction act ->
                  set_ofp_table_feature_prop_header_typ buf (ofp_table_feature_prop_type_to_int OFPTFPT_WRITE_ACTIONS);
                  marshal_fields buf_payload act ActionHdr.marshal
                | TfpWriteActionMiss act ->
                  set_ofp_table_feature_prop_header_typ buf (ofp_table_feature_prop_type_to_int OFPTFPT_WRITE_ACTIONS_MISS);
                  marshal_fields buf_payload act ActionHdr.marshal
                | TfpApplyAction act ->
                  set_ofp_table_feature_prop_header_typ buf (ofp_table_feature_prop_type_to_int OFPTFPT_APPLY_ACTIONS);
                  marshal_fields buf_payload act ActionHdr.marshal
                | TfpApplyActionMiss act ->
                  set_ofp_table_feature_prop_header_typ buf (ofp_table_feature_prop_type_to_int OFPTFPT_APPLY_ACTIONS_MISS);
                  marshal_fields buf_payload act ActionHdr.marshal
                | TfpMatch ox ->
                  set_ofp_table_feature_prop_header_typ buf (ofp_table_feature_prop_type_to_int OFPTFPT_MATCH);
                  marshal_fields buf_payload ox Oxm.marshal_header
                | TfpWildcard ox ->
                  set_ofp_table_feature_prop_header_typ buf (ofp_table_feature_prop_type_to_int OFPTFPT_WILDCARDS);
                  marshal_fields buf_payload ox Oxm.marshal_header
                | TfpWriteSetField ox->
                  set_ofp_table_feature_prop_header_typ buf (ofp_table_feature_prop_type_to_int OFPTFPT_WRITE_SETFIELD);
                  marshal_fields buf_payload ox Oxm.marshal_header
                | TfpWriteSetFieldMiss ox ->
                  set_ofp_table_feature_prop_header_typ buf (ofp_table_feature_prop_type_to_int OFPTFPT_WRITE_SETFIELD_MISS);
                  marshal_fields buf_payload ox Oxm.marshal_header
                | TfpApplySetField ox ->
                  set_ofp_table_feature_prop_header_typ buf (ofp_table_feature_prop_type_to_int OFPTFPT_APPLY_SETFIELD);
                  marshal_fields buf_payload ox Oxm.marshal_header
                | TfpApplySetFieldMiss ox ->
                  set_ofp_table_feature_prop_header_typ buf (ofp_table_feature_prop_type_to_int OFPTFPT_APPLY_SETFIELD_MISS);
                  marshal_fields buf_payload ox Oxm.marshal_header
                | TfpExperimenter (ex,by) ->
                  set_ofp_table_feature_prop_header_typ buf (ofp_table_feature_prop_type_to_int OFPTFPT_EXPERIMENTER);
                  Cstruct.blit by 0 buf_payload 0 (Cstruct.len by);
                  Cstruct.len by
                | TfpExperimenterMiss (ex,by) ->
                  set_ofp_table_feature_prop_header_typ buf (ofp_table_feature_prop_type_to_int OFPTFPT_EXPERIMENTER_MISS);
                  Cstruct.blit by 0 buf_payload 0 (Cstruct.len by);
                  Cstruct.len by) in
    set_ofp_table_feature_prop_header_length buf size;
    pad_to_64bits size

  let rec parse_tables (bits : Cstruct.t) len =
    if Cstruct.len bits < 1 then ([], bits)
    else let field, bits2 = get_uint8 bits 0, Cstruct.shift bits 1 in
      let fields, bits3 = parse_tables bits2 (len -1) in
      (List.append [field] fields, bits3)

  let parse (bits : Cstruct.t) : tableFeatureProp =
    let tfpType = get_ofp_table_feature_prop_header_typ bits in
    let tfpLength = get_ofp_table_feature_prop_header_length bits in
    let tfpPayBits = Cstruct.sub bits sizeof_ofp_table_feature_prop_header (tfpLength - sizeof_ofp_table_feature_prop_header) in
    match int_to_ofp_table_feature_prop_type tfpType with
    | Some OFPTFPT_INSTRUCTIONS ->
      TfpInstruction (parse_fields tfpPayBits InstructionHdr.parse InstructionHdr.length_func)
    | Some OFPTFPT_INSTRUCTIONS_MISS ->
      TfpInstructionMiss (parse_fields tfpPayBits InstructionHdr.parse InstructionHdr.length_func)
    | Some OFPTFPT_NEXT_TABLES ->
      let ids,_ = parse_tables tfpPayBits (tfpLength - sizeof_ofp_table_feature_prop_header) in
      TfpNextTable ids
    | Some OFPTFPT_NEXT_TABLES_MISS ->
      let ids,_ = parse_tables tfpPayBits (tfpLength - sizeof_ofp_table_feature_prop_header) in
      TfpNextTableMiss ids
    | Some OFPTFPT_WRITE_ACTIONS ->
      TfpWriteAction (parse_fields tfpPayBits ActionHdr.parse ActionHdr.length_func)
    | Some OFPTFPT_WRITE_ACTIONS_MISS ->
      TfpWriteActionMiss (parse_fields tfpPayBits ActionHdr.parse ActionHdr.length_func)
    | Some OFPTFPT_APPLY_ACTIONS ->
      TfpApplyAction (parse_fields tfpPayBits ActionHdr.parse ActionHdr.length_func)
    | Some OFPTFPT_APPLY_ACTIONS_MISS ->
      TfpApplyActionMiss (parse_fields tfpPayBits ActionHdr.parse ActionHdr.length_func)
    | Some OFPTFPT_MATCH ->
      let fields,_ = Oxm.parse_headers tfpPayBits in
      TfpMatch fields
    | Some OFPTFPT_WILDCARDS ->
      let fields,_ = Oxm.parse_headers tfpPayBits in
      TfpWildcard fields
    | Some OFPTFPT_WRITE_SETFIELD ->
      let fields,_ = Oxm.parse_headers tfpPayBits in
      TfpWriteSetField fields
    | Some OFPTFPT_WRITE_SETFIELD_MISS ->
      let fields,_ = Oxm.parse_headers tfpPayBits in
      TfpWriteSetFieldMiss fields
    | Some OFPTFPT_APPLY_SETFIELD ->
      let fields,_ = Oxm.parse_headers tfpPayBits in
      TfpApplySetField fields
    | Some OFPTFPT_APPLY_SETFIELD_MISS ->
      let fields,_ = Oxm.parse_headers tfpPayBits in
      TfpApplySetFieldMiss fields
    | Some OFPTFPT_EXPERIMENTER ->
      let exp_id = get_ofp_table_feature_prop_experimenter_experimenter bits in
      let exp_type = get_ofp_table_feature_prop_experimenter_exp_typ bits in
      TfpExperimenter ({exp_id;exp_type},tfpPayBits)
    | Some OFPTFPT_EXPERIMENTER_MISS ->
      let exp_id = get_ofp_table_feature_prop_experimenter_experimenter bits in
      let exp_type = get_ofp_table_feature_prop_experimenter_exp_typ bits in
      TfpExperimenterMiss ({exp_id;exp_type},tfpPayBits)
    | _ -> raise (Unparsable (sprintf "malformed type"))

end

module TableConfig = struct

  cenum ofp_table_config {
    OFPTC_DEPRECATED_MASK = 3
  } as uint32_t

  type t = tableConfig
  let marshal (tc : tableConfig) : int32 =
    match tc with
    | Deprecated -> ofp_table_config_to_int OFPTC_DEPRECATED_MASK

  let parse t : tableConfig =
    match int_to_ofp_table_config t with
    | Some OFPTC_DEPRECATED_MASK -> Deprecated
    | _ -> raise (Unparsable (sprintf "unsupported config "))

end

module TableFeature = struct

  type t = tableFeatures

  let sizeof (tf : t) =
    (* should be equal to tf.length *)
    pad_to_64bits (sizeof_ofp_table_features + sum (List.map ~f:TableFeatureProp.sizeof tf.feature_prop))

  let marshal (buf : Cstruct.t) (tf : t) : int =
    set_ofp_table_features_length buf tf.length;
    set_ofp_table_features_table_id buf tf.table_id;
    set_ofp_table_features_pad (Cstruct.to_string (Cstruct.create 5)) 0 buf;
    set_ofp_table_features_name tf.name 0 buf;
    set_ofp_table_features_metadata_match buf tf.metadata_match;
    set_ofp_table_features_metadata_write buf tf.metadata_write;
    set_ofp_table_features_config buf (TableConfig.marshal tf.config);
    set_ofp_table_features_max_entries buf tf.max_entries;
    sizeof_ofp_table_features + (
      marshal_fields (Cstruct.shift buf sizeof_ofp_table_features) tf.feature_prop TableFeatureProp.marshal)

  let parse (bits : Cstruct.t) : t =
    let length = get_ofp_table_features_length bits in
    let tableId = get_ofp_table_features_table_id bits in
    let name = Cstruct.to_string (get_ofp_table_features_name bits) in
    let metadataMatch = get_ofp_table_features_metadata_match bits in
    let metadataWrite = get_ofp_table_features_metadata_write bits in
    let config = TableConfig.parse (get_ofp_table_features_config bits) in
    let maxEntries = get_ofp_table_features_max_entries bits in
    let featureProp = parse_fields (Cstruct.sub bits sizeof_ofp_table_features (length-sizeof_ofp_table_features)) TableFeatureProp.parse TableFeatureProp.length_func in
    { length = length;
      table_id = tableId;
      name = name;
      metadata_match = metadataMatch;
      metadata_write = metadataWrite;
      config = config;
      max_entries = maxEntries;
      feature_prop = featureProp}

  let length_func (buf : Cstruct.t) : int option =
    if Cstruct.len buf < sizeof_ofp_table_features then None
    else Some (get_ofp_table_features_length buf)
end

module MultipartReq = struct

  cstruct ofp_multipart_request {
    uint16_t typ; (* One of the OFPMP_* constants. *)
    uint16_t flags; (* OFPMPF_REQ_* flags. *)
    uint8_t pad0;
    uint8_t pad1;
    uint8_t pad2;
    uint8_t pad3
  } as big_endian

  cstruct ofp_experimenter_multipart_header {
    uint32_t experimenter;
    uint32_t exp_type
  } as big_endian

  type t = multipartRequest

  let msg_code_of_request mpr = match mpr with
    | SwitchDescReq -> OFPMP_DESC
    | PortsDescReq -> OFPMP_PORT_DESC
    | FlowStatsReq _ -> OFPMP_FLOW
    | AggregFlowStatsReq _ -> OFPMP_AGGREGATE
    | TableStatsReq -> OFPMP_TABLE
    | PortStatsReq _ -> OFPMP_PORT_STATS
    | QueueStatsReq _ -> OFPMP_QUEUE
    | GroupStatsReq _ -> OFPMP_GROUP
    | GroupDescReq -> OFPMP_GROUP_DESC
    | GroupFeatReq -> OFPMP_GROUP_FEATURES
    | MeterStatsReq _ -> OFPMP_METER
    | MeterConfReq _ -> OFPMP_METER_CONFIG
    | MeterFeatReq -> OFPMP_METER_FEATURES
    | TableFeatReq _ -> OFPMP_TABLE_FEATURES
    | ExperimentReq _ -> OFPMP_EXPERIMENTER

  let sizeof (mpr : multipartRequest) =
    sizeof_ofp_multipart_request +
    (match mpr.mpr_type with
     | SwitchDescReq | PortsDescReq | TableStatsReq | MeterFeatReq | GroupDescReq
     | GroupFeatReq -> 0
     | FlowStatsReq fr -> FlowRequest.sizeof fr
     | AggregFlowStatsReq fr -> FlowRequest.sizeof fr
     | PortStatsReq _ -> sizeof_ofp_port_stats_request
     | QueueStatsReq _ -> sizeof_ofp_queue_stats_request
     | GroupStatsReq _ -> sizeof_ofp_group_stats_request
     | MeterStatsReq _  | MeterConfReq _ -> sizeof_ofp_meter_multipart_request
     | TableFeatReq tfr -> (match tfr with
         | None -> 0
         | Some t -> sum (List.map ~f:TableFeature.sizeof t))
     | ExperimentReq _ -> sizeof_ofp_experimenter_multipart_header)

  let marshal (buf : Cstruct.t) (mpr : multipartRequest) : int =
    let size = sizeof_ofp_multipart_request in
    set_ofp_multipart_request_typ buf (ofp_multipart_types_to_int (msg_code_of_request mpr.mpr_type));
    set_ofp_multipart_request_flags buf (
      match mpr.mpr_flags with
      | true -> ofp_multipart_request_flags_to_int OFPMPF_REQ_MORE
      | false -> 0);
    set_ofp_multipart_request_pad0 buf 0;
    set_ofp_multipart_request_pad1 buf 0;
    set_ofp_multipart_request_pad2 buf 0;
    set_ofp_multipart_request_pad3 buf 0;
    let pay_buf = Cstruct.shift buf sizeof_ofp_multipart_request in
    match mpr.mpr_type with
    | SwitchDescReq
    | PortsDescReq -> size
    | FlowStatsReq f -> size + (FlowRequest.marshal pay_buf f)
    | AggregFlowStatsReq f -> size + (FlowRequest.marshal pay_buf f)
    | TableStatsReq -> size
    | PortStatsReq p -> set_ofp_port_stats_request_port_no pay_buf p;
      size + sizeof_ofp_port_stats_request
    | QueueStatsReq q -> size + (QueueRequest.marshal pay_buf q)
    | GroupStatsReq g -> set_ofp_port_stats_request_port_no pay_buf g;
      size + sizeof_ofp_port_stats_request
    | GroupDescReq
    | GroupFeatReq -> size
    | MeterStatsReq m -> set_ofp_meter_multipart_request_meter_id pay_buf m;
      size + sizeof_ofp_meter_multipart_request
    | MeterConfReq m -> set_ofp_meter_multipart_request_meter_id pay_buf m;
      size + sizeof_ofp_meter_multipart_request
    | MeterFeatReq -> size
    | TableFeatReq t ->
      (match t with
       | None -> 0
       | Some v -> size + marshal_fields pay_buf v TableFeature.marshal)
    | ExperimentReq _ -> size

  let parse (bits : Cstruct.t) : multipartRequest =
    let mprType = int_to_ofp_multipart_types (get_ofp_multipart_request_typ bits) in
    let mpr_flags = (
      match int_to_ofp_multipart_request_flags (get_ofp_multipart_request_flags bits) with
      | Some OFPMPF_REQ_MORE -> true
      | _ -> false) in
    let mpr_type = match mprType with
      | Some OFPMP_DESC -> SwitchDescReq
      | Some OFPMP_PORT_DESC -> PortsDescReq
      | Some OFPMP_FLOW -> FlowStatsReq (
          FlowRequest.parse (Cstruct.shift bits sizeof_ofp_multipart_request))
      | Some OFPMP_AGGREGATE -> AggregFlowStatsReq (
          FlowRequest.parse (Cstruct.shift bits sizeof_ofp_multipart_request))
      | Some OFPMP_TABLE -> TableStatsReq
      | Some OFPMP_PORT_STATS -> PortStatsReq (
          get_ofp_port_stats_request_port_no (Cstruct.shift bits sizeof_ofp_multipart_request))
      | Some OFPMP_QUEUE -> QueueStatsReq (
          QueueRequest.parse (Cstruct.shift bits sizeof_ofp_multipart_request))
      | Some OFPMP_GROUP -> GroupStatsReq (
          get_ofp_group_stats_request_group_id (Cstruct.shift bits sizeof_ofp_multipart_request))
      | Some OFPMP_GROUP_DESC -> GroupDescReq
      | Some OFPMP_GROUP_FEATURES -> GroupFeatReq
      | Some OFPMP_METER -> MeterStatsReq (
          get_ofp_meter_multipart_request_meter_id (Cstruct.shift bits sizeof_ofp_multipart_request))
      | Some OFPMP_METER_CONFIG -> MeterConfReq (
          get_ofp_meter_multipart_request_meter_id (Cstruct.shift bits sizeof_ofp_multipart_request))
      | Some OFPMP_METER_FEATURES -> MeterFeatReq
      | Some OFPMP_TABLE_FEATURES -> TableFeatReq (
          if Cstruct.len bits <= sizeof_ofp_multipart_request then None
          else Some (
              parse_fields (Cstruct.shift bits sizeof_ofp_multipart_request) TableFeature.parse TableFeature.length_func
            ))
      | Some OFPMP_EXPERIMENTER -> ExperimentReq (
          let exp_bits = Cstruct.shift bits sizeof_ofp_multipart_request in
          let exp_id = get_ofp_experimenter_multipart_header_experimenter exp_bits in
          let exp_type = get_ofp_experimenter_multipart_header_exp_type exp_bits in
          {exp_id; exp_type})
      | _ -> raise (Unparsable (sprintf "bad ofp_multipart_types number"))
    in {mpr_type; mpr_flags}


end

module SwitchDescriptionReply = struct

  type t = switchDesc

  let sizeof (sdr : switchDesc) : int =
    sizeof_ofp_desc

  let marshal (buf : Cstruct.t) (sdr : switchDesc) : int =
    set_ofp_desc_mfr_desc sdr.mfr_desc 0 buf;
    set_ofp_desc_hw_desc sdr.hw_desc 0 buf;
    set_ofp_desc_sw_desc sdr.sw_desc 0 buf;
    set_ofp_desc_serial_num sdr.serial_num 0 buf;
    sizeof_ofp_desc

  let parse (bits : Cstruct.t) : switchDesc =
    let mfr_desc = copy_ofp_desc_mfr_desc bits in
    let hw_desc = copy_ofp_desc_hw_desc bits in
    let sw_desc = copy_ofp_desc_sw_desc bits in
    let serial_num = copy_ofp_desc_serial_num bits in
    { mfr_desc;
      hw_desc;
      sw_desc;
      serial_num}

end

module FlowStats = struct

  cstruct ofp_flow_stats {
    uint16_t length;
    uint8_t table_id;
    uint8_t pad0;
    uint32_t duration_sec;
    uint32_t duration_nsec;
    uint16_t priority;
    uint16_t idle_timeout;
    uint16_t hard_timeout;
    uint16_t flags;
    uint8_t pad1[4];
    uint64_t cookie;
    uint64_t packet_count;
    uint64_t byte_count;
  } as big_endian

  type t = flowStats

  let sizeof (fs : flowStats) =
    sizeof_ofp_flow_stats +
    (OfpMatch.sizeof fs.ofp_match)+
    (Instructions.sizeof fs.instructions)

  let marshal (buf : Cstruct.t) (fs : flowStats) : int =
    set_ofp_flow_stats_length buf (sizeof fs);
    set_ofp_flow_stats_table_id buf fs.table_id;
    set_ofp_flow_stats_pad0 buf 0;
    set_ofp_flow_stats_duration_sec buf fs.duration_sec;
    set_ofp_flow_stats_duration_nsec buf fs.duration_nsec;
    set_ofp_flow_stats_priority buf fs.priority;
    set_ofp_flow_stats_idle_timeout buf
      (match fs.idle_timeout with
       | Permanent -> 0
       | ExpiresAfter  v -> v);
    set_ofp_flow_stats_hard_timeout buf
      (match fs.hard_timeout with
       | Permanent -> 0
       | ExpiresAfter  v -> v);
    set_ofp_flow_stats_flags buf (FlowMod.Flags.marshal fs.flags);
    set_ofp_flow_stats_pad1 (Cstruct.to_string (Cstruct.create 4)) 0 buf;
    set_ofp_flow_stats_cookie buf fs.cookie;
    set_ofp_flow_stats_packet_count buf fs.packet_count;
    set_ofp_flow_stats_byte_count buf fs.byte_count;
    let size = sizeof_ofp_flow_stats +
               OfpMatch.marshal (Cstruct.shift buf sizeof_ofp_flow_stats) fs.ofp_match in
    size + Instructions.marshal (Cstruct.shift buf size) fs.instructions

  let parse (bits : Cstruct.t) : flowStats =
    let table_id = get_ofp_flow_stats_table_id bits in
    let duration_sec = get_ofp_flow_stats_duration_sec bits in
    let duration_nsec = get_ofp_flow_stats_duration_nsec bits in
    let priority = get_ofp_flow_stats_priority bits in
    let idle_timeout = match (get_ofp_flow_stats_idle_timeout bits) with
      | 0 -> Permanent
      | n -> ExpiresAfter n in
    let hard_timeout = match (get_ofp_flow_stats_hard_timeout bits) with
      | 0 -> Permanent
      | n -> ExpiresAfter n in
    let flagsBits = get_ofp_flow_stats_flags bits in
    let flags = FlowMod.Flags.parse flagsBits in
    let cookie = get_ofp_flow_stats_cookie bits in
    let packet_count = get_ofp_flow_stats_packet_count bits in
    let byte_count = get_ofp_flow_stats_byte_count bits in
    let ofp_match_bits = Cstruct.shift bits sizeof_ofp_flow_stats in
    let ofp_match, instruction_bits = OfpMatch.parse ofp_match_bits in
    let instructions = Instructions.parse instruction_bits in
    { table_id
    ; duration_sec
    ; duration_nsec
    ; priority
    ; idle_timeout
    ; hard_timeout
    ; flags
    ; cookie
    ; packet_count
    ; byte_count
    ; ofp_match
    ; instructions}

  let length_func (buf :  Cstruct.t) : int option =
    if Cstruct.len buf < sizeof_ofp_flow_stats then None
    else Some (get_ofp_flow_stats_length buf)

end

module AggregateStats = struct

  cstruct ofp_aggregate_stats_reply {
    uint64_t packet_count;
    uint64_t byte_count;
    uint32_t flow_count;
    uint8_t pad[4];
  } as big_endian

  type t = aggregStats

  let sizeof ag =
    sizeof_ofp_aggregate_stats_reply

  let marshal (buf : Cstruct.t) (ag : aggregStats) : int =
    set_ofp_aggregate_stats_reply_packet_count buf ag.packet_count;
    set_ofp_aggregate_stats_reply_byte_count buf ag.byte_count;
    set_ofp_aggregate_stats_reply_flow_count buf ag.flow_count;
    set_ofp_aggregate_stats_reply_pad (Cstruct.to_string (Cstruct.create 4)) 0 buf;
    sizeof_ofp_aggregate_stats_reply

  let parse (bits : Cstruct.t) : aggregStats =
    { packet_count = (get_ofp_aggregate_stats_reply_packet_count bits)
    ; byte_count = (get_ofp_aggregate_stats_reply_byte_count bits)
    ; flow_count = (get_ofp_aggregate_stats_reply_flow_count bits)}

end

module TableStats = struct
  cstruct ofp_table_stats {
    uint8_t table_id;
    uint8_t pad[3];
    uint32_t active_count;
    uint64_t lookup_count;
    uint64_t matched_count;
  } as big_endian

  type t = tableStats

  let sizeof (ts : tableStats) =
    sizeof_ofp_table_stats

  let marshal (buf : Cstruct.t) (ts : tableStats) : int =
    set_ofp_table_stats_table_id buf ts.table_id;
    set_ofp_table_stats_pad (Cstruct.to_string (Cstruct.create 3)) 0 buf;
    set_ofp_table_stats_active_count buf ts.active_count;
    set_ofp_table_stats_lookup_count buf ts.lookup_count;
    set_ofp_table_stats_matched_count buf ts.matched_count;
    sizeof_ofp_table_stats

  let parse (bits : Cstruct.t) : tableStats =
    { table_id = get_ofp_table_stats_table_id bits
    ; active_count = get_ofp_table_stats_active_count bits
    ; lookup_count = get_ofp_table_stats_lookup_count bits
    ; matched_count = get_ofp_table_stats_matched_count bits}

  let length_func = (fun buf -> Some sizeof_ofp_table_stats)

end

module PortStats = struct

  type t = portStats

  let sizeof (ps : portStats) =
    sizeof_ofp_port_stats

  let marshal (buf : Cstruct.t) (ps : portStats) : int =
    set_ofp_port_stats_port_no buf ps.psPort_no;
    set_ofp_port_stats_pad (Cstruct.to_string (Cstruct.create 4)) 0 buf;
    set_ofp_port_stats_rx_packets buf ps.rx_packets;
    set_ofp_port_stats_tx_packets buf ps.tx_packets;
    set_ofp_port_stats_rx_bytes buf ps.rx_bytes;
    set_ofp_port_stats_tx_bytes buf ps.tx_bytes;
    set_ofp_port_stats_rx_dropped buf ps.rx_dropped;
    set_ofp_port_stats_tx_dropped buf ps.tx_dropped;
    set_ofp_port_stats_rx_errors buf ps.rx_errors;
    set_ofp_port_stats_tx_errors buf ps.tx_errors;
    set_ofp_port_stats_rx_frame_err buf ps.rx_frame_err;
    set_ofp_port_stats_rx_over_err buf ps.rx_over_err;
    set_ofp_port_stats_rx_crc_err buf ps.rx_crc_err;
    set_ofp_port_stats_collisions buf ps.collisions;
    set_ofp_port_stats_duration_sec buf ps.duration_sec;
    set_ofp_port_stats_duration_nsec buf ps.duration_nsec;
    sizeof_ofp_port_stats

  let parse (bits : Cstruct.t) : portStats =
    { psPort_no     = get_ofp_port_stats_port_no bits;
      rx_packets    = get_ofp_port_stats_rx_packets bits;
      tx_packets    = get_ofp_port_stats_tx_packets bits;
      rx_bytes      = get_ofp_port_stats_rx_bytes bits;
      tx_bytes      = get_ofp_port_stats_tx_bytes bits;
      rx_dropped    = get_ofp_port_stats_rx_dropped bits;
      tx_dropped    = get_ofp_port_stats_tx_dropped bits;
      rx_errors     = get_ofp_port_stats_rx_errors bits;
      tx_errors     = get_ofp_port_stats_tx_errors bits;
      rx_frame_err  = get_ofp_port_stats_rx_frame_err bits;
      rx_over_err   = get_ofp_port_stats_rx_over_err bits;
      rx_crc_err    = get_ofp_port_stats_rx_crc_err bits;
      collisions    = get_ofp_port_stats_collisions bits;
      duration_sec  = get_ofp_port_stats_duration_sec bits;
      duration_nsec = get_ofp_port_stats_duration_nsec bits
    }

  let length_func = (fun buf -> Some sizeof_ofp_port_stats)

end

module QueueStats = struct

  cstruct ofp_queue_stats {
    uint32_t port_no;
    uint32_t queue_id;
    uint64_t tx_bytes;
    uint64_t tx_packets;
    uint64_t tx_errors;
    uint32_t duration_sec;
    uint32_t duration_nsec
  } as big_endian

  type t = queueStats

  let sizeof (qs : queueStats) : int =
    sizeof_ofp_queue_stats

  let marshal (buf : Cstruct.t) (qs : queueStats) : int =
    set_ofp_queue_stats_port_no buf qs.qsPort_no;
    set_ofp_queue_stats_queue_id buf qs.queue_id;
    set_ofp_queue_stats_tx_bytes buf qs.tx_bytes;
    set_ofp_queue_stats_tx_packets buf qs.tx_packets;
    set_ofp_queue_stats_tx_errors buf qs.tx_errors;
    set_ofp_queue_stats_duration_sec buf qs.duration_sec;
    set_ofp_queue_stats_duration_nsec buf qs.duration_nsec;
    sizeof_ofp_queue_stats

  let parse (bits : Cstruct.t) : queueStats =
    { qsPort_no = get_ofp_queue_stats_port_no bits
    ; queue_id = get_ofp_queue_stats_queue_id bits
    ; tx_bytes = get_ofp_queue_stats_tx_bytes bits
    ; tx_packets = get_ofp_queue_stats_tx_packets bits
    ; tx_errors = get_ofp_queue_stats_tx_errors bits
    ; duration_sec = get_ofp_queue_stats_duration_sec bits
    ; duration_nsec = get_ofp_queue_stats_duration_nsec bits
    }

  let length_func = (fun buf -> Some sizeof_ofp_queue_stats)

end

module GroupStats = struct

  cstruct ofp_group_stats {
    uint16_t length;
    uint8_t pad[2];
    uint32_t group_id;
    uint32_t ref_count;
    uint8_t pad2[4];
    uint64_t packet_count;
    uint64_t byte_count;
    uint32_t duration_sec;
    uint32_t duration_nsec
  } as big_endian

  module BucketStats = struct

    cstruct ofp_bucket_counter {
      uint64_t packet_count;
      uint64_t byte_count
    } as big_endian

    type t = bucketStats

    let sizeof (gs : bucketStats) : int =
      sizeof_ofp_bucket_counter

    let marshal (buf : Cstruct.t) (bs : bucketStats) : int =
      set_ofp_bucket_counter_packet_count buf bs.packet_count;
      set_ofp_bucket_counter_byte_count buf bs.byte_count;
      sizeof_ofp_bucket_counter

    let parse (bits : Cstruct.t) : bucketStats =
      { packet_count = get_ofp_bucket_counter_packet_count bits
      ; byte_count = get_ofp_bucket_counter_byte_count bits }

    let length_func = (fun buf -> Some sizeof_ofp_bucket_counter)

  end

  type t = groupStats

  let sizeof (gs : groupStats) : int =
    gs.length

  let marshal (buf : Cstruct.t) (gs : groupStats) : int =
    set_ofp_group_stats_length buf gs.length;
    set_ofp_group_stats_group_id buf gs.group_id;
    set_ofp_group_stats_ref_count buf gs.ref_count;
    set_ofp_group_stats_packet_count buf gs.packet_count;
    set_ofp_group_stats_byte_count buf gs.byte_count;
    set_ofp_group_stats_duration_sec buf gs.duration_sec;
    set_ofp_group_stats_duration_nsec buf gs.duration_nsec;
    sizeof_ofp_group_stats + (marshal_fields (Cstruct.shift buf sizeof_ofp_group_stats) gs.bucket_stats BucketStats.marshal)

  let parse (bits : Cstruct.t) : groupStats =
    { length = get_ofp_group_stats_length bits
    ; group_id = get_ofp_group_stats_group_id bits
    ; ref_count = get_ofp_group_stats_ref_count bits
    ; packet_count = get_ofp_group_stats_packet_count bits
    ; byte_count = get_ofp_group_stats_byte_count bits
    ; duration_sec = get_ofp_group_stats_duration_sec bits
    ; duration_nsec = get_ofp_group_stats_duration_nsec bits
    ; bucket_stats = parse_fields (Cstruct.shift bits sizeof_ofp_group_stats) BucketStats.parse BucketStats.length_func
    }

  let length_func (buf :  Cstruct.t) : int option =
    if Cstruct.len buf < sizeof_ofp_group_stats then None
    else Some (get_ofp_group_stats_length buf)

end

module GroupDesc = struct

  cstruct ofp_group_desc {
    uint16_t length;
    uint8_t typ;
    uint8_t pad;
    uint32_t group_id;
  } as big_endian

  type t = groupDesc

  let sizeof (gd : groupDesc) : int =
    sizeof_ofp_group_desc + sum (List.map ~f:Bucket.sizeof gd.bucket)

  let marshal (buf : Cstruct.t) (gd : groupDesc) : int =
    set_ofp_group_desc_length buf gd.length;
    set_ofp_group_desc_typ buf (GroupType.marshal gd.typ);
    set_ofp_group_desc_group_id buf gd.group_id;
    let size_bucket =
      (marshal_fields (Cstruct.shift buf sizeof_ofp_group_desc) gd.bucket Bucket.marshal) in
    sizeof_ofp_group_desc + size_bucket

  let parse (bits : Cstruct.t) : groupDesc =
    let len = get_ofp_group_desc_length bits in
    let typ = GroupType.parse (get_ofp_group_desc_typ bits) in
    let group_id = get_ofp_group_desc_group_id bits in
    let bucket_bits = Cstruct.sub bits sizeof_ofp_group_desc (len - sizeof_ofp_group_desc) in
    let bucket = parse_fields bucket_bits Bucket.parse Bucket.length_func in
    { length = len
    ; typ = typ
    ; group_id = group_id
    ; bucket = bucket}

  let length_func buf =
    if Cstruct.len buf < sizeof_ofp_group_desc  then None
    else Some (get_ofp_group_desc_length buf)

end

module GroupFeatures = struct

  cstruct ofp_group_features {
    uint32_t typ;
    uint32_t capabilities;
    uint32_t max_groups_all;
    uint32_t max_groups_select;
    uint32_t max_groups_indirect;
    uint32_t max_groups_fastfailover;
    uint32_t actions_all;
    uint32_t actions_select;
    uint32_t actions_indirect;
    uint32_t actions_fastfailover
  } as big_endian

  module GroupType = struct

    type t = groupTypeMap

    let marshal (gtm : groupTypeMap) : int32 =
      Int32.bit_or (if gtm.all then (Int32.shift_left 1l 0) else 0l)
        (Int32.bit_or (if gtm.select then (Int32.shift_left 1l 1) else 0l)
           (Int32.bit_or (if gtm.indirect then (Int32.shift_left 1l 2) else 0l)
              (if gtm.ff then (Int32.shift_left 1l 3) else 0l)))

    let parse bits : groupTypeMap =
      { all = Frenetic_Bits.test_bit 0 bits
      ; select = Frenetic_Bits.test_bit 1 bits
      ; indirect = Frenetic_Bits.test_bit 2 bits
      ; ff = Frenetic_Bits.test_bit 3 bits }

  end

  module Capabilities = struct

    type t = groupCapabilities

    let marshal (gc : groupCapabilities) : int32 =
      Int32.bit_or (if gc.select_weight then (Int32.shift_left 1l 0) else 0l)
        (Int32.bit_or (if gc.select_liveness then (Int32.shift_left 1l 1) else 0l)
           (Int32.bit_or (if gc.chaining then (Int32.shift_left 1l 2) else 0l)
              (if gc.chaining_checks then (Int32.shift_left 1l 3) else 0l)))

    let parse bits : groupCapabilities =
      { select_weight = Frenetic_Bits.test_bit 0 bits
      ; select_liveness = Frenetic_Bits.test_bit 1 bits
      ; chaining = Frenetic_Bits.test_bit 2 bits
      ; chaining_checks = Frenetic_Bits.test_bit 3 bits }

  end

  module ActionTypeMap = struct

    type t = actionTypeMap

    let marshal (atm : actionTypeMap) : int32 =
      Int32.bit_or (if atm.output then (Int32.shift_left 1l 0) else 0l)
        (Int32.bit_or (if atm.copy_ttl_out then (Int32.shift_left 1l 11) else 0l)
           (Int32.bit_or (if atm.copy_ttl_in then (Int32.shift_left 1l 12) else 0l)
              (Int32.bit_or (if atm.set_mpls_ttl then (Int32.shift_left 1l 15) else 0l)
                 (Int32.bit_or (if atm.dec_mpls_ttl then (Int32.shift_left 1l 16) else 0l)
                    (Int32.bit_or (if atm.push_vlan then (Int32.shift_left 1l 17) else 0l)
                       (Int32.bit_or (if atm.pop_vlan then (Int32.shift_left 1l 18) else 0l)
                          (Int32.bit_or (if atm.push_mpls then (Int32.shift_left 1l 19) else 0l)
                             (Int32.bit_or (if atm.pop_mpls then (Int32.shift_left 1l 20) else 0l)
                                (Int32.bit_or (if atm.set_queue then (Int32.shift_left 1l 21) else 0l)
                                   (Int32.bit_or (if atm.group then (Int32.shift_left 1l 22) else 0l)
                                      (Int32.bit_or (if atm.set_nw_ttl then (Int32.shift_left 1l 23) else 0l)
                                         (Int32.bit_or (if atm.dec_nw_ttl then (Int32.shift_left 1l 24) else 0l)
                                            (Int32.bit_or (if atm.set_field then (Int32.shift_left 1l 25) else 0l)
                                               (Int32.bit_or (if atm.push_pbb then (Int32.shift_left 1l 26) else 0l)
                                                  (if atm.pop_pbb then (Int32.shift_left 1l 27) else 0l)))))))))))))))

    let parse bits : actionTypeMap =
      { output = Frenetic_Bits.test_bit 0 bits
      ; copy_ttl_out = Frenetic_Bits.test_bit 11 bits
      ; copy_ttl_in = Frenetic_Bits.test_bit 12 bits
      ; set_mpls_ttl = Frenetic_Bits.test_bit 15 bits
      ; dec_mpls_ttl = Frenetic_Bits.test_bit 16 bits
      ; push_vlan = Frenetic_Bits.test_bit 17 bits
      ; pop_vlan = Frenetic_Bits.test_bit 18 bits
      ; push_mpls = Frenetic_Bits.test_bit 19 bits
      ; pop_mpls = Frenetic_Bits.test_bit 20 bits
      ; set_queue = Frenetic_Bits.test_bit 21 bits
      ; group = Frenetic_Bits.test_bit 22 bits
      ; set_nw_ttl = Frenetic_Bits.test_bit 23 bits
      ; dec_nw_ttl = Frenetic_Bits.test_bit 24 bits
      ; set_field = Frenetic_Bits.test_bit 25 bits
      ; push_pbb = Frenetic_Bits.test_bit 26 bits
      ; pop_pbb = Frenetic_Bits.test_bit 27 bits }

  end

  type t = groupFeatures

  let sizeof (gf : groupFeatures) : int =
    sizeof_ofp_group_features

  let marshal (buf : Cstruct.t) (gf : groupFeatures) : int =
    set_ofp_group_features_typ buf (GroupType.marshal gf.typ);
    set_ofp_group_features_capabilities buf (Capabilities.marshal gf.capabilities);
    set_ofp_group_features_max_groups_all buf gf.max_groups_all;
    set_ofp_group_features_max_groups_select buf gf.max_groups_select;
    set_ofp_group_features_max_groups_indirect buf gf.max_groups_indirect;
    set_ofp_group_features_max_groups_fastfailover buf gf.max_groups_ff;
    set_ofp_group_features_actions_all buf (ActionTypeMap.marshal gf.actions_all);
    set_ofp_group_features_actions_select buf (ActionTypeMap.marshal gf.actions_select);
    set_ofp_group_features_actions_indirect buf (ActionTypeMap.marshal gf.actions_indirect);
    set_ofp_group_features_actions_fastfailover buf (ActionTypeMap.marshal gf.actions_ff);
    sizeof_ofp_group_features

  let parse (bits : Cstruct.t) : groupFeatures =
    { typ = GroupType.parse (get_ofp_group_features_typ bits)
    ; capabilities = Capabilities.parse (get_ofp_group_features_capabilities bits)
    ; max_groups_all = get_ofp_group_features_max_groups_all bits
    ; max_groups_select = get_ofp_group_features_max_groups_select bits
    ; max_groups_indirect = get_ofp_group_features_max_groups_indirect bits
    ; max_groups_ff = get_ofp_group_features_max_groups_fastfailover bits
    ; actions_all = ActionTypeMap.parse (get_ofp_group_features_actions_all bits)
    ; actions_select = ActionTypeMap.parse (get_ofp_group_features_actions_select bits)
    ; actions_indirect = ActionTypeMap.parse (get_ofp_group_features_actions_indirect bits)
    ; actions_ff = ActionTypeMap.parse (get_ofp_group_features_actions_fastfailover bits)
    }

end

module MeterStats = struct

  cstruct ofp_meter_stats {
    uint32_t meter_id;
    uint16_t len;
    uint8_t pad[6];
    uint32_t flow_count;
    uint64_t packet_in_count;
    uint64_t byte_in_count;
    uint32_t duration_sec;
    uint32_t duration_nsec
  } as big_endian

  module Band = struct

    cstruct ofp_meter_band_stats {
      uint64_t packet_band_count;
      uint64_t byte_band_count
    } as big_endian

    type t = meterBandStats

    let length_func = fun buf -> Some sizeof_ofp_meter_band_stats

    let marshal (buf : Cstruct.t) (mbs : meterBandStats) : int =
      set_ofp_meter_band_stats_packet_band_count buf mbs.packet_band_count;
      set_ofp_meter_band_stats_byte_band_count buf mbs.byte_band_count;
      sizeof_ofp_meter_band_stats

    let parse (bits : Cstruct.t) : meterBandStats =
      { packet_band_count = get_ofp_meter_band_stats_packet_band_count bits
      ; byte_band_count = get_ofp_meter_band_stats_byte_band_count bits}

  end

  type t = meterStats

  let sizeof (ms : meterStats) : int =
    ms.len

  let marshal (buf : Cstruct.t) (ms : meterStats) =
    set_ofp_meter_stats_meter_id buf ms.meter_id;
    set_ofp_meter_stats_len buf ms.len;
    set_ofp_meter_stats_flow_count buf ms.flow_count;
    set_ofp_meter_stats_packet_in_count buf ms.packet_in_count;
    set_ofp_meter_stats_byte_in_count buf ms.byte_in_count;
    set_ofp_meter_stats_duration_sec buf ms.duration_sec;
    set_ofp_meter_stats_duration_nsec buf ms.duration_nsec;
    let band_buf = Cstruct.sub buf sizeof_ofp_meter_stats (ms.len - sizeof_ofp_meter_stats) in
    sizeof_ofp_meter_stats + (marshal_fields band_buf ms.band Band.marshal)

  let parse (bits : Cstruct.t) : meterStats =
    let meter_id = get_ofp_meter_stats_meter_id bits in
    let len = get_ofp_meter_stats_len bits in
    let flow_count = get_ofp_meter_stats_flow_count bits in
    let packet_in_count = get_ofp_meter_stats_packet_in_count bits in
    let byte_in_count = get_ofp_meter_stats_byte_in_count bits in
    let duration_sec = get_ofp_meter_stats_duration_sec bits in
    let duration_nsec = get_ofp_meter_stats_duration_nsec bits in
    let band_bits = Cstruct.sub bits sizeof_ofp_meter_stats (len - sizeof_ofp_meter_stats) in
    let band = parse_fields band_bits Band.parse Band.length_func in
    { meter_id; len; flow_count; packet_in_count; byte_in_count; duration_sec; duration_nsec; band }

  let length_func buf =
    if Cstruct.len buf < sizeof_ofp_meter_stats  then None
    else Some (get_ofp_meter_stats_len buf)

end

module MeterConfig = struct

  cstruct ofp_meter_config {
    uint16_t length;
    uint16_t flags;
    uint32_t meter_id
  } as big_endian

  type t = meterConfig

  let sizeof (mc : meterConfig) : int =
    sizeof_ofp_meter_config + sum (List.map ~f:MeterBand.sizeof mc.bands)

  let marshal (buf : Cstruct.t) (mc : meterConfig) : int =
    set_ofp_meter_config_length buf mc.length;
    set_ofp_meter_config_flags buf (MeterFlags.marshal mc.flags);
    set_ofp_meter_config_meter_id buf mc.meter_id;
    sizeof_ofp_meter_config + (marshal_fields (Cstruct.shift buf sizeof_ofp_meter_config) mc.bands MeterBand.marshal)

  let parse (bits : Cstruct.t) : meterConfig =
    let length = get_ofp_meter_config_length bits in
    let flags = MeterFlags.parse (get_ofp_meter_config_flags bits) in
    let meter_id = get_ofp_meter_config_meter_id bits in
    let bands_bits = Cstruct.sub bits sizeof_ofp_meter_config (length-sizeof_ofp_meter_config) in
    let bands = parse_fields bands_bits MeterBand.parse MeterBand.length_fun in
    { length
    ; flags
    ; meter_id
    ; bands
    }

  let length_func (buf : Cstruct.t) : int option =
    if Cstruct.len buf < sizeof_ofp_meter_config then None
    else Some (get_ofp_meter_config_length buf)

end

module MeterFeatures = struct

  cstruct ofp_meter_features {
    uint32_t max_meter;
    uint32_t band_types;
    uint32_t capabilities;
    uint8_t max_bands;
    uint8_t max_color;
    uint8_t pad[2]
  } as big_endian

  module Bands = struct
    type t = meterBandMaps

    let marshal (mbm : meterBandMaps) : int32 =
      Int32.bit_or (if mbm.drop then (Int32.shift_left 1l 1) else 0l)
        (if mbm.dscpRemark then (Int32.shift_left 1l 2) else 0l)

    let parse bits : meterBandMaps =
      { drop = Frenetic_Bits.test_bit 1 bits
      ; dscpRemark = Frenetic_Bits.test_bit 2 bits }

  end

  type t = meterFeatures

  let sizeof (mfs : t) : int =
    sizeof_ofp_meter_features

  let marshal (buf : Cstruct.t) (mfs : t) : int =
    set_ofp_meter_features_max_meter buf mfs.max_meter;
    set_ofp_meter_features_band_types buf (Bands.marshal mfs.band_typ);
    (* int -> int32 fix, before release of OF1.3.5 *)
    set_ofp_meter_features_capabilities buf (Int32.of_int_exn (MeterFlags.marshal mfs.capabilities));
    set_ofp_meter_features_max_bands buf mfs.max_band;
    set_ofp_meter_features_max_color buf mfs.max_color;
    sizeof_ofp_meter_features

  let parse (bits : Cstruct.t) : t =
    { max_meter = get_ofp_meter_features_max_meter bits
    ; band_typ = Bands.parse (get_ofp_meter_features_band_types bits)
    (* int32 -> int fix, before release of OF1.3.5 *)
    ; capabilities = MeterFlags.parse (Int32.to_int_exn (get_ofp_meter_features_capabilities bits))
    ; max_band = get_ofp_meter_features_max_bands bits
    ; max_color = get_ofp_meter_features_max_color bits
    }
end

module MultipartReply = struct

  type t = multipartReply

  let sizeof (mpr : multipartReply) =
    sizeof_ofp_multipart_reply +
    match mpr.mpreply_typ with
    | PortsDescReply pdr -> sum (List.map ~f:PortDesc.sizeof pdr)
    | SwitchDescReply _ -> sizeof_ofp_desc
    | FlowStatsReply fsr -> sum (List.map ~f:FlowStats.sizeof fsr)
    | AggregateReply ag -> AggregateStats.sizeof ag
    | TableReply tr -> sum (List.map ~f:TableStats.sizeof tr)
    | TableFeaturesReply tf -> sum (List.map ~f:TableFeature.sizeof tf)
    | PortStatsReply psr -> sum (List.map ~f:PortStats.sizeof psr)
    | QueueStatsReply qsr -> sum (List.map ~f:QueueStats.sizeof qsr)
    | GroupStatsReply gs -> sum (List.map ~f:GroupStats.sizeof gs)
    | GroupDescReply gd -> sum (List.map ~f:GroupDesc.sizeof gd)
    | GroupFeaturesReply gf -> GroupFeatures.sizeof gf
    | MeterReply mr -> sum (List.map ~f:MeterStats.sizeof mr)
    | MeterConfig mc -> sum (List.map ~f:MeterConfig.sizeof mc)
    | MeterFeaturesReply mf -> MeterFeatures.sizeof mf

  let marshal (buf : Cstruct.t) (mpr : multipartReply) : int =
    let ofp_body_bits = Cstruct.shift buf sizeof_ofp_multipart_reply in
    set_ofp_multipart_reply_flags buf (
      match mpr.mpreply_flags with
      | true -> ofp_multipart_request_flags_to_int OFPMPF_REQ_MORE
      | false -> 0);
    sizeof_ofp_multipart_reply + (match mpr.mpreply_typ with
        | PortsDescReply pdr ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_PORT_DESC);
          marshal_fields ofp_body_bits pdr PortDesc.marshal
        | SwitchDescReply sdr ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_DESC);
          SwitchDescriptionReply.marshal ofp_body_bits sdr
        | FlowStatsReply fsr ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_FLOW);
          marshal_fields ofp_body_bits fsr FlowStats.marshal
        | AggregateReply ar ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_AGGREGATE);
          AggregateStats.marshal ofp_body_bits ar
        | TableReply tr ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_TABLE);
          marshal_fields ofp_body_bits tr TableStats.marshal
        | TableFeaturesReply tf ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_TABLE_FEATURES);
          marshal_fields ofp_body_bits tf TableFeature.marshal
        | PortStatsReply psr ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_PORT_STATS);
          marshal_fields ofp_body_bits psr PortStats.marshal
        | QueueStatsReply qsr ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_QUEUE);
          marshal_fields ofp_body_bits qsr QueueStats.marshal
        | GroupStatsReply gs ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_GROUP);
          marshal_fields ofp_body_bits gs GroupStats.marshal
        | GroupDescReply gd ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_GROUP_DESC);
          marshal_fields ofp_body_bits gd GroupDesc.marshal
        | GroupFeaturesReply gf ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_GROUP_FEATURES);
          GroupFeatures.marshal ofp_body_bits gf
        | MeterReply mr ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_METER);
          marshal_fields ofp_body_bits mr MeterStats.marshal
        | MeterConfig mc ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_METER_CONFIG);
          marshal_fields ofp_body_bits mc MeterConfig.marshal
        | MeterFeaturesReply mfr ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_METER_FEATURES);
          MeterFeatures.marshal ofp_body_bits mfr
      )

  let parse (bits : Cstruct.t) : multipartReply =
    let ofp_body_bits = Cstruct.shift bits sizeof_ofp_multipart_reply in
    let typ = (match int_to_ofp_multipart_types (get_ofp_multipart_reply_typ bits) with
        | Some OFPMP_PORT_DESC ->
          PortsDescReply (parse_fields ofp_body_bits PortDesc.parse PortDesc.length_func)
        | Some OFPMP_DESC ->
          SwitchDescReply (SwitchDescriptionReply.parse ofp_body_bits)
        | Some OFPMP_FLOW ->
          FlowStatsReply (parse_fields ofp_body_bits FlowStats.parse FlowStats.length_func)
        | Some OFPMP_AGGREGATE ->
          AggregateReply (AggregateStats.parse ofp_body_bits)
        | Some OFPMP_TABLE ->
          TableReply (parse_fields ofp_body_bits TableStats.parse TableStats.length_func)
        | Some OFPMP_TABLE_FEATURES ->
          TableFeaturesReply (parse_fields ofp_body_bits TableFeature.parse TableFeature.length_func)
        | Some OFPMP_PORT_STATS ->
          PortStatsReply (parse_fields ofp_body_bits PortStats.parse PortStats.length_func)
        | Some OFPMP_QUEUE ->
          QueueStatsReply (parse_fields ofp_body_bits QueueStats.parse QueueStats.length_func)
        | Some OFPMP_GROUP ->
          GroupStatsReply (parse_fields ofp_body_bits GroupStats.parse GroupStats.length_func)
        | Some OFPMP_GROUP_DESC ->
          GroupDescReply (parse_fields ofp_body_bits GroupDesc.parse GroupDesc.length_func)
        | Some OFPMP_GROUP_FEATURES ->
          GroupFeaturesReply (GroupFeatures.parse ofp_body_bits)
        | Some OFPMP_METER ->
          MeterReply (parse_fields ofp_body_bits MeterStats.parse MeterStats.length_func)
        | Some OFPMP_METER_CONFIG ->
          MeterConfig (parse_fields ofp_body_bits MeterConfig.parse MeterConfig.length_func)
        | Some OFPMP_METER_FEATURES ->
          MeterFeaturesReply (MeterFeatures.parse ofp_body_bits)
        | _ -> raise (Unparsable (sprintf "NYI: can't parse this multipart reply"))) in
    let flags = (
      match int_to_ofp_multipart_request_flags (get_ofp_multipart_request_flags bits) with
      | Some OFPMPF_REQ_MORE -> true
      | _ -> false) in
    {mpreply_typ = typ; mpreply_flags = flags}

end

module TableMod = struct

  cstruct ofp_table_mod {
    uint8_t table_id;
    uint8_t pad[3];
    uint32_t config
  } as big_endian

  type t = tableMod

  let sizeof (tab : tableMod) : int =
    sizeof_ofp_table_mod

  let marshal (buf : Cstruct.t) (tab : tableMod) : int =
    set_ofp_table_mod_table_id buf tab.table_id;
    set_ofp_table_mod_config buf (TableConfig.marshal tab.config);
    sizeof_ofp_table_mod

  let parse (bits : Cstruct.t) : tableMod =
    let table_id = get_ofp_table_mod_table_id bits in
    let config = TableConfig.parse (get_ofp_table_mod_config bits) in
    { table_id; config }

end

module QueueConfReq = struct

  cstruct ofp_queue_get_config_request {
    uint32_t port;
    uint8_t pad[4]
  } as big_endian

  type t = queueConfReq

  let sizeof (qr : t) : int =
    sizeof_ofp_queue_get_config_request

  let marshal (buf : Cstruct.t) (qr : t) : int =
    set_ofp_queue_get_config_request_port buf qr.port;
    sizeof_ofp_queue_get_config_request

  let parse (bits : Cstruct.t) : t =
    let port = get_ofp_queue_get_config_request_port bits in
    { port }
end

module QueueConfReply = struct

  cstruct ofp_queue_get_config_reply {
    uint32_t port;
    uint8_t pad[4];
  } as big_endian

  type t = queueConfReply

  let sizeof (qr : t) : int =
    sizeof_ofp_queue_get_config_reply + sum (List.map ~f:QueueDesc.sizeof qr.queues)

  let marshal (buf : Cstruct.t) (qr : t) : int =
    set_ofp_queue_get_config_reply_port buf qr.port;
    let queueBuf = Cstruct.shift buf sizeof_ofp_queue_get_config_reply in
    sizeof_ofp_queue_get_config_reply + (marshal_fields queueBuf qr.queues QueueDesc.marshal)

  let parse (bits : Cstruct.t) : t =
    let port = get_ofp_queue_get_config_reply_port bits in
    let queuesBits = Cstruct.shift bits sizeof_ofp_queue_get_config_reply in
    let queues = parse_fields queuesBits QueueDesc.parse QueueDesc.length_func in
    { port; queues}

end

module RoleRequest = struct

  cstruct ofp_role_request {
    uint32_t role;
    uint8_t pad[4];
    uint64_t generation_id
  } as big_endian

  module Role = struct
    cenum ofp_controller_role {
      OFPCR_ROLE_NOCHANGE = 0;
      OFPCR_ROLE_EQUAL = 1;
      OFPCR_ROLE_MASTER = 2;
      OFPCR_ROLE_SLAVE = 3
    } as uint32_t

    let marshal (role : controllerRole) : int32 =
      match role with
      | NoChangeRole -> ofp_controller_role_to_int OFPCR_ROLE_NOCHANGE
      | EqualRole -> ofp_controller_role_to_int OFPCR_ROLE_EQUAL
      | MasterRole -> ofp_controller_role_to_int OFPCR_ROLE_MASTER
      | SlaveRole -> ofp_controller_role_to_int OFPCR_ROLE_SLAVE

    let parse t : controllerRole =
      match int_to_ofp_controller_role t with
      | Some OFPCR_ROLE_NOCHANGE -> NoChangeRole
      | Some OFPCR_ROLE_EQUAL -> EqualRole
      | Some OFPCR_ROLE_MASTER -> MasterRole
      | Some OFPCR_ROLE_SLAVE -> SlaveRole
      | None -> raise (Unparsable (sprintf "malformed role"))

  end

  type t = roleRequest

  let sizeof (role : roleRequest) : int =
    sizeof_ofp_role_request

  let marshal (buf : Cstruct.t) (role : roleRequest) : int =
    set_ofp_role_request_role buf (Role.marshal role.role);
    set_ofp_role_request_generation_id buf role.generation_id;
    sizeof_ofp_role_request

  let parse (bits : Cstruct.t) : roleRequest =
    { role = Role.parse (get_ofp_role_request_role bits)
    ; generation_id = get_ofp_role_request_generation_id bits }
end

module Error = struct

  type t = error

      cstruct ofp_error_msg {
      uint16_t typ;
      uint16_t code
    } as big_endian

    cenum ofp_error_type {
      OFPET_HELLO_FAILED = 0;
      OFPET_BAD_REQUEST = 1;
      OFPET_BAD_ACTION = 2;
      OFPET_BAD_INSTRUCTION = 3;
      OFPET_BAD_MATCH = 4;
      OFPET_FLOW_MOD_FAILED = 5;
      OFPET_GROUP_MOD_FAILED = 6;
      OFPET_PORT_MOD_FAILED = 7;
      OFPET_TABLE_MOD_FAILED = 8;
      OFPET_QUEUE_OP_FAILED = 9;
      OFPET_SWITCH_CONFIG_FAILED = 10;
      OFPET_ROLE_REQUEST_FAILED = 11;
      OFPET_METER_MOD_FAILED = 12;
      OFPET_TABLE_FEATURES_FAILED = 13;
      OFPET_EXPERIMENTER = 0xffff
    } as uint16_t

  module HelloFailed = struct

    cenum ofp_hello_failed_code {
      OFPHFC_INCOMPATIBLE = 0;
      OFPHFC_EPERM = 1
    } as uint16_t

    type t = helloFailed

    let marshal (cod : helloFailed) : int =
      match cod with
      | HelloIncompatible -> ofp_hello_failed_code_to_int OFPHFC_INCOMPATIBLE
      | HelloPermError -> ofp_hello_failed_code_to_int OFPHFC_EPERM

    let parse t : helloFailed =
      match int_to_ofp_hello_failed_code t with
      | Some OFPHFC_INCOMPATIBLE -> HelloIncompatible
      | Some OFPHFC_EPERM -> HelloPermError
      | None -> raise (Unparsable (sprintf "malfomed hello_failed code"))

  end

  module BadRequest = struct

    cenum ofp_bad_request_code {
      OFPBRC_BAD_VERSION = 0;
      OFPBRC_BAD_TYPE = 1;
      OFPBRC_BAD_MULTIPART = 2;
      OFPBRC_BAD_EXPERIMENTER = 3;
      OFPBRC_BAD_EXP_TYPE = 4;
      OFPBRC_EPERM = 5;
      OFPBRC_BAD_LEN = 6;
      OFPBRC_BUFFER_EMPTY = 7;
      OFPBRC_BUFFER_UNKNOWN = 8;
      OFPBRC_BAD_TABLE_ID = 9;
      OFPBRC_IS_SLAVE = 10;
      OFPBRC_BAD_PORT = 11;
      OFPBRC_BAD_PACKET = 12;
      OFPBRC_MULTIPART_BUFFER_OVERFLOW = 13
    } as uint16_t

    type t = badRequest

    let marshal (cod : badRequest) : int =
      match cod with
      | ReqBadVersion -> ofp_bad_request_code_to_int OFPBRC_BAD_VERSION
      | ReqBadType -> ofp_bad_request_code_to_int OFPBRC_BAD_TYPE
      | ReqBadMultipart -> ofp_bad_request_code_to_int OFPBRC_BAD_MULTIPART
      | ReqBadExp -> ofp_bad_request_code_to_int OFPBRC_BAD_EXPERIMENTER
      | ReqBadExpType -> ofp_bad_request_code_to_int OFPBRC_BAD_EXP_TYPE
      | ReqPermError -> ofp_bad_request_code_to_int OFPBRC_EPERM
      | ReqBadLen -> ofp_bad_request_code_to_int OFPBRC_BAD_LEN
      | ReqBufferEmpty -> ofp_bad_request_code_to_int OFPBRC_BUFFER_EMPTY
      | ReqBufferUnknown -> ofp_bad_request_code_to_int OFPBRC_BUFFER_UNKNOWN
      | ReqBadTableId -> ofp_bad_request_code_to_int OFPBRC_BAD_TABLE_ID
      | ReqIsSlave -> ofp_bad_request_code_to_int OFPBRC_IS_SLAVE
      | ReqBadPort -> ofp_bad_request_code_to_int OFPBRC_BAD_PORT
      | ReqBadPacket -> ofp_bad_request_code_to_int OFPBRC_BAD_PACKET
      | ReqMultipartBufOverflow -> ofp_bad_request_code_to_int OFPBRC_MULTIPART_BUFFER_OVERFLOW

    let parse t : badRequest =
      match int_to_ofp_bad_request_code t with
      | Some OFPBRC_BAD_VERSION -> ReqBadVersion
      | Some OFPBRC_BAD_TYPE -> ReqBadType
      | Some OFPBRC_BAD_MULTIPART -> ReqBadMultipart
      | Some OFPBRC_BAD_EXPERIMENTER -> ReqBadExp
      | Some OFPBRC_BAD_EXP_TYPE -> ReqBadExpType
      | Some OFPBRC_EPERM -> ReqPermError
      | Some OFPBRC_BAD_LEN -> ReqBadLen
      | Some OFPBRC_BUFFER_EMPTY -> ReqBufferEmpty
      | Some OFPBRC_BUFFER_UNKNOWN -> ReqBufferUnknown
      | Some OFPBRC_BAD_TABLE_ID -> ReqBadTableId
      | Some OFPBRC_IS_SLAVE -> ReqIsSlave
      | Some OFPBRC_BAD_PORT -> ReqBadPort
      | Some OFPBRC_BAD_PACKET -> ReqBadPacket
      | Some OFPBRC_MULTIPART_BUFFER_OVERFLOW -> ReqMultipartBufOverflow
      | None -> raise (Unparsable (sprintf "malfomed bad_request code"))

  end

  module BadAction = struct

    cenum ofp_bad_action_code {
      OFPBAC_BAD_TYPE = 0;
      OFPBAC_BAD_LEN = 1;
      OFPBAC_BAD_EXPERIMENTER = 2;
      OFPBAC_BAD_EXP_TYPE = 3;
      OFPBAC_BAD_OUT_PORT = 4;
      OFPBAC_BAD_ARGUMENT = 5;
      OFPBAC_EPERM = 6;
      OFPBAC_TOO_MANY = 7;
      OFPBAC_BAD_QUEUE = 8;
      OFPBAC_BAD_OUT_GROUP = 9;
      OFPBAC_MATCH_INCONSISTENT = 10;
      OFPBAC_UNSUPPORTED_ORDER = 11;
      OFPBAC_BAD_TAG = 12;
      OFPBAC_BAD_SET_TYPE = 13;
      OFPBAC_BAD_SET_LEN = 14;
      OFPBAC_BAD_SET_ARGUMENT = 15
    } as uint16_t

    type t = badAction

    let marshal (cod : badAction) : int =
      match cod with
      | ActBadType -> ofp_bad_action_code_to_int OFPBAC_BAD_TYPE
      | ActBadLen -> ofp_bad_action_code_to_int OFPBAC_BAD_LEN
      | ActBadExp -> ofp_bad_action_code_to_int OFPBAC_BAD_EXPERIMENTER
      | ActBadExpType -> ofp_bad_action_code_to_int OFPBAC_BAD_EXP_TYPE
      | ActBadOutPort -> ofp_bad_action_code_to_int OFPBAC_BAD_OUT_PORT
      | ActBadArg -> ofp_bad_action_code_to_int OFPBAC_BAD_ARGUMENT
      | ActPermError -> ofp_bad_action_code_to_int OFPBAC_EPERM
      | ActTooMany -> ofp_bad_action_code_to_int OFPBAC_TOO_MANY
      | ActBadQueue -> ofp_bad_action_code_to_int OFPBAC_BAD_QUEUE
      | ActBadOutGroup -> ofp_bad_action_code_to_int OFPBAC_BAD_OUT_GROUP
      | ActMatchInconsistent -> ofp_bad_action_code_to_int OFPBAC_MATCH_INCONSISTENT
      | ActUnsupportedOrder -> ofp_bad_action_code_to_int OFPBAC_UNSUPPORTED_ORDER
      | ActBadTag -> ofp_bad_action_code_to_int OFPBAC_BAD_TAG
      | ActBadSetTyp -> ofp_bad_action_code_to_int OFPBAC_BAD_SET_TYPE
      | ActBadSetLen -> ofp_bad_action_code_to_int OFPBAC_BAD_SET_LEN
      | ActBadSetArg -> ofp_bad_action_code_to_int OFPBAC_BAD_SET_ARGUMENT

    let parse t : badAction =
      match int_to_ofp_bad_action_code t with
      | Some OFPBAC_BAD_TYPE -> ActBadType
      | Some OFPBAC_BAD_LEN -> ActBadLen
      | Some OFPBAC_BAD_EXPERIMENTER -> ActBadExp
      | Some OFPBAC_BAD_EXP_TYPE -> ActBadExpType
      | Some OFPBAC_BAD_OUT_PORT -> ActBadOutPort
      | Some OFPBAC_BAD_ARGUMENT -> ActBadArg
      | Some OFPBAC_EPERM -> ActPermError
      | Some OFPBAC_TOO_MANY -> ActTooMany
      | Some OFPBAC_BAD_QUEUE -> ActBadQueue
      | Some OFPBAC_BAD_OUT_GROUP -> ActBadOutGroup
      | Some OFPBAC_MATCH_INCONSISTENT -> ActMatchInconsistent
      | Some OFPBAC_UNSUPPORTED_ORDER -> ActUnsupportedOrder
      | Some OFPBAC_BAD_TAG -> ActBadTag
      | Some OFPBAC_BAD_SET_TYPE -> ActBadSetTyp
      | Some OFPBAC_BAD_SET_LEN -> ActBadSetLen
      | Some OFPBAC_BAD_SET_ARGUMENT -> ActBadSetArg
      | None -> raise (Unparsable (sprintf "malfomed bad_action code"))

  end

  module BadInstruction = struct

    cenum ofp_bad_instruction_code {
      OFPBIC_UNKNOWN_INST = 0;
      OFPBIC_UNSUP_INST = 1;
      OFPBIC_BAD_TABLE_ID = 2;
      OFPBIC_UNSUP_METADATA = 3;
      OFPBIC_UNSUP_METADATA_MASK = 4;
      OFPBIC_BAD_EXPERIMENTER = 5;
      OFPBIC_BAD_EXP_TYPE = 6;
      OFPBIC_BAD_LEN = 7;
      OFPBIC_EPERM = 8
    } as uint16_t

    type t = badInstruction

    let marshal (cod : badInstruction) : int =
      match cod with
      | InstUnknownInst -> ofp_bad_instruction_code_to_int OFPBIC_UNKNOWN_INST
      | InstBadTableId -> ofp_bad_instruction_code_to_int OFPBIC_BAD_TABLE_ID
      | InstUnsupInst -> ofp_bad_instruction_code_to_int OFPBIC_UNSUP_INST
      | InstUnsupMeta -> ofp_bad_instruction_code_to_int OFPBIC_UNSUP_METADATA
      | InstUnsupMetaMask -> ofp_bad_instruction_code_to_int OFPBIC_UNSUP_METADATA_MASK
      | InstBadExp -> ofp_bad_instruction_code_to_int OFPBIC_BAD_EXPERIMENTER
      | InstBadExpTyp -> ofp_bad_instruction_code_to_int OFPBIC_BAD_EXP_TYPE
      | InstBadLen -> ofp_bad_instruction_code_to_int OFPBIC_BAD_LEN
      | InstPermError -> ofp_bad_instruction_code_to_int OFPBIC_EPERM

    let parse t : badInstruction =
      match int_to_ofp_bad_instruction_code t with
      | Some OFPBIC_UNKNOWN_INST -> InstUnknownInst
      | Some OFPBIC_BAD_TABLE_ID -> InstBadTableId
      | Some OFPBIC_UNSUP_INST -> InstUnsupInst
      | Some OFPBIC_UNSUP_METADATA -> InstUnsupMeta
      | Some OFPBIC_UNSUP_METADATA_MASK -> InstUnsupMetaMask
      | Some OFPBIC_BAD_EXPERIMENTER -> InstBadExp
      | Some OFPBIC_BAD_EXP_TYPE -> InstBadExpTyp
      | Some OFPBIC_BAD_LEN -> InstBadLen
      | Some OFPBIC_EPERM -> InstPermError
      | None -> raise (Unparsable (sprintf "malfomed bad_instruction code"))

  end

  module BadMatch = struct

    cenum ofp_bad_match_code {
      OFPBMC_BAD_TYPE = 0;
      OFPBMC_BAD_LEN = 1;
      OFPBMC_BAD_TAG = 2;
      OFPBMC_BAD_DL_ADDR_MASK = 3;
      OFPBMC_BAD_NW_ADDR_MASK = 4;
      OFPBMC_BAD_WILDCARDS = 5;
      OFPBMC_BAD_FIELD = 6;
      OFPBMC_BAD_VALUE = 7;
      OFPBMC_BAD_MASK = 8;
      OFPBMC_BAD_PREREQ = 9;
      OFPBMC_DUP_FIELD = 10;
      OFPBMC_EPERM = 11
    } as uint16_t

    type t = badMatch

    let marshal (cod : badMatch) : int =
      match cod with
      | MatBadTyp -> ofp_bad_match_code_to_int OFPBMC_BAD_TYPE
      | MatBadLen -> ofp_bad_match_code_to_int OFPBMC_BAD_LEN
      | MatBadTag -> ofp_bad_match_code_to_int OFPBMC_BAD_TAG
      | MatBadDlAddrMask -> ofp_bad_match_code_to_int OFPBMC_BAD_DL_ADDR_MASK
      | MatBadNwAddrMask -> ofp_bad_match_code_to_int OFPBMC_BAD_NW_ADDR_MASK
      | MatBadWildcards -> ofp_bad_match_code_to_int OFPBMC_BAD_WILDCARDS
      | MatBadField -> ofp_bad_match_code_to_int OFPBMC_BAD_FIELD
      | MatBadValue -> ofp_bad_match_code_to_int OFPBMC_BAD_VALUE
      | MatBadMask -> ofp_bad_match_code_to_int OFPBMC_BAD_MASK
      | MatBadPrereq -> ofp_bad_match_code_to_int OFPBMC_BAD_PREREQ
      | MatDupField -> ofp_bad_match_code_to_int OFPBMC_DUP_FIELD
      | MatPermError -> ofp_bad_match_code_to_int OFPBMC_EPERM

    let parse t : badMatch =
      match int_to_ofp_bad_match_code t with
      | Some OFPBMC_BAD_TYPE -> MatBadTyp
      | Some OFPBMC_BAD_LEN -> MatBadLen
      | Some OFPBMC_BAD_TAG -> MatBadTag
      | Some OFPBMC_BAD_DL_ADDR_MASK -> MatBadDlAddrMask
      | Some OFPBMC_BAD_NW_ADDR_MASK -> MatBadNwAddrMask
      | Some OFPBMC_BAD_WILDCARDS -> MatBadWildcards
      | Some OFPBMC_BAD_FIELD -> MatBadField
      | Some OFPBMC_BAD_VALUE -> MatBadValue
      | Some OFPBMC_BAD_MASK -> MatBadMask
      | Some OFPBMC_BAD_PREREQ -> MatBadPrereq
      | Some OFPBMC_DUP_FIELD -> MatDupField
      | Some OFPBMC_EPERM -> MatPermError
      | None -> raise (Unparsable (sprintf "malfomed bad_match code"))

  end

  module FlowModFailed = struct

    cenum ofp_flow_mod_failed_code {
      OFPFMFC_UNKNOWN = 0;
      OFPFMFC_TABLE_FULL = 1;
      OFPFMFC_BAD_TABLE_ID = 2;
      OFPFMFC_OVERLAP = 3;
      OFPFMFC_EPERM = 4;
      OFPFMFC_BAD_TIMEOUT = 5;
      OFPFMFC_BAD_COMMAND = 6;
      OFPFMFC_BAD_FLAGS = 7
    } as uint16_t

    type t = flowModFailed

    let marshal (cod : flowModFailed) : int =
      match cod with
      | FlUnknown -> ofp_flow_mod_failed_code_to_int OFPFMFC_UNKNOWN
      | FlTableFull -> ofp_flow_mod_failed_code_to_int OFPFMFC_TABLE_FULL
      | FlBadTableId -> ofp_flow_mod_failed_code_to_int OFPFMFC_BAD_TABLE_ID
      | FlOverlap -> ofp_flow_mod_failed_code_to_int OFPFMFC_OVERLAP
      | FlPermError -> ofp_flow_mod_failed_code_to_int OFPFMFC_EPERM
      | FlBadTimeout -> ofp_flow_mod_failed_code_to_int OFPFMFC_BAD_TIMEOUT
      | FlBadCommand -> ofp_flow_mod_failed_code_to_int OFPFMFC_BAD_COMMAND
      | FlBadFlags  -> ofp_flow_mod_failed_code_to_int OFPFMFC_BAD_FLAGS

    let parse t : flowModFailed =
      match int_to_ofp_flow_mod_failed_code t with
      | Some OFPFMFC_UNKNOWN -> FlUnknown
      | Some OFPFMFC_TABLE_FULL -> FlTableFull
      | Some OFPFMFC_BAD_TABLE_ID -> FlBadTableId
      | Some OFPFMFC_OVERLAP -> FlOverlap
      | Some OFPFMFC_EPERM -> FlPermError
      | Some OFPFMFC_BAD_TIMEOUT -> FlBadTimeout
      | Some OFPFMFC_BAD_COMMAND -> FlBadCommand
      | Some OFPFMFC_BAD_FLAGS -> FlBadFlags
      | None -> raise (Unparsable (sprintf "malfomed flow mod failed code"))

  end

  module GroupModFailed = struct

    cenum ofp_group_mod_failed_code {
      OFPGMFC_GROUP_EXISTS = 0;
      OFPGMFC_INVALID_GROUP = 1;
      OFPGMFC_WEIGHT_UNSUPPORTED = 2;
      OFPGMFC_OUT_OF_GROUPS = 3;
      OFPGMFC_OUT_OF_BUCKETS = 4;
      OFPGMFC_CHAINING_UNSUPPORTED = 5;
      OFPGMFC_WATCH_UNSUPPORTED = 6;
      OFPGMFC_LOOP = 7;
      OFPGMFC_UNKNOWN_GROUP = 8;
      OFPGMFC_CHAINED_GROUP = 9;
      OFPGMFC_BAD_TYPE = 10;
      OFPGMFC_BAD_COMMAND = 11;
      OFPGMFC_BAD_BUCKET = 12;
      OFPGMFC_BAD_WATCH = 13;
      OFPGMFC_EPERM = 14
    } as uint16_t

    type t = groupModFailed

    let marshal (cod : groupModFailed) : int =
      match cod with
      | GrGroupExists -> ofp_group_mod_failed_code_to_int OFPGMFC_GROUP_EXISTS
      | GrInvalidGroup -> ofp_group_mod_failed_code_to_int OFPGMFC_INVALID_GROUP
      | GrWeightUnsupported -> ofp_group_mod_failed_code_to_int OFPGMFC_WEIGHT_UNSUPPORTED
      | GrOutOfGroups -> ofp_group_mod_failed_code_to_int OFPGMFC_OUT_OF_GROUPS
      | GrOutOfBuckets -> ofp_group_mod_failed_code_to_int OFPGMFC_OUT_OF_BUCKETS
      | GrChainingUnsupported -> ofp_group_mod_failed_code_to_int OFPGMFC_CHAINING_UNSUPPORTED
      | GrWatcHUnsupported -> ofp_group_mod_failed_code_to_int OFPGMFC_WATCH_UNSUPPORTED
      | GrLoop -> ofp_group_mod_failed_code_to_int OFPGMFC_LOOP
      | GrUnknownGroup -> ofp_group_mod_failed_code_to_int OFPGMFC_UNKNOWN_GROUP
      | GrChainedGroup -> ofp_group_mod_failed_code_to_int OFPGMFC_CHAINED_GROUP
      | GrBadTyp -> ofp_group_mod_failed_code_to_int OFPGMFC_BAD_TYPE
      | GrBadCommand -> ofp_group_mod_failed_code_to_int OFPGMFC_BAD_COMMAND
      | GrBadBucket -> ofp_group_mod_failed_code_to_int OFPGMFC_BAD_BUCKET
      | GrBadWatch -> ofp_group_mod_failed_code_to_int OFPGMFC_BAD_WATCH
      | GrPermError -> ofp_group_mod_failed_code_to_int OFPGMFC_EPERM

    let parse t : groupModFailed =
      match int_to_ofp_group_mod_failed_code t with
      | Some OFPGMFC_GROUP_EXISTS -> GrGroupExists
      | Some OFPGMFC_INVALID_GROUP -> GrInvalidGroup
      | Some OFPGMFC_WEIGHT_UNSUPPORTED -> GrWeightUnsupported
      | Some OFPGMFC_OUT_OF_GROUPS -> GrOutOfGroups
      | Some OFPGMFC_OUT_OF_BUCKETS -> GrOutOfBuckets
      | Some OFPGMFC_CHAINING_UNSUPPORTED -> GrChainingUnsupported
      | Some OFPGMFC_WATCH_UNSUPPORTED -> GrWatcHUnsupported
      | Some OFPGMFC_LOOP -> GrLoop
      | Some OFPGMFC_UNKNOWN_GROUP -> GrUnknownGroup
      | Some OFPGMFC_CHAINED_GROUP -> GrChainedGroup
      | Some OFPGMFC_BAD_TYPE -> GrBadTyp
      | Some OFPGMFC_BAD_COMMAND -> GrBadCommand
      | Some OFPGMFC_BAD_BUCKET -> GrBadBucket
      | Some OFPGMFC_BAD_WATCH -> GrBadWatch
      | Some OFPGMFC_EPERM -> GrPermError
      | None -> raise (Unparsable (sprintf "malfomed group mod failed code"))

  end

  module PortModFailed = struct

    cenum ofp_port_mod_failed_code {
      OFPPMFC_BAD_PORT = 0;
      OFPPMFC_BAD_HW_ADDR = 1;
      OFPPMFC_BAD_CONFIG = 2;
      OFPPMFC_BAD_ADVERTISE = 3;
      OFPPMFC_EPERM = 4
    } as uint16_t

    type t = portModFailed

    let marshal (cod : portModFailed) : int =
      match cod with
      | PoBadPort -> ofp_port_mod_failed_code_to_int OFPPMFC_BAD_PORT
      | PoBadHwAddr -> ofp_port_mod_failed_code_to_int OFPPMFC_BAD_HW_ADDR
      | PoBadConfig -> ofp_port_mod_failed_code_to_int OFPPMFC_BAD_CONFIG
      | PoBadAdvertise -> ofp_port_mod_failed_code_to_int OFPPMFC_BAD_ADVERTISE
      | PoPermError -> ofp_port_mod_failed_code_to_int OFPPMFC_EPERM

    let parse t : portModFailed =
      match int_to_ofp_port_mod_failed_code t with
      | Some OFPPMFC_BAD_PORT -> PoBadPort
      | Some OFPPMFC_BAD_HW_ADDR -> PoBadHwAddr
      | Some OFPPMFC_BAD_CONFIG -> PoBadConfig
      | Some OFPPMFC_BAD_ADVERTISE -> PoBadAdvertise
      | Some OFPPMFC_EPERM -> PoPermError
      | None -> raise (Unparsable (sprintf "malfomed port mod failed code"))

  end

  module TableModFailed = struct

    cenum ofp_table_mod_failed_code {
      OFPTMFC_BAD_TABLE = 0;
      OFPTMFC_BAD_CONFIG = 1;
      OFPTMFC_EPERM = 2
    } as uint16_t

    type t = tableModFailed

    let marshal (cod : tableModFailed) : int =
      match cod with
      | TaBadTable -> ofp_table_mod_failed_code_to_int OFPTMFC_BAD_TABLE
      | TaBadConfig -> ofp_table_mod_failed_code_to_int OFPTMFC_BAD_CONFIG
      | TaPermError -> ofp_table_mod_failed_code_to_int OFPTMFC_EPERM

    let parse t : tableModFailed =
      match int_to_ofp_table_mod_failed_code t with
      | Some OFPTMFC_BAD_TABLE -> TaBadTable
      | Some OFPTMFC_BAD_CONFIG -> TaBadConfig
      | Some OFPTMFC_EPERM -> TaPermError
      | None -> raise (Unparsable (sprintf "malfomed table mod failed code"))

  end

  module QueueOpFailed = struct

    cenum ofp_queue_op_failed_code {
      OFPQOFC_BAD_PORT = 0;
      OFPQOFC_BAD_QUEUE = 1;
      OFPQOFC_EPERM = 2
    } as uint16_t

    type t = queueOpFailed

    let marshal (cod : queueOpFailed) : int =
      match cod with
      | QuBadPort -> ofp_queue_op_failed_code_to_int OFPQOFC_BAD_PORT
      | QuBadQUeue -> ofp_queue_op_failed_code_to_int OFPQOFC_BAD_QUEUE
      | QuPermError -> ofp_queue_op_failed_code_to_int OFPQOFC_EPERM

    let parse t : queueOpFailed =
      match int_to_ofp_queue_op_failed_code t with
      | Some OFPQOFC_BAD_PORT -> QuBadPort
      | Some OFPQOFC_BAD_QUEUE -> QuBadQUeue
      | Some OFPQOFC_EPERM -> QuPermError
      | None -> raise (Unparsable (sprintf "malfomed queue op failed code"))

  end

  module SwitchConfigFailed = struct

    cenum ofp_switch_config_failed_code {
      OFPSCFC_BAD_FLAGS = 0;
      OFPSCFC_BAD_LEN = 1;
      OFPSCFC_EPERM = 2
    } as uint16_t

    type t = switchConfigFailed

    let marshal (cod : switchConfigFailed) : int =
      match cod with
      | ScBadFlags ->  ofp_switch_config_failed_code_to_int OFPSCFC_BAD_FLAGS
      | ScBadLen -> ofp_switch_config_failed_code_to_int OFPSCFC_BAD_LEN
      | ScPermError -> ofp_switch_config_failed_code_to_int OFPSCFC_EPERM

    let parse t : switchConfigFailed =
      match int_to_ofp_switch_config_failed_code t with
      | Some OFPSCFC_BAD_FLAGS -> ScBadFlags
      | Some OFPSCFC_BAD_LEN -> ScBadLen
      | Some OFPSCFC_EPERM -> ScPermError
      | None -> raise (Unparsable (sprintf "malfomed switch config failed code"))

  end

  module RoleReqFailed = struct

    cenum ofp_role_request_failed_code {
      OFPRRFC_STALE = 0;
      OFPRRFC_UNSUP = 1;
      OFPRRFC_BAD_ROLE = 2
    } as uint16_t

    type t = roleReqFailed

    let marshal (cod : roleReqFailed) : int =
      match cod with
      | RoStale -> ofp_role_request_failed_code_to_int OFPRRFC_STALE
      | RoUnsup -> ofp_role_request_failed_code_to_int OFPRRFC_UNSUP
      | RoBadRole -> ofp_role_request_failed_code_to_int OFPRRFC_BAD_ROLE

    let parse t : roleReqFailed =
      match int_to_ofp_role_request_failed_code t with
      | Some OFPRRFC_STALE -> RoStale
      | Some OFPRRFC_UNSUP -> RoUnsup
      | Some OFPRRFC_BAD_ROLE -> RoBadRole
      | None -> raise (Unparsable (sprintf "malfomed role request failed code"))

  end

  module MeterModFailed = struct

    cenum ofp_meter_mod_failed_code {
      OFPMMFC_UNKNOWN = 0;
      OFPMMFC_METER_EXISTS = 1;
      OFPMMFC_INVALID_METER = 2;
      OFPMMFC_UNKNOWN_METER = 3;
      OFPMMFC_BAD_COMMAND = 4;
      OFPMMFC_BAD_FLAGS = 5;
      OFPMMFC_BAD_RATE = 6;
      OFPMMFC_BAD_BURST = 7;
      OFPMMFC_BAD_BAND = 8;
      OFPMMFC_BAD_BAND_VALUE = 9;
      OFPMMFC_OUT_OF_METERS = 10;
      OFPMMFC_OUT_OF_BANDS = 11
    } as uint16_t

    type t = meterModFailed

    let marshal (cod : meterModFailed) : int =
      match cod with
      | MeUnknown -> ofp_meter_mod_failed_code_to_int OFPMMFC_UNKNOWN
      | MeMeterExists -> ofp_meter_mod_failed_code_to_int OFPMMFC_METER_EXISTS
      | MeInvalidMeter -> ofp_meter_mod_failed_code_to_int OFPMMFC_INVALID_METER
      | MeUnknownMeter -> ofp_meter_mod_failed_code_to_int OFPMMFC_UNKNOWN_METER
      | MeBadCommand -> ofp_meter_mod_failed_code_to_int OFPMMFC_BAD_COMMAND
      | MeBadFlags -> ofp_meter_mod_failed_code_to_int OFPMMFC_BAD_FLAGS
      | MeBadRate -> ofp_meter_mod_failed_code_to_int OFPMMFC_BAD_RATE
      | MeBadBurst -> ofp_meter_mod_failed_code_to_int OFPMMFC_BAD_BURST
      | MeBadBand -> ofp_meter_mod_failed_code_to_int OFPMMFC_BAD_BAND
      | MeBadBandValue -> ofp_meter_mod_failed_code_to_int OFPMMFC_BAD_BAND_VALUE
      | MeOutOfMeters -> ofp_meter_mod_failed_code_to_int OFPMMFC_OUT_OF_METERS
      | MeOutOfBands -> ofp_meter_mod_failed_code_to_int OFPMMFC_OUT_OF_BANDS

    let parse t : meterModFailed =
      match int_to_ofp_meter_mod_failed_code t with
      | Some OFPMMFC_UNKNOWN -> MeUnknown
      | Some OFPMMFC_METER_EXISTS -> MeMeterExists
      | Some OFPMMFC_INVALID_METER -> MeInvalidMeter
      | Some OFPMMFC_UNKNOWN_METER -> MeUnknownMeter
      | Some OFPMMFC_BAD_COMMAND -> MeBadCommand
      | Some OFPMMFC_BAD_FLAGS -> MeBadFlags
      | Some OFPMMFC_BAD_RATE -> MeBadRate
      | Some OFPMMFC_BAD_BURST -> MeBadBurst
      | Some OFPMMFC_BAD_BAND -> MeBadBand
      | Some OFPMMFC_BAD_BAND_VALUE -> MeBadBandValue
      | Some OFPMMFC_OUT_OF_METERS -> MeOutOfMeters
      | Some OFPMMFC_OUT_OF_BANDS -> MeOutOfBands
      | None -> raise (Unparsable (sprintf "malfomed meter mod failed code"))

  end

  module TableFeatFailed = struct

    cenum ofp_table_features_failed_code {
      OFPTFFC_BAD_TABLE = 0;
      OFPTFFC_BAD_METADATA = 1;
      OFPTFFC_BAD_TYPE = 2;
      OFPTFFC_BAD_LEN = 3;
      OFPTFFC_BAD_ARGUMENT = 4;
      OFPTFFC_EPERM = 5
    } as uint16_t

    type t = tableFeatFailed

    let marshal (cod : tableFeatFailed) : int =
      match cod with
      | TfBadTable -> ofp_table_features_failed_code_to_int OFPTFFC_BAD_TABLE
      | TfBadMeta -> ofp_table_features_failed_code_to_int OFPTFFC_BAD_METADATA
      | TfBadType -> ofp_table_features_failed_code_to_int OFPTFFC_BAD_TYPE
      | TfBadLen -> ofp_table_features_failed_code_to_int OFPTFFC_BAD_LEN
      | TfBadArg -> ofp_table_features_failed_code_to_int OFPTFFC_BAD_ARGUMENT
      | TfPermError -> ofp_table_features_failed_code_to_int OFPTFFC_EPERM

    let parse t : tableFeatFailed =
      match int_to_ofp_table_features_failed_code t with
      | Some OFPTFFC_BAD_TABLE -> TfBadTable
      | Some OFPTFFC_BAD_METADATA -> TfBadMeta
      | Some OFPTFFC_BAD_TYPE -> TfBadType
      | Some OFPTFFC_BAD_LEN -> TfBadLen
      | Some OFPTFFC_BAD_ARGUMENT -> TfBadArg
      | Some OFPTFFC_EPERM -> TfPermError
      | None -> raise (Unparsable (sprintf "malfomed table features failed code"))

  end

    cstruct ofp_error_experimenter_msg {
    uint16_t typ;
    uint16_t exp_type;
    uint32_t experimenter
  } as big_endian

  let experimenterFailed_to_string (exp : experimenterFailed) : string =
    Format.sprintf "Exp type : %u; exp ID: %lu"
      exp.exp_typ
      exp.exp_id

  let sizeof (t : t) : int =
    match t.err with
    | ExperimenterFailed _ -> sizeof_ofp_error_experimenter_msg + (Cstruct.len t.data)
    | _ -> sizeof_ofp_error_msg + (Cstruct.len t.data)

  let marshal (buf : Cstruct.t) (t : t) : int =
    match t.err with
    | HelloFailed h ->
      set_ofp_error_msg_typ buf (ofp_error_type_to_int OFPET_HELLO_FAILED);
      set_ofp_error_msg_code buf (HelloFailed.marshal h);
      let dataBuf = Cstruct.shift buf sizeof_ofp_error_msg in
      Cstruct.blit t.data 0 dataBuf 0 (Cstruct.len t.data);
      sizeof_ofp_error_msg + (Cstruct.len t.data)
    | BadRequest br ->
      set_ofp_error_msg_typ buf (ofp_error_type_to_int OFPET_BAD_REQUEST);
      set_ofp_error_msg_code buf (BadRequest.marshal br);
      let dataBuf = Cstruct.shift buf sizeof_ofp_error_msg in
      Cstruct.blit t.data 0 dataBuf 0 (Cstruct.len t.data);
      sizeof_ofp_error_msg + (Cstruct.len t.data)
    | BadAction ba ->
      set_ofp_error_msg_typ buf (ofp_error_type_to_int OFPET_BAD_ACTION);
      set_ofp_error_msg_code buf (BadAction.marshal ba);
      let dataBuf = Cstruct.shift buf sizeof_ofp_error_msg in
      Cstruct.blit t.data 0 dataBuf 0 (Cstruct.len t.data);
      sizeof_ofp_error_msg + (Cstruct.len t.data)
    | BadInstruction bi ->
      set_ofp_error_msg_typ buf (ofp_error_type_to_int OFPET_BAD_INSTRUCTION);
      set_ofp_error_msg_code buf (BadInstruction.marshal bi);
      let dataBuf = Cstruct.shift buf sizeof_ofp_error_msg in
      Cstruct.blit t.data 0 dataBuf 0 (Cstruct.len t.data);
      sizeof_ofp_error_msg + (Cstruct.len t.data)
    | BadMatch bm ->
      set_ofp_error_msg_typ buf (ofp_error_type_to_int OFPET_BAD_MATCH);
      set_ofp_error_msg_code buf (BadMatch.marshal bm);
      let dataBuf = Cstruct.shift buf sizeof_ofp_error_msg in
      Cstruct.blit t.data 0 dataBuf 0 (Cstruct.len t.data);
      sizeof_ofp_error_msg + (Cstruct.len t.data)
    | FlowModFailed fm ->
      set_ofp_error_msg_typ buf (ofp_error_type_to_int OFPET_FLOW_MOD_FAILED);
      set_ofp_error_msg_code buf (FlowModFailed.marshal fm);
      let dataBuf = Cstruct.shift buf sizeof_ofp_error_msg in
      Cstruct.blit t.data 0 dataBuf 0 (Cstruct.len t.data);
      sizeof_ofp_error_msg + (Cstruct.len t.data)
    | GroupModFailed gm ->
      set_ofp_error_msg_typ buf (ofp_error_type_to_int OFPET_GROUP_MOD_FAILED);
      set_ofp_error_msg_code buf (GroupModFailed.marshal gm);
      let dataBuf = Cstruct.shift buf sizeof_ofp_error_msg in
      Cstruct.blit t.data 0 dataBuf 0 (Cstruct.len t.data);
      sizeof_ofp_error_msg + (Cstruct.len t.data)
    | PortModFailed pm ->
      set_ofp_error_msg_typ buf (ofp_error_type_to_int OFPET_PORT_MOD_FAILED);
      set_ofp_error_msg_code buf (PortModFailed.marshal pm);
      let dataBuf = Cstruct.shift buf sizeof_ofp_error_msg in
      Cstruct.blit t.data 0 dataBuf 0 (Cstruct.len t.data);
      sizeof_ofp_error_msg + (Cstruct.len t.data)
    | TableModFailed tm ->
      set_ofp_error_msg_typ buf (ofp_error_type_to_int OFPET_TABLE_MOD_FAILED);
      set_ofp_error_msg_code buf (TableModFailed.marshal tm);
      let dataBuf = Cstruct.shift buf sizeof_ofp_error_msg in
      Cstruct.blit t.data 0 dataBuf 0 (Cstruct.len t.data);
      sizeof_ofp_error_msg + (Cstruct.len t.data)
    | QueueOpFailed qo ->
      set_ofp_error_msg_typ buf (ofp_error_type_to_int OFPET_QUEUE_OP_FAILED);
      set_ofp_error_msg_code buf (QueueOpFailed.marshal qo);
      let dataBuf = Cstruct.shift buf sizeof_ofp_error_msg in
      Cstruct.blit t.data 0 dataBuf 0 (Cstruct.len t.data);
      sizeof_ofp_error_msg + (Cstruct.len t.data)
    | SwitchConfigFailed sc ->
      set_ofp_error_msg_typ buf (ofp_error_type_to_int OFPET_SWITCH_CONFIG_FAILED);
      set_ofp_error_msg_code buf (SwitchConfigFailed.marshal sc);
      let dataBuf = Cstruct.shift buf sizeof_ofp_error_msg in
      Cstruct.blit t.data 0 dataBuf 0 (Cstruct.len t.data);
      sizeof_ofp_error_msg + (Cstruct.len t.data)
    | RoleReqFailed rr ->
      set_ofp_error_msg_typ buf (ofp_error_type_to_int OFPET_ROLE_REQUEST_FAILED);
      set_ofp_error_msg_code buf (RoleReqFailed.marshal rr);
      let dataBuf = Cstruct.shift buf sizeof_ofp_error_msg in
      Cstruct.blit t.data 0 dataBuf 0 (Cstruct.len t.data);
      sizeof_ofp_error_msg + (Cstruct.len t.data)
    | MeterModFailed mm ->
      set_ofp_error_msg_typ buf (ofp_error_type_to_int OFPET_METER_MOD_FAILED);
      set_ofp_error_msg_code buf (MeterModFailed.marshal mm);
      let dataBuf = Cstruct.shift buf sizeof_ofp_error_msg in
      Cstruct.blit t.data 0 dataBuf 0 (Cstruct.len t.data);
      sizeof_ofp_error_msg + (Cstruct.len t.data)
    | TableFeatFailed tf ->
      set_ofp_error_msg_typ buf (ofp_error_type_to_int OFPET_TABLE_FEATURES_FAILED);
      set_ofp_error_msg_code buf (TableFeatFailed.marshal tf);
      let dataBuf = Cstruct.shift buf sizeof_ofp_error_msg in
      Cstruct.blit t.data 0 dataBuf 0 (Cstruct.len t.data);
      sizeof_ofp_error_msg + (Cstruct.len t.data)
    | ExperimenterFailed e ->
      set_ofp_error_experimenter_msg_typ buf (ofp_error_type_to_int OFPET_EXPERIMENTER);
      set_ofp_error_experimenter_msg_exp_type buf e.exp_typ;
      set_ofp_error_experimenter_msg_experimenter buf e.exp_id;
      let dataBuf = Cstruct.shift buf sizeof_ofp_error_experimenter_msg in
      Cstruct.blit t.data 0 dataBuf 0 (Cstruct.len t.data);
      sizeof_ofp_error_experimenter_msg + (Cstruct.len t.data)

  let parse (bits : Cstruct.t) : t =
    let typ = get_ofp_error_msg_typ bits in
    let code = get_ofp_error_msg_code bits in
    let err =  match int_to_ofp_error_type typ with
      | Some OFPET_HELLO_FAILED -> HelloFailed (HelloFailed.parse code)
      | Some OFPET_BAD_REQUEST -> BadRequest (BadRequest.parse code)
      | Some OFPET_BAD_ACTION -> BadAction (BadAction.parse code)
      | Some OFPET_BAD_INSTRUCTION -> BadInstruction (BadInstruction.parse code)
      | Some OFPET_BAD_MATCH -> BadMatch (BadMatch.parse code)
      | Some OFPET_FLOW_MOD_FAILED -> FlowModFailed (FlowModFailed.parse code)
      | Some OFPET_GROUP_MOD_FAILED -> GroupModFailed (GroupModFailed.parse code)
      | Some OFPET_PORT_MOD_FAILED -> PortModFailed (PortModFailed.parse code)
      | Some OFPET_TABLE_MOD_FAILED -> TableModFailed (TableModFailed.parse code)
      | Some OFPET_QUEUE_OP_FAILED -> QueueOpFailed (QueueOpFailed.parse code)
      | Some OFPET_SWITCH_CONFIG_FAILED -> SwitchConfigFailed (SwitchConfigFailed.parse code)
      | Some OFPET_ROLE_REQUEST_FAILED -> RoleReqFailed (RoleReqFailed.parse code)
      | Some OFPET_METER_MOD_FAILED -> MeterModFailed (MeterModFailed.parse code)
      | Some OFPET_TABLE_FEATURES_FAILED -> TableFeatFailed (TableFeatFailed.parse code)
      | Some OFPET_EXPERIMENTER -> (
          let exp_typ = get_ofp_error_experimenter_msg_exp_type bits in
          let exp_id = get_ofp_error_experimenter_msg_experimenter bits in
          ExperimenterFailed ({exp_typ; exp_id}) )
      | None -> raise (Unparsable (sprintf "malfomed type error")) in
    let err_bits = match err with
      | ExperimenterFailed _ -> Cstruct.shift bits sizeof_ofp_error_experimenter_msg
      | _ -> Cstruct.shift bits sizeof_ofp_error_msg in
    let data = Cstruct.create (Cstruct.len err_bits) in
    (* create a new Cstruct to set the offset to 0 *)
    Cstruct.blit err_bits 0 data 0 (Cstruct.len err_bits);
    { err; data }

end

module Hello = struct

  module Element = struct

    cstruct ofp_hello_elem_header {
      uint16_t typ;
      uint16_t len
    } as big_endian

    cenum ofp_hello_elem_type {
      OFPHET_VERSIONBITMAP = 1
    } as uint16_t

    module VersionBitMap = struct

      type t = supportedList

      let sizeof (l : supportedList) : int =
        match l with
        | [] -> 0
        | t::q -> ((t / 32 ) + 1 ) * 4

      let marshal (buf : Cstruct.t) (t : supportedList) : int =
        let rec marshal_bitmap (ls : supportedList) acc curr =
          match ls,curr with
          | [],0 ->
            set_ofp_uint32_value buf acc;
          | [],n->
            set_ofp_uint32_value (Cstruct.shift buf (4*n)) acc;
            marshal_bitmap [] 0l (n-1)
          | t::q,n ->
            if t / 32 <> n then (
              set_ofp_uint32_value (Cstruct.shift buf (4*n)) acc;
              marshal_bitmap ls 0l (n-1))
            else (
              let acc = Int32.bit_or (Int32.shift_left 1l (t mod 32)) acc in
              marshal_bitmap q acc n
            ) in
        marshal_bitmap t 0l (List.hd_exn t / 32);
        ((List.hd_exn t / 32) + 1) * 4

      let parse (bits : Cstruct.t) : supportedList =
        let rec parse_uint32 (bits : Cstruct.t) index curr (acc : supportedList) : supportedList =
          if Cstruct.len bits < sizeof_ofp_uint32 then acc
          else (
            let acc = if Frenetic_Bits.test_bit index (get_ofp_uint32_value bits) then
                (index+(curr*32))::acc
              else acc in
            if index = 31 then
              parse_uint32 (Cstruct.shift bits 4) 0 (curr+1) acc
            else
              parse_uint32 bits (index+1) (curr) acc) in
        parse_uint32 bits 0 0 []

    end
    type t = element

    let sizeof (t : element) : int =
      let size = sizeof_ofp_hello_elem_header + (
          match t with
          | VersionBitMap v ->
            VersionBitMap.sizeof v) in
      pad_to_64bits size

    let length_func (buf : Cstruct.t) : int option =
      if Cstruct.len buf < sizeof_ofp_hello_elem_header then None
      else Some (pad_to_64bits (get_ofp_hello_elem_header_len buf))

    let marshal (buf : Cstruct.t) (t : element) : int =
      match t with
      | VersionBitMap v ->
        set_ofp_hello_elem_header_typ buf (ofp_hello_elem_type_to_int OFPHET_VERSIONBITMAP);
        set_ofp_hello_elem_header_len buf (sizeof_ofp_hello_elem_header +
                                           VersionBitMap.marshal (Cstruct.shift buf sizeof_ofp_hello_elem_header) v);
        sizeof t

    let parse (bits : Cstruct.t) : element =
      let typ = get_ofp_hello_elem_header_typ bits in
      let len = get_ofp_hello_elem_header_len bits in
      let payBits = Cstruct.sub bits sizeof_ofp_hello_elem_header (len - sizeof_ofp_hello_elem_header) in
      match int_to_ofp_hello_elem_type typ with
      | Some OFPHET_VERSIONBITMAP -> VersionBitMap (VersionBitMap.parse payBits)
      | None -> raise (Unparsable (sprintf "malformed type"))

  end

  type t = helloElement

  let sizeof (t : helloElement) : int =
    sum (List.map ~f:Element.sizeof t)

  let marshal (buf : Cstruct.t) (t : helloElement) : int =
    marshal_fields buf t Element.marshal

  let parse (bits : Cstruct.t) : helloElement =
    parse_fields bits Element.parse Element.length_func

end

module AsyncConfig = struct

  module PacketIn = struct
    type t = packetInReasonMap

    let marshal (t : t) : int8 =
      (if t.table_miss then 1 lsl 0 else 0) lor
      (if t.apply_action then 1 lsl 1 else 0) lor
      (if t.invalid_ttl then 1 lsl 2 else 0)

    let parse bits : t =
      { table_miss = test_bit16 0 bits
      ; apply_action = test_bit16 1 bits
      ; invalid_ttl = test_bit16 2 bits}

  end

  module PortStatus = struct

    type t = portReasonMap

    let marshal (t : t) : int8 =
      (if t.add then 1 lsl 0 else 0) lor
      (if t.delete then 1 lsl 1 else 0) lor
      (if t.modify then 1 lsl 2 else 0)

    let parse bits : t =
      { add = test_bit16 0 bits
      ; delete = test_bit16 1 bits
      ; modify = test_bit16 2 bits }

  end

  module FlowRemoved = struct

    type t = flowReasonMask

    let marshal (t : t) : int8 =
      (if t.idle_timeout then 1 lsl 0 else 0) lor
      (if t.hard_timeout then 1 lsl 1 else 0) lor
      (if t.delete then 1 lsl 2 else 0) lor
      (if t.group_delete then 1 lsl 3 else 0)

    let parse bits : t =
      { idle_timeout = test_bit16 0 bits
      ; hard_timeout = test_bit16 1 bits
      ; delete = test_bit16 2 bits
      ; group_delete = test_bit16 3 bits }

  end

    cstruct ofp_async_config {
    uint32_t packet_in_mask0;
    uint32_t packet_in_mask1;
    uint32_t port_status_mask0;
    uint32_t port_status_mask1;
    uint32_t flow_removed_mask0;
    uint32_t flow_removed_mask1;
  } as big_endian

  type t = asyncConfig

  let sizeof (async : asyncConfig) : int =
    sizeof_ofp_async_config

  let marshal (buf : Cstruct.t) (async : asyncConfig) : int =
    set_ofp_async_config_packet_in_mask0 buf (Int32.of_int_exn (PacketIn.marshal async.packet_in.m_master));
    set_ofp_async_config_packet_in_mask1 buf (Int32.of_int_exn (PacketIn.marshal async.packet_in.m_slave));
    set_ofp_async_config_port_status_mask0 buf (Int32.of_int_exn (PortStatus.marshal async.port_status.m_master));
    set_ofp_async_config_port_status_mask1 buf (Int32.of_int_exn (PortStatus.marshal async.port_status.m_slave));
    set_ofp_async_config_flow_removed_mask0 buf (Int32.of_int_exn (FlowRemoved.marshal async.flow_removed.m_master));
    set_ofp_async_config_flow_removed_mask1 buf (Int32.of_int_exn (FlowRemoved.marshal async.flow_removed.m_slave));
    sizeof_ofp_async_config

  let parse (bits : Cstruct.t) : asyncConfig =
    let packet_in = { m_master = PacketIn.parse (Int32.to_int_exn (get_ofp_async_config_packet_in_mask0 bits));
                      m_slave = PacketIn.parse (Int32.to_int_exn (get_ofp_async_config_packet_in_mask1 bits))} in
    let port_status = { m_master = PortStatus.parse (Int32.to_int_exn (get_ofp_async_config_port_status_mask0 bits));
                        m_slave = PortStatus.parse (Int32.to_int_exn (get_ofp_async_config_port_status_mask1 bits))} in
    let flow_removed = { m_master = FlowRemoved.parse (Int32.to_int_exn (get_ofp_async_config_flow_removed_mask0 bits));
                         m_slave = FlowRemoved.parse (Int32.to_int_exn (get_ofp_async_config_flow_removed_mask1 bits))} in
    { packet_in; port_status; flow_removed }

end

module Message = struct

  type t = message

  let string_of_msg_code (msg : msg_code) : string = match msg with
    | HELLO -> "HELLO"
    | ECHO_REQ -> "ECHO_REQ"
    | ECHO_RESP -> "ECHO_RESP"
    | FEATURES_REQ -> "FEATURES_REQ"
    | FEATURES_RESP -> "FEATURES_RESP"
    | FLOW_MOD -> "FLOW_MOD"
    | GROUP_MOD -> "GROUP_MOD"
    | PACKET_IN -> "PACKET_IN"
    | PACKET_OUT -> "PACKET_OUT"
    | PORT_STATUS -> "PORT_STATUS"
    | MULTIPART_REQ -> "MULTIPART_REQ"
    | MULTIPART_RESP -> "MULTIPART_RESP"
    | BARRIER_REQ -> "BARRIER_REQ"
    | BARRIER_RESP -> "BARRIER_RESP"
    | ERROR -> "ERROR"
    | VENDOR -> "VENDOR"
    | GET_CONFIG_REQ -> "GET_CONFIG_REQ"
    | GET_CONFIG_RESP -> "GET_CONFIG_RESP"
    | SET_CONFIG -> "SET_CONFIG"
    | FLOW_REMOVED -> "FLOW_REMOVED"
    | PORT_MOD -> "PORT_MOD"
    | TABLE_MOD -> "TABLE_MOD"
    | QUEUE_GET_CONFIG_REQ -> "QUEUE_GET_CONFIG_REQ"
    | QUEUE_GET_CONFIG_RESP -> "QUEUE_GET_CONFIG_RESP"
    | ROLE_REQ -> "ROLE_REQ"
    | ROLE_RESP -> "ROLE_RESP"
    | GET_ASYNC_REQ -> "GET_ASYNC_REQ"
    | GET_ASYNC_REP -> "GET_ASYNC_REP"
    | SET_ASYNC -> "SET_ASYNC"
    | METER_MOD -> "METER_MOD"

  module Header = Frenetic_OpenFlow_Header

  let msg_code_of_message (msg : t) : msg_code = match msg with
    | Hello _ -> HELLO
    | EchoRequest _ -> ECHO_REQ
    | EchoReply _ -> ECHO_RESP
    | FeaturesRequest -> FEATURES_REQ
    | FeaturesReply _ -> FEATURES_RESP
    | FlowModMsg _ -> FLOW_MOD
    | GroupModMsg _ -> GROUP_MOD
    | PortModMsg _ -> PORT_MOD
    | MeterModMsg _ -> METER_MOD
    | PacketInMsg _ -> PACKET_IN
    | FlowRemoved _ -> FLOW_REMOVED
    | PacketOutMsg _ -> PACKET_OUT
    | PortStatusMsg _ ->   PORT_STATUS
    | MultipartReq _ -> MULTIPART_REQ
    | MultipartReply _ -> MULTIPART_RESP
    | BarrierRequest ->   BARRIER_REQ
    | BarrierReply ->   BARRIER_RESP
    | QueueGetConfigReq _ -> QUEUE_GET_CONFIG_REQ
    | QueueGetConfigReply _ -> QUEUE_GET_CONFIG_RESP
    | GetConfigRequestMsg -> GET_CONFIG_REQ
    | GetConfigReplyMsg _ -> GET_CONFIG_RESP
    | SetConfigMsg _ -> SET_CONFIG
    | TableModMsg _ -> TABLE_MOD
    | GetAsyncRequest -> GET_ASYNC_REQ
    | GetAsyncReply _ -> GET_ASYNC_REP
    | SetAsync _ -> SET_ASYNC
    | Error _ -> ERROR
    | RoleRequest _ -> ROLE_REQ
    | RoleReply _ -> ROLE_RESP

  let sizeof (msg : t) : int = match msg with
    | Hello e -> Header.size + Hello.sizeof e
    | EchoRequest bytes -> Header.size + (String.length (Cstruct.to_string bytes))
    | EchoReply bytes -> Header.size + (String.length (Cstruct.to_string bytes))
    | FeaturesRequest -> Header.size
    | FeaturesReply f -> Header.size + SwitchFeatures.sizeof f
    | FlowModMsg fm -> Header.size + FlowMod.sizeof fm
    | GroupModMsg gm -> Header.size + GroupMod.sizeof gm
    | PortModMsg pm -> Header.size + PortMod.sizeof pm
    | MeterModMsg mm -> Header.size + MeterMod.sizeof mm
    | PacketInMsg pi -> Header.size + PacketIn.sizeof pi
    | FlowRemoved fr -> Header.size + FlowRemoved.sizeof fr
    | PacketOutMsg po -> Header.size + PacketOut.sizeof po
    | PortStatusMsg p -> Header.size + PortStatus.sizeof p
    | MultipartReq req -> Header.size + MultipartReq.sizeof req
    | MultipartReply rep -> Header.size + MultipartReply.sizeof rep
    | QueueGetConfigReq qc -> Header.size + QueueConfReq.sizeof qc
    | QueueGetConfigReply qc -> Header.size + QueueConfReply.sizeof qc
    | GetConfigRequestMsg -> Header.size
    | GetConfigReplyMsg conf -> Header.size + SwitchConfig.sizeof conf
    | SetConfigMsg conf -> Header.size + SwitchConfig.sizeof conf
    | TableModMsg tm -> Header.size + TableMod.sizeof tm
    | BarrierRequest -> Header.size
    | BarrierReply -> Header.size
    | GetAsyncRequest -> Header.size
    | GetAsyncReply async -> Header.size + AsyncConfig.sizeof async
    | SetAsync async -> Header.size + AsyncConfig.sizeof async
    | Error err -> Header.size + Error.sizeof err
    | RoleRequest rr -> Header.size + RoleRequest.sizeof rr
    | RoleReply rr -> Header.size + RoleRequest.sizeof rr

  (* let marshal (buf : Cstruct.t) (msg : message) : int = *)
  (*   let buf2 = (Cstruct.shift buf Header.size) in *)
  (*   set_ofp_header_version buf 0x04; *)
  (*   set_ofp_header_typ buf (msg_code_to_int (msg_code_of_message msg)); *)
  (*   set_ofp_header_length buf (sizeof msg); *)

  let blit_message (msg : t) (out : Cstruct.t) =
    match msg with
    | Hello e ->
      Header.size + Hello.marshal out e
    | EchoRequest bytes
    | EchoReply bytes ->
      Cstruct.blit_from_string (Cstruct.to_string bytes) 0 out 0 (String.length (Cstruct.to_string bytes));
      Header.size + String.length (Cstruct.to_string bytes)
    | FeaturesRequest ->
      Header.size
    | FeaturesReply fr ->
      Header.size + SwitchFeatures.marshal out fr
    | FlowModMsg fm ->
      Header.size + FlowMod.marshal out fm
    | GroupModMsg gm ->
      Header.size + GroupMod.marshal out gm
    | PortModMsg pm ->
      Header.size + PortMod.marshal out pm
    | MeterModMsg mm ->
      Header.size + MeterMod.marshal out mm
    | PacketOutMsg po ->
      Header.size + PacketOut.marshal out po
    | MultipartReq mpr ->
      Header.size + MultipartReq.marshal out mpr
    | BarrierRequest ->
      Header.size
    | BarrierReply ->
      Header.size
    | MultipartReply mpr ->
      Header.size + MultipartReply.marshal out mpr
    | QueueGetConfigReq qr ->
      Header.size + QueueConfReq.marshal out qr
    | QueueGetConfigReply qr ->
      Header.size + QueueConfReply.marshal out qr
    | PacketInMsg pi ->
      Header.size + PacketIn.marshal out pi
    | PortStatusMsg ps ->
      Header.size + PortStatus.marshal out ps
    | RoleRequest rr ->
      Header.size + RoleRequest.marshal out rr
    | RoleReply rr ->
      Header.size + RoleRequest.marshal out rr
    | GetConfigRequestMsg ->
      Header.size
    | GetConfigReplyMsg conf ->
      Header.size + SwitchConfig.marshal out conf
    | SetConfigMsg conf ->
      Header.size + SwitchConfig.marshal out conf
    | TableModMsg tm ->
      Header.size + TableMod.marshal out tm
    | FlowRemoved fr ->
      Header.size + FlowRemoved.marshal out fr
    | GetAsyncRequest ->
      Header.size
    | GetAsyncReply async ->
      Header.size + AsyncConfig.marshal out async
    | SetAsync async ->
      Header.size + AsyncConfig.marshal out async
    | Error err ->
      Header.size + Error.marshal out err


  let header_of xid msg =
    let open Header in
    { version = 0x04; type_code = msg_code_to_int (msg_code_of_message msg);
      length = sizeof msg; xid = xid }

  let marshal_body (msg : t) (buf : Cstruct.t) =
    let _ = blit_message msg buf in
    ()

  let marshal (xid : xid) (msg : t) : string =
    let sizeof_buf = sizeof msg in
    let hdr = header_of xid msg in
    let buf = Cstruct.create sizeof_buf in
    Header.marshal buf hdr;
    let _ = blit_message msg (Cstruct.shift buf Header.size) in
    Cstruct.to_string buf

  let parse (hdr : Header.t) (body_buf : string) : (xid * t) =
    let body_bits = Cstruct.of_string body_buf in
    let typ = match int_to_msg_code hdr.Header.type_code with
      | Some code -> code
      | None -> raise (Unparsable "unknown message code") in
    let msg = match typ with
      | HELLO -> Hello (Hello.parse body_bits)
      | ECHO_RESP -> EchoReply body_bits
      | FEATURES_RESP -> FeaturesReply (SwitchFeatures.parse body_bits)
      | FLOW_MOD -> FlowModMsg (FlowMod.parse body_bits)
      | GROUP_MOD -> GroupModMsg (GroupMod.parse body_bits)
      | PORT_MOD -> PortModMsg (PortMod.parse body_bits)
      | METER_MOD -> MeterModMsg (MeterMod.parse body_bits)
      | PACKET_IN -> PacketInMsg (PacketIn.parse body_bits)
      | PACKET_OUT -> PacketOutMsg (PacketOut.parse body_bits)
      | ECHO_REQ -> EchoRequest body_bits
      | PORT_STATUS -> PortStatusMsg (PortStatus.parse body_bits)
      | MULTIPART_REQ -> MultipartReq (MultipartReq.parse body_bits)
      | MULTIPART_RESP -> MultipartReply (MultipartReply.parse body_bits)
      | QUEUE_GET_CONFIG_REQ -> QueueGetConfigReq (QueueConfReq.parse body_bits)
      | QUEUE_GET_CONFIG_RESP -> QueueGetConfigReply (QueueConfReply.parse body_bits)
      | BARRIER_REQ -> BarrierRequest
      | BARRIER_RESP -> BarrierReply
      | ERROR -> Error (Error.parse body_bits)
      | ROLE_REQ -> RoleRequest (RoleRequest.parse body_bits)
      | ROLE_RESP -> RoleReply (RoleRequest.parse body_bits)
      | GET_CONFIG_RESP -> GetConfigReplyMsg (SwitchConfig.parse body_bits)
      | SET_CONFIG -> SetConfigMsg (SwitchConfig.parse body_bits)
      | TABLE_MOD -> TableModMsg (TableMod.parse body_bits)
      | FLOW_REMOVED -> FlowRemoved (FlowRemoved.parse body_bits)
      | GET_ASYNC_REQ -> GetAsyncRequest
      | GET_ASYNC_REP -> GetAsyncReply (AsyncConfig.parse body_bits)
      | SET_ASYNC -> SetAsync (AsyncConfig.parse body_bits)
      | code -> raise (Unparsable (Printf.sprintf "unexpected message type %s" (string_of_msg_code typ))) in
    (hdr.Header.xid, msg)
end

let portDescReq =
  { mpr_type = PortsDescReq
  ; mpr_flags = false }

let portsDescRequest = MultipartReq portDescReq
