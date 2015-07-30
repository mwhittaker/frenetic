open Core.Std
open Frenetic_OpenFlow0x04
open Frenetic_Packet

val val_to_mask : 'a1 -> 'a1 mask

val ip_to_mask : (nwAddr * int32) -> nwAddr mask

type msg_code =  | HELLO | ERROR | ECHO_REQ | ECHO_RESP | VENDOR | FEATURES_REQ
               | FEATURES_RESP | GET_CONFIG_REQ | GET_CONFIG_RESP
               | SET_CONFIG | PACKET_IN | FLOW_REMOVED | PORT_STATUS | PACKET_OUT
               | FLOW_MOD | GROUP_MOD | PORT_MOD | TABLE_MOD | MULTIPART_REQ
               | MULTIPART_RESP | BARRIER_REQ | BARRIER_RESP | QUEUE_GET_CONFIG_REQ
               | QUEUE_GET_CONFIG_RESP | ROLE_REQ | ROLE_RESP | GET_ASYNC_REQ
               | GET_ASYNC_REP | SET_ASYNC | METER_MOD

module Message : sig

  type t = message

  val sizeof : t -> int

  val blit_message : t -> Cstruct.t -> int

  val header_of : xid -> t -> Frenetic_OpenFlow_Header.t

  val marshal : xid -> t -> string

  val parse : Frenetic_OpenFlow_Header.t -> string -> (xid * t)

  val marshal_body : t -> Cstruct.t -> unit

end
