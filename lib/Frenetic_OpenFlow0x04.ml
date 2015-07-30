(* TODO(???): rename sizeof to size_of for consistency with 0x01 stuff. *)

(** OpenFlow 1.3 (protocol version 0x04) *)

open Printf
open Frenetic_Packet

(* If we used [@@deriving show] in Frenetic_Packet, we wouldn't have to write
   these *)
let pp_int48 fmt n = Format.fprintf fmt "%Lx" n
let pp_int16 fmt n = Format.fprintf fmt "%n" n
let pp_int8 fmt n = Format.fprintf fmt "%n" n
type cstruct = Cstruct.t
let pp_cstruct fmt (b : Cstruct.t) = Format.fprintf fmt "%s" (Cstruct.to_string b)

type 'a mask = { m_value : 'a; m_mask : 'a option } [@@deriving show]

type 'a asyncMask = { m_master : 'a ; m_slave : 'a } [@@deriving show]

type payload =
  | Buffered of int32 * (cstruct )
  | NotBuffered of cstruct
  [@@deriving show]

type xid = Frenetic_OpenFlow_Header.xid

type int12 = int16
  [@@deriving show]

type int24 = int32 [@printer fun fmt n -> Format.fprintf fmt "%ld" n]
  [@@deriving show]

type int128 = (int64 * int64) [@printer fun fmt (m, n) -> Format.fprintf fmt "%Lx%Lx" m n]
  [@@deriving show]

type switchId = int64 [@printer fun fmt n -> Format.fprintf fmt "%Lx" n]
  [@@deriving show]

type groupId = int32 [@printer fun fmt n -> Format.fprintf fmt "%ld" n]
  [@@deriving show]

type portId = int32 [@printer fun fmt n -> Format.fprintf fmt "%ld" n]
  [@@deriving show]

type tableId = int8 [@printer fun fmt n -> Format.fprintf fmt "%d" n]
  [@@deriving show]

type bufferId = int32 [@printer fun fmt n -> Format.fprintf fmt "%ld" n]
  [@@deriving show]

type switchFlags =
  | NormalFrag
  | DropFrag
  | ReasmFrag
  | MaskFrag
  [@@deriving show]

type switchConfig = {
  flags : switchFlags;
  miss_send_len : int16
} [@@deriving show]


type helloFailed =
  | HelloIncompatible
  | HelloPermError
  [@@deriving show]

type badRequest =
  | ReqBadVersion
  | ReqBadType
  | ReqBadMultipart
  | ReqBadExp
  | ReqBadExpType
  | ReqPermError
  | ReqBadLen
  | ReqBufferEmpty
  | ReqBufferUnknown
  | ReqBadTableId
  | ReqIsSlave
  | ReqBadPort
  | ReqBadPacket
  | ReqMultipartBufOverflow
  [@@deriving show]

type badAction =
  | ActBadType
  | ActBadLen
  | ActBadExp
  | ActBadExpType
  | ActBadOutPort
  | ActBadArg
  | ActPermError
  | ActTooMany
  | ActBadQueue
  | ActBadOutGroup
  | ActMatchInconsistent
  | ActUnsupportedOrder
  | ActBadTag
  | ActBadSetTyp
  | ActBadSetLen
  | ActBadSetArg
  [@@deriving show]

type badInstruction =
  | InstUnknownInst
  | InstBadTableId
  | InstUnsupInst
  | InstUnsupMeta
  | InstUnsupMetaMask
  | InstBadExp
  | InstBadExpTyp
  | InstBadLen
  | InstPermError
  [@@deriving show]

type badMatch =
  | MatBadTyp
  | MatBadLen
  | MatBadTag
  | MatBadDlAddrMask
  | MatBadNwAddrMask
  | MatBadWildcards
  | MatBadField
  | MatBadValue
  | MatBadMask
  | MatBadPrereq
  | MatDupField
  | MatPermError
  [@@deriving show]

type flowModFailed =
  | FlUnknown
  | FlTableFull
  | FlBadTableId
  | FlOverlap
  | FlPermError
  | FlBadTimeout
  | FlBadCommand
  | FlBadFlags
  [@@deriving show]

type groupModFailed =
  | GrGroupExists
  | GrInvalidGroup
  | GrWeightUnsupported
  | GrOutOfGroups
  | GrOutOfBuckets
  | GrChainingUnsupported
  | GrWatcHUnsupported
  | GrLoop
  | GrUnknownGroup
  | GrChainedGroup
  | GrBadTyp
  | GrBadCommand
  | GrBadBucket
  | GrBadWatch
  | GrPermError
  [@@deriving show]

type portModFailed =
  | PoBadPort
  | PoBadHwAddr
  | PoBadConfig
  | PoBadAdvertise
  | PoPermError
  [@@deriving show]

type tableModFailed =
  | TaBadTable
  | TaBadConfig
  | TaPermError
  [@@deriving show]

type queueOpFailed =
  | QuBadPort
  | QuBadQUeue
  | QuPermError
  [@@deriving show]

type switchConfigFailed =
  | ScBadFlags
  | ScBadLen
  | ScPermError
  [@@deriving show]

type roleReqFailed =
  | RoStale
  | RoUnsup
  | RoBadRole
  [@@deriving show]

type meterModFailed =
  | MeUnknown
  | MeMeterExists
  | MeInvalidMeter
  | MeUnknownMeter
  | MeBadCommand
  | MeBadFlags
  | MeBadRate
  | MeBadBurst
  | MeBadBand
  | MeBadBandValue
  | MeOutOfMeters
  | MeOutOfBands
  [@@deriving show]

type tableFeatFailed =
  | TfBadTable
  | TfBadMeta
  | TfBadType
  | TfBadLen
  | TfBadArg
  | TfPermError
  [@@deriving show]

type experimenterFailed = {
  exp_typ : int16;
  exp_id : int32
} [@@deriving show]

type errorTyp =
  | HelloFailed of helloFailed
  | BadRequest of badRequest
  | BadAction of badAction
  | BadInstruction of badInstruction
  | BadMatch of badMatch
  | FlowModFailed of flowModFailed
  | GroupModFailed of groupModFailed
  | PortModFailed of portModFailed
  | TableModFailed of tableModFailed
  | QueueOpFailed of queueOpFailed
  | SwitchConfigFailed of switchConfigFailed
  | RoleReqFailed of roleReqFailed
  | MeterModFailed of meterModFailed
  | TableFeatFailed of tableFeatFailed
  | ExperimenterFailed of experimenterFailed
  [@@deriving show]

type length = int16 [@@deriving show]

type oxmIPv6ExtHdr = {
  noext : bool;
  esp : bool;
  auth : bool;
  dest : bool;
  frac : bool;
  router : bool;
  hop : bool;
  unrep : bool;
  unseq : bool
} [@@deriving show]

type oxm =
  | OxmInPort of portId
  | OxmInPhyPort of portId
  | OxmMetadata of int64 mask
  | OxmEthType of int16
  | OxmEthDst of int48 mask
  | OxmEthSrc of int48 mask
  | OxmVlanVId of int12 mask
  | OxmVlanPcp of int8
  | OxmIPProto of int8
  | OxmIPDscp of int8
  | OxmIPEcn of int8
  | OxmIP4Src of int32 mask
  | OxmIP4Dst of int32 mask
  | OxmTCPSrc of int16
  | OxmTCPDst of int16
  | OxmARPOp of int16
  | OxmARPSpa of int32 mask
  | OxmARPTpa of int32 mask
  | OxmARPSha of int48 mask
  | OxmARPTha of int48 mask
  | OxmICMPType of int8
  | OxmICMPCode of int8
  | OxmMPLSLabel of int32
  | OxmMPLSTc of int8
  | OxmTunnelId of int64 mask
  | OxmUDPSrc of int16
  | OxmUDPDst of int16
  | OxmSCTPSrc of int16
  | OxmSCTPDst of int16
  | OxmIPv6Src of int128 mask
  | OxmIPv6Dst of int128 mask
  | OxmIPv6FLabel of int32 mask
  | OxmICMPv6Type of int8
  | OxmICMPv6Code of int8
  | OxmIPv6NDTarget of int128 mask
  | OxmIPv6NDSll of int48
  | OxmIPv6NDTll of int48
  | OxmMPLSBos of bool
  | OxmPBBIsid of int24 mask
  | OxmIPv6ExtHdr of oxmIPv6ExtHdr mask
  [@@deriving show]

type oxmMatch = oxm list [@@deriving show]

type pseudoPort =
  | PhysicalPort of portId
  | InPort
  | Table
  | Normal
  | Flood
  | AllPorts
  | Controller of int16
  | Local
  | Any
  [@@deriving show]

type actionHdr =
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
  | SetQueueHdr
  | ExperimenterAHdr of int32
  [@@deriving show]

type action =
  | Output of pseudoPort
  | Group of groupId
  | PopVlan
  | PushVlan
  | PopMpls
  | PushMpls
  | SetField of oxm
  | CopyTtlOut
  | CopyTtlIn
  | SetNwTtl of int8
  | DecNwTtl
  | PushPbb
  | PopPbb
  | SetMplsTtl of int8
  | DecMplsTtl
  | SetQueue of int32
  | Experimenter of int32
  [@@deriving show]

type actionSequence = action list
  [@@deriving show]

type instructionHdr =
  | GotoTableHdr
  | ApplyActionsHdr
  | WriteActionsHdr
  | WriteMetadataHdr
  | ClearHdr
  | MeterHdr
  | ExperimenterHdr of int32
  [@@deriving show]

type instruction =
  | GotoTable of tableId
  | ApplyActions of actionSequence
  | WriteActions of actionSequence
  | WriteMetadata of int64 mask
  | Clear
  | Meter of int32
  | Experimenter of int32
  [@@deriving show]

type bucket = {
  bu_weight : int16;
  bu_watch_port : portId option;
  bu_watch_group : groupId option;
  bu_actions : actionSequence
} [@@deriving show]

type groupType =
  | All
  | Select
  | Indirect
  | FF
  [@@deriving show]

type groupMod =
  | AddGroup of groupType * groupId * bucket list
  | DeleteGroup of groupType * groupId
  | ModifyGroup of groupType * groupId * bucket list
  [@@deriving show]

type timeout =
  | Permanent
  | ExpiresAfter of int16
  [@@deriving show]

type flowModCommand =
  | AddFlow
  | ModFlow
  | ModStrictFlow
  | DeleteFlow
  | DeleteStrictFlow
  [@@deriving show]

type packetInReason =
  | NoMatch
  | ExplicitSend
  | InvalidTTL
  [@@deriving show]

type packetIn = {
  pi_total_len : int16;
  pi_reason : packetInReason;
  pi_table_id : tableId;
  pi_cookie : int64;
  pi_ofp_match : oxmMatch;
  pi_payload : payload
} [@@deriving show]


type flowReason =
  | FlowIdleTimeout
  | FlowHardTiemout
  | FlowDelete
  | FlowGroupDelete
  [@@deriving show]

type flowRemoved = {
  cookie : int64;
  priority : int16;
  reason : flowReason;
  table_id : tableId;
  duration_sec : int32;
  duration_nsec : int32;
  idle_timeout : timeout;
  hard_timeout : timeout;
  packet_count : int64;
  byte_count : int64;
  oxm : oxmMatch
} [@@deriving show]

type capabilities = {
  flow_stats : bool;
  table_stats : bool;
  port_stats : bool;
  group_stats : bool;
  ip_reasm : bool;
  queue_stats : bool;
  port_blocked : bool
} [@@deriving show]

type portState = {
  link_down : bool;
  blocked : bool;
  live : bool
} [@@deriving show]

type portConfig = {
  port_down : bool;
  no_recv : bool;
  no_fwd : bool;
  no_packet_in : bool
} [@@deriving show]

type portFeatures = {
  rate_10mb_hd : bool;
  rate_10mb_fd : bool;
  rate_100mb_hd : bool;
  rate_100mb_fd : bool;
  rate_1gb_hd : bool;
  rate_1gb_fd : bool;
  rate_10gb_fd : bool;
  rate_40gb_fd : bool;
  rate_100gb_fd : bool;
  rate_1tb_fd : bool;
  other : bool;
  copper : bool;
  fiber : bool;
  autoneg : bool;
  pause : bool;
  pause_asym : bool
} [@@deriving show]

type portDesc = {
  port_no : portId;
  hw_addr : int48;
  name : string;
  config : portConfig;
  state : portState;
  curr : portFeatures;
  advertised : portFeatures;
  supported : portFeatures;
  peer : portFeatures;
  curr_speed : int32;
  max_speed : int32
} [@@deriving show]

type portMod = {
  mpPortNo : portId;
  mpHw_addr : int48;
  mpConfig : portConfig;
  mpMask : portConfig;
  mpAdvertise : portState
} [@@deriving show]

type portReason =
  | PortAdd
  | PortDelete
  | PortModify
  [@@deriving show]

type portStatus = {
  reason : portReason;
  desc : portDesc
} [@@deriving show]

type packetOut = {
  po_payload : payload;
  po_port_id : portId option;
  po_actions : actionSequence
} [@@deriving show]

type rate = int32 [@@deriving show]

type burst = int32 [@@deriving show]

type experimenterId = int32 [@@deriving show]

type meterBand =
  | Drop of (rate*burst)
  | DscpRemark of (rate*burst*int8)
  | ExpMeter of (rate*burst*experimenterId)
  [@@deriving show]

type meterCommand =
  | AddMeter
  | ModifyMeter
  | DeleteMeter
  [@@deriving show]

type meterFlags = {
  kbps : bool;
  pktps : bool;
  burst : bool;
  stats : bool
} [@@deriving show]

type meterMod = { command : meterCommand; flags : meterFlags; meter_id : int32;
                  bands : meterBand list} [@@deriving show]

type flowRequest = {fr_table_id : tableId; fr_out_port : portId;
                    fr_out_group : portId; fr_cookie : int64 mask;
                    fr_match : oxmMatch} [@@deriving show]

type queueRequest = {port_number : portId; queue_id : int32} [@@deriving show]

type experimenter = {exp_id : int32; exp_type : int32} [@@deriving show]

type tableFeatureProp =
  | TfpInstruction of instructionHdr list
  | TfpInstructionMiss of instructionHdr list
  | TfpNextTable of tableId list
  | TfpNextTableMiss of tableId list
  | TfpWriteAction of actionHdr list
  | TfpWriteActionMiss of actionHdr list
  | TfpApplyAction of actionHdr list
  | TfpApplyActionMiss of actionHdr list
  | TfpMatch of oxm list
  | TfpWildcard of oxm list
  | TfpWriteSetField of oxm list
  | TfpWriteSetFieldMiss of oxm list
  | TfpApplySetField of oxm list
  | TfpApplySetFieldMiss of oxm list
  | TfpExperimenter of (experimenter * cstruct)
  | TfpExperimenterMiss of (experimenter * cstruct)
  [@@deriving show]

type tableConfig = Deprecated [@@deriving show]

type tableFeatures = {length : int16;table_id : tableId; name : string;
                      metadata_match : int64; metadata_write : int64;
                      config : tableConfig; max_entries: int32;
                      feature_prop : tableFeatureProp list} [@@deriving show]

type multipartType =
  | SwitchDescReq
  | PortsDescReq
  | FlowStatsReq of flowRequest
  | AggregFlowStatsReq of flowRequest
  | TableStatsReq
  | PortStatsReq of portId
  | QueueStatsReq of queueRequest
  | GroupStatsReq of int32
  | GroupDescReq
  | GroupFeatReq
  | MeterStatsReq of int32
  | MeterConfReq of int32
  | MeterFeatReq
  | TableFeatReq of (tableFeatures list) option
  | ExperimentReq of experimenter
  [@@deriving show]

type multipartRequest = {
  mpr_type : multipartType;
  mpr_flags : bool
} [@@deriving show]

type switchDesc = { mfr_desc :string ; hw_desc : string; sw_desc : string;
                    serial_num : string } [@@deriving show]

type flowModFlags = { fmf_send_flow_rem : bool; fmf_check_overlap : bool;
                      fmf_reset_counts : bool; fmf_no_pkt_counts : bool;
                      fmf_no_byt_counts : bool } [@@deriving show]

type flowStats = { table_id : tableId; duration_sec : int32; duration_nsec :
                     int32; priority : int16; idle_timeout : timeout;
                   hard_timeout : timeout; flags : flowModFlags; cookie : int64;
                   packet_count : int64; byte_count : int64; ofp_match : oxmMatch;
                   instructions : instruction list} [@@deriving show]

type aggregStats = { packet_count : int64; byte_count : int64; flow_count : int32} [@@deriving show]

type tableStats = { table_id : tableId; active_count : int32; lookup_count : int64;
                    matched_count : int64} [@@deriving show]

type portStats = { psPort_no : portId; rx_packets : int64; tx_packets : int64;
                   rx_bytes : int64; tx_bytes : int64; rx_dropped : int64;
                   tx_dropped : int64; rx_errors : int64; tx_errors : int64;
                   rx_frame_err : int64; rx_over_err : int64; rx_crc_err : int64;
                   collisions : int64; duration_sec : int32; duration_nsec : int32} [@@deriving show]


type queueStats = { qsPort_no : portId; queue_id : int32; tx_bytes : int64; tx_packets : int64;
                    tx_errors : int64; duration_sec : int32; duration_nsec : int32 } [@@deriving show]

type bucketStats = { packet_count : int64; byte_count : int64} [@@deriving show]

type groupStats = { length : int16; group_id : int32; ref_count : int32;
                    packet_count : int64; byte_count : int64; duration_sec : int32;
                    duration_nsec : int32; bucket_stats : bucketStats list} [@@deriving show]

type groupDesc = { length : int16; typ : groupType; group_id : int32; bucket : bucket list} [@@deriving show]

type groupCapabilities = { select_weight : bool; select_liveness : bool;
                           chaining : bool; chaining_checks : bool } [@@deriving show]

type groupTypeMap = { all : bool; select : bool; indirect : bool; ff : bool} [@@deriving show]

type actionTypeMap = { output : bool; copy_ttl_out : bool; copy_ttl_in : bool;
                       set_mpls_ttl : bool; dec_mpls_ttl : bool; push_vlan : bool;
                       pop_vlan : bool; push_mpls : bool; pop_mpls : bool; set_queue : bool;
                       group : bool; set_nw_ttl : bool; dec_nw_ttl : bool; set_field : bool;
                       push_pbb : bool; pop_pbb : bool } [@@deriving show]

type groupFeatures = { typ : groupTypeMap; capabilities : groupCapabilities;
                       max_groups_all : int32; max_groups_select : int32;
                       max_groups_indirect : int32; max_groups_ff :
                         int32; actions_all : actionTypeMap; actions_select : actionTypeMap;
                       actions_indirect : actionTypeMap; actions_ff : actionTypeMap } [@@deriving show]

type meterBandStats = { packet_band_count : int64; byte_band_count : int64 } [@@deriving show]

type meterStats = { meter_id: int32; len : int16; flow_count : int32; packet_in_count :
                      int64; byte_in_count : int64; duration_sec : int32; duration_nsec :
                      int32; band : meterBandStats list} [@@deriving show]

type meterConfig = { length : length; flags : meterFlags; meter_id : int32; bands : meterBand list} [@@deriving show]

type meterBandMaps = { drop : bool; dscpRemark : bool} [@@deriving show]

type meterFeatures = { max_meter : int32; band_typ : meterBandMaps;
                       capabilities : meterFlags; max_band : int8;
                       max_color : int8 } [@@deriving show]

type multipartReplyTyp =
  | PortsDescReply of portDesc list
  | SwitchDescReply of switchDesc
  | FlowStatsReply of flowStats list
  | AggregateReply of aggregStats
  | TableReply of tableStats list
  | TableFeaturesReply of tableFeatures list
  | PortStatsReply of portStats list
  | QueueStatsReply of queueStats list
  | GroupStatsReply of groupStats list
  | GroupDescReply of groupDesc list
  | GroupFeaturesReply of groupFeatures
  | MeterReply of meterStats list
  | MeterConfig of meterConfig list
  | MeterFeaturesReply of meterFeatures
  [@@deriving show]

type multipartReply = {mpreply_typ : multipartReplyTyp; mpreply_flags : bool} [@@deriving show]

type tableMod = { table_id : tableId; config : tableConfig } [@@deriving show]

type rateQueue =
  | Rate of int
  | Disabled
  [@@deriving show]

type queueProp =
  | MinRateProp of rateQueue
  | MaxRateProp of rateQueue
  | ExperimenterProp of int32
  [@@deriving show]

type queueDesc = { queue_id : int32; port : portId; len : int16; properties : queueProp list } [@@deriving show]

type queueConfReq = { port : portId } [@@deriving show]

type queueConfReply = { port : portId; queues : queueDesc list } [@@deriving show]

type controllerRole =
  | NoChangeRole
  | EqualRole
  | MasterRole
  | SlaveRole
  [@@deriving show]

type roleRequest = { role : controllerRole; generation_id : int64 } [@@deriving show]

type supportedList = int list [@@deriving show]

type element =
  | VersionBitMap of supportedList
  [@@deriving show]

type helloElement = element list [@@deriving show]

type packetInReasonMap =  { table_miss : bool; apply_action : bool; invalid_ttl : bool } [@@deriving show]

type portReasonMap =  { add : bool; delete : bool; modify : bool } [@@deriving show]

type flowReasonMask = { idle_timeout : bool; hard_timeout : bool; delete : bool;
                        group_delete : bool} [@@deriving show]

type asyncConfig = { packet_in : packetInReasonMap asyncMask;
                     port_status : portReasonMap asyncMask;
                     flow_removed : flowReasonMask asyncMask } [@@deriving show]

type error = {
  err : errorTyp;
  data : cstruct ;
} [@@deriving show]

type flowMod = { mfCookie : int64 mask; mfTable_id : tableId;
                 mfCommand : flowModCommand; mfIdle_timeout : timeout;
                 mfHard_timeout : timeout; mfPriority : int16;
                 mfBuffer_id : bufferId option;
                 mfOut_port : pseudoPort option;
                 mfOut_group : groupId option; mfFlags : flowModFlags;
                 mfOfp_match : oxmMatch; mfInstructions : instruction list } [@@deriving show]

type switchFeatures = {
  datapath_id : int64;
  num_buffers : int32;
  num_tables : int8;
  aux_id : int8;
  supported_capabilities : capabilities
} [@@deriving show]

type message =
  | Hello of element list
  | EchoRequest of cstruct
  | EchoReply of cstruct
  | FeaturesRequest
  | FeaturesReply of switchFeatures
  | FlowModMsg of flowMod
  | GroupModMsg of groupMod
  | PortModMsg of portMod
  | MeterModMsg of meterMod
  | PacketInMsg of packetIn
  | FlowRemoved of flowRemoved
  | PacketOutMsg of packetOut
  | PortStatusMsg of portStatus
  | MultipartReq of multipartRequest
  | MultipartReply of multipartReply
  | BarrierRequest
  | BarrierReply
  | RoleRequest of roleRequest
  | RoleReply of roleRequest
  | QueueGetConfigReq of queueConfReq
  | QueueGetConfigReply of queueConfReply
  | GetConfigRequestMsg
  | GetConfigReplyMsg of switchConfig
  | SetConfigMsg of switchConfig
  | TableModMsg of tableMod
  | GetAsyncRequest
  | GetAsyncReply of asyncConfig
  | SetAsync of asyncConfig
  | Error of error
  [@@deriving show]

let portDescReq =
  { mpr_type = PortsDescReq
  ; mpr_flags = false }

let match_all = []

let default_fm_flags =
  { fmf_send_flow_rem = false
  ; fmf_check_overlap = false
  ; fmf_reset_counts = false
  ; fmf_no_pkt_counts = false
  ; fmf_no_byt_counts = false }

let add_flow ~tbl ~prio ~pat ~insts =
  { mfCookie = { m_value = 0L; m_mask = None }
  ; mfTable_id = tbl
  ; mfCommand = AddFlow
  ; mfIdle_timeout = Permanent
  ; mfHard_timeout = Permanent
  ; mfPriority = prio
  ; mfBuffer_id = None
  ; mfOut_port = None
  ; mfOut_group = None
  ; mfFlags = default_fm_flags
  ; mfOfp_match = pat
  ; mfInstructions = insts }

let delete_all_flows =
  { mfCookie = { m_value = 0L; m_mask = None }
  ; mfTable_id = 0xff (* OFPTT_ALL *)
  ; mfCommand = DeleteFlow
  ; mfIdle_timeout = Permanent
  ; mfHard_timeout = Permanent
  ; mfPriority = 0
  ; mfBuffer_id = None
  ; mfOut_port = None
  ; mfOut_group = Some 0xffffffffl (* OFPG_ANY *)
  ; mfFlags = default_fm_flags
  ; mfOfp_match = match_all
  ; mfInstructions = [] }

let delete_all_groups =
  DeleteGroup (All, 0xfffffffcl)

let parse_payload = function
  | Buffered (_, b)
  | NotBuffered b ->
    Frenetic_Packet.parse b

let marshal_payload buffer pkt =
  let payload = Frenetic_Packet.marshal pkt in
  match buffer with
  | Some b -> Buffered (b, payload)
  | None -> NotBuffered payload
