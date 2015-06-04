(* This implements a staged webserver interface to the virtual compiler. It is *)
(* based on the Compile_Server. It allows POSTing partial inputs of the *)
(* compile job separately, and then running the compile job, instead of *)
(* hardcoding them in. *)

open Core.Std
open Async.Std
open Cohttp_async
open NetKAT_Types
module Server = Cohttp_async.Server
open Common
open Baked_VNOS

type vno = { id                : int;
             policy            : policy ;
             relation          : pred ;
             topology          : policy ;
             ingress_policy    : policy ;
             ingress_predicate : pred ;
             egress_predicate  : pred ;
           }

let default_vno = { id                = 0  ;
                    policy            = Filter True ;
                    relation          = True ;
                    topology          = Filter True ;
                    ingress_policy    = Filter True ;
                    ingress_predicate = True ;
                    egress_predicate  = True ;
                  }

let topology          = ref (Filter True)
let ingress_predicate = ref True
let egress_predicate  = ref True
let compiled          = ref None

let vnos = Hashtbl.create ~hashable:Int.hashable ()

let parse_pol s = NetKAT_Parser.program NetKAT_Lexer.token (Lexing.from_string s)
let parse_pol_json s = NetKAT_Json.policy_from_json_string s
let parse_pred s = NetKAT_Parser.pred_program NetKAT_Lexer.token (Lexing.from_string s)
let respond = Cohttp_async.Server.respond_with_string

type stage =
  | VAdd              of int
  | VRemove           of int
  | VPolicy           of int
  | VRelation         of int
  | VTopology         of int
  | VIngressPolicy    of int
  | VIngressPredicate of int
  | VEgressPredicate  of int
  | PTopology
  | PIngressPredicate
  | PEgressPredicate
  | Compile
  | FlowTable         of switchId
  | Unknown

let request_to_stage (req : Request.t) : stage =
  let parts = List.filter ~f:(fun str -> not (String.is_empty str))
    (String.split ~on:'/'
       (Uri.path req.uri)) in
  (print_endline "");
  (print_endline (List.hd_exn parts));
  match parts with
  | [ "add-vno"; i ]                      -> VAdd (int_of_string i)
  | [ "remove-vno"; i ]                   -> VRemove (int_of_string i)
  | [ "virtual-policy"; vno ]             -> VPolicy (int_of_string vno)
  | [ "virtual-relation"; vno ]           -> VRelation (int_of_string vno)
  | [ "virtual-topology" ; vno ]          -> VTopology (int_of_string vno)
  | [ "virtual-ingress-policy" ; vno ]    -> VIngressPolicy (int_of_string vno)
  | [ "virtual-ingress-predicate" ; vno ] -> VIngressPredicate (int_of_string vno)
  | [ "virtual-egress-predicate" ; vno ]  -> VEgressPredicate (int_of_string vno)
  | [ "physical-topology" ]               -> PTopology
  | [ "physical-ingress-predicate" ]      -> PIngressPredicate
  | [ "physical-egress-predicate" ]       -> PEgressPredicate
  | [ "compile" ]                         -> Compile
  | [ "get-flowtable" ; sw]               -> FlowTable (Int64.of_string sw)
  | _                                     -> Unknown


let attempt_vno_update i body parse update default =
  (Body.to_string body) >>= (fun s ->
    print_endline s;
    
      let value = parse s in
      print_endline "Done parsing";
      match Hashtbl.find vnos i with
            | Some vno -> Hashtbl.replace vnos i (update vno value) ; respond "Replace"
            | None -> Hashtbl.add_exn vnos i (default value) ; respond "OK")
    (* with *)
    (* | Invalid_argument s -> respond s *)
    (* | _ -> respond "Parse error") *)

let attempt_phys_update body parse loc =
  (Body.to_string body) >>= (fun s ->
    try
      let value = parse s in
      loc := value;
      respond "Replace"
    with
    | _ -> respond "Parse error")

let compile i vno =
  let ing = if i = 1 then Baked_VNOS.get_pol "vno1-vingpol"
  else Baked_VNOS.get_pol "vno2-vingpol" in
  print_endline "VNO Policy";
  print_endline (NetKAT_Pretty.string_of_policy vno.policy);
  print_endline "VNO Ingress Policy";
  print_endline (NetKAT_Pretty.string_of_policy ing);
  print_endline "VNO Topology";
  print_endline (NetKAT_Pretty.string_of_policy vno.topology);
  print_endline "VNO Relation";
  print_endline (NetKAT_Pretty.string_of_pred vno.relation);
  print_endline "VNO Ingress predicate";
  print_endline (NetKAT_Pretty.string_of_pred vno.ingress_predicate);
  print_endline "";
  (NetKAT_VirtualCompiler.compile vno.policy
     vno.relation vno.topology ing
     vno.ingress_predicate vno.egress_predicate
     !topology !ingress_predicate
     !egress_predicate)

let handle_request
    ~(body : Cohttp_async.Body.t)
    (client_addr : Socket.Address.Inet.t)
    (request : Request.t) : Server.response Deferred.t =
  match request.meth, request_to_stage request with
  | `GET, VAdd i -> begin
    match Hashtbl.add vnos i {default_vno with id = i} with
    | `Duplicate -> respond "Replace"
    | `Ok -> respond "OK" end
  | `GET, VRemove i ->
    Hashtbl.remove vnos i ;
    respond "OK"
  | `POST, VPolicy i ->
    attempt_vno_update i body parse_pol_json (fun v p -> {v with policy = p})
      (fun p -> {default_vno with policy = p})
  | `POST, VRelation i ->
    attempt_vno_update i body parse_pred (fun v r -> {v with relation = r})
      (fun r -> {default_vno with relation = r})
  | `POST, VTopology i ->
    attempt_vno_update i body parse_pol (fun v t -> {v with topology = t})
      (fun t -> {default_vno with topology = t})
  | `POST, VIngressPolicy i ->
    attempt_vno_update i body parse_pol_json (fun v p -> {v with ingress_policy = p})
      (fun p -> {default_vno with ingress_policy = p})
  | `POST, VIngressPredicate i ->
    attempt_vno_update i body parse_pred (fun v p -> {v with ingress_predicate = p})
      (fun p -> {default_vno with ingress_predicate = p})
  | `POST, VEgressPredicate i ->
    attempt_vno_update i body parse_pred (fun v p -> {v with egress_predicate = p})
      (fun p -> {default_vno with egress_predicate = p})
  | `POST, PTopology ->
    attempt_phys_update body parse_pol topology
  | `POST, PIngressPredicate ->
    attempt_phys_update body parse_pred ingress_predicate
  | `POST, PEgressPredicate ->
    attempt_phys_update body parse_pred egress_predicate
  | `GET, Compile ->
    print_endline ("Physical Topology");
    print_endline (NetKAT_Pretty.string_of_policy !topology);
    print_endline ("Physical Ingress Predicate");
    print_endline (NetKAT_Pretty.string_of_pred !ingress_predicate);
    print_endline ("Physical Egress Predicate");
    print_endline (NetKAT_Pretty.string_of_pred !egress_predicate);
    print_endline "";

    let vno_list = Hashtbl.fold vnos ~init:[]
      ~f:(fun ~key:id ~data:vno acc -> vno::acc) in
    let union = List.fold (List.tl_exn vno_list)
      ~init:(compile 1 (List.hd_exn vno_list))
      ~f:(fun acc vno -> Optimize.mk_union acc (compile 2 vno)) in
    print_endline "Union done";
    let global =
      NetKAT_GlobalFDDCompiler.of_policy ~dedup:true ~ing:!ingress_predicate
        ~remove_duplicates:true union in
    print_endline "Global compilation done";
    compiled := Some (NetKAT_GlobalFDDCompiler.to_local NetKAT_FDD.Field.Vlan
      (NetKAT_FDD.Value.of_int 0xffff) global );
    respond "OK"
  | `GET, FlowTable sw -> begin
    match !compiled with
    | None -> respond "None"
    | Some local ->
      local |>
          NetKAT_LocalCompiler.to_table' sw |>
              (fun ls ->
                print_endline "Printing table";
            (List.map ~f:(fun (f,s) ->
              let _ = List.iter ~f:print_endline s in f ) ls)) |>
         NetKAT_SDN_Json.flowTable_to_json |>
         Yojson.Basic.to_string ~std:true |>
         Cohttp_async.Server.respond_with_string end
  | _ -> respond "Unknown"


let listen ?(port=9000) () =
  NetKAT_FDD.Field.set_order
   [ Switch; Location; VSwitch; VPort; IP4Dst; Vlan; TCPSrcPort; TCPDstPort; IP4Src;
      EthType; EthDst; EthSrc; VlanPcp; IPProto ];
  ignore (Cohttp_async.Server.create (Tcp.on_port port) handle_request)

let main (args : string list) : unit = match args with
  | [ "--port"; p ] | [ "-p"; p ] ->
    listen ~port:(Int.of_string p) ()
  | [] -> listen ~port:9000 ()
  |  _ -> (print_endline "Invalid command-line arguments"; Shutdown.shutdown 1)

