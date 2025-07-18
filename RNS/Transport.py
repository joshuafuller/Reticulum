# Reticulum License
#
# Copyright (c) 2016-2025 Mark Qvist
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# - The Software shall not be used in any kind of system which includes amongst
#   its functions the ability to purposefully do harm to human beings.
#
# - The Software shall not be used, directly or indirectly, in the creation of
#   an artificial intelligence, machine learning or language model training
#   dataset, including but not limited to any use that contributes to the
#   training or development of such a model or algorithm.
#
# - The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import gc
import RNS
import time
import math
import struct
import inspect
import threading
from time import sleep
from .vendor import umsgpack as umsgpack
from RNS.Interfaces.BackboneInterface import BackboneInterface

class Transport:
    """
    Through static methods of this class you can interact with the
    Transport system of Reticulum.
    """
    # Constants
    BROADCAST                   = 0x00;
    TRANSPORT                   = 0x01;
    RELAY                       = 0x02;
    TUNNEL                      = 0x03;
    types                       = [BROADCAST, TRANSPORT, RELAY, TUNNEL]

    REACHABILITY_UNREACHABLE    = 0x00
    REACHABILITY_DIRECT         = 0x01
    REACHABILITY_TRANSPORT      = 0x02

    APP_NAME = "rnstransport"

    PATHFINDER_M                = 128       # Max hops
    """
    Maximum amount of hops that Reticulum will transport a packet.
    """
    
    PATHFINDER_R                = 1            # Retransmit retries
    PATHFINDER_G                = 5            # Retry grace period
    PATHFINDER_RW               = 0.5          # Random window for announce rebroadcast
    PATHFINDER_E                = 60*60*24*7   # Path expiration of one week
    AP_PATH_TIME                = 60*60*24     # Path expiration of one day for Access Point paths
    ROAMING_PATH_TIME           = 60*60*6      # Path expiration of 6 hours for Roaming paths

    # TODO: Calculate an optimal number for this in
    # various situations
    LOCAL_REBROADCASTS_MAX      = 2            # How many local rebroadcasts of an announce is allowed

    PATH_REQUEST_TIMEOUT        = 15           # Default timeout for client path requests in seconds
    PATH_REQUEST_GRACE          = 0.4          # Grace time before a path announcement is made, allows directly reachable peers to respond first
    PATH_REQUEST_RG             = 1.5          # Extra grace time for roaming-mode interfaces to allow more suitable peers to respond first
    PATH_REQUEST_MI             = 20           # Minimum interval in seconds for automated path requests

    STATE_UNKNOWN               = 0x00
    STATE_UNRESPONSIVE          = 0x01
    STATE_RESPONSIVE            = 0x02

    LINK_TIMEOUT                = RNS.Link.STALE_TIME * 1.25
    REVERSE_TIMEOUT             = 8*60         # Reverse table entries are removed after 8 minutes
    DESTINATION_TIMEOUT         = 60*60*24*7   # Destination table entries are removed if unused for one week
    MAX_RECEIPTS                = 1024         # Maximum number of receipts to keep track of
    MAX_RATE_TIMESTAMPS         = 16           # Maximum number of announce timestamps to keep per destination
    PERSIST_RANDOM_BLOBS        = 32           # Maximum number of random blobs per destination to persist to disk
    MAX_RANDOM_BLOBS            = 64           # Maximum number of random blobs per destination to keep in memory

    interfaces                  = []           # All active interfaces
    destinations                = []           # All active destinations
    pending_links               = []           # Links that are being established
    active_links                = []           # Links that are active
    packet_hashlist             = set()        # A list of packet hashes for duplicate detection
    packet_hashlist_prev        = set()
    receipts                    = []           # Receipts of all outgoing packets for proof processing

    # Notes on memory usage: 1 megabyte of memory can store approximately
    # 55.100 path table entries or approximately 22.300 link table entries.

    announce_table              = {}           # A table for storing announces currently waiting to be retransmitted
    path_table                  = {}           # A lookup table containing the next hop to a given destination
    reverse_table               = {}           # A lookup table for storing packet hashes used to return proofs and replies
    link_table                  = {}           # A lookup table containing hops for links
    held_announces              = {}           # A table containing temporarily held announce-table entries
    announce_handlers           = []           # A table storing externally registered announce handlers
    tunnels                     = {}           # A table storing tunnels to other transport instances
    announce_rate_table         = {}           # A table for keeping track of announce rates
    path_requests               = {}           # A table for storing path request timestamps
    path_states                 = {}           # A table for keeping track of path states
    
    discovery_path_requests     = {}           # A table for keeping track of path requests on behalf of other nodes
    discovery_pr_tags           = []           # A table for keeping track of tagged path requests
    max_pr_tags                 = 32000        # Maximum amount of unique path request tags to remember

    # Transport control destinations are used
    # for control purposes like path requests
    control_destinations        = []
    control_hashes              = []
    remote_management_allowed   = []

    # Interfaces for communicating with
    # local clients connected to a shared
    # Reticulum instance
    local_client_interfaces     = []

    local_client_rssi_cache     = []
    local_client_snr_cache      = []
    local_client_q_cache        = []
    LOCAL_CLIENT_CACHE_MAXSIZE  = 512

    pending_local_path_requests = {}

    start_time                  = None
    jobs_locked                 = False
    jobs_running                = False
    job_interval                = 0.250
    links_last_checked          = 0.0
    links_check_interval        = 1.0
    receipts_last_checked       = 0.0
    receipts_check_interval     = 1.0
    announces_last_checked      = 0.0
    announces_check_interval    = 1.0
    pending_prs_last_checked    = 0.0
    pending_prs_check_interval  = 30.0
    cache_last_cleaned          = 0.0
    cache_clean_interval        = 300.0
    hashlist_maxsize            = 1000000
    tables_last_culled          = 0.0
    tables_cull_interval        = 5.0
    interface_last_jobs         = 0.0
    interface_jobs_interval     = 5.0

    traffic_rxb                 = 0
    traffic_txb                 = 0
    speed_rx                    = 0
    speed_tx                    = 0
    traffic_captured            = None

    identity = None

    @staticmethod
    def start(reticulum_instance):
        Transport.jobs_running = True
        Transport.owner = reticulum_instance

        if Transport.identity == None:
            transport_identity_path = RNS.Reticulum.storagepath+"/transport_identity"
            if os.path.isfile(transport_identity_path):
                Transport.identity = RNS.Identity.from_file(transport_identity_path)                

            if Transport.identity == None:
                RNS.log("No valid Transport Identity in storage, creating...", RNS.LOG_VERBOSE)
                Transport.identity = RNS.Identity()
                Transport.identity.to_file(transport_identity_path)
            else:
                RNS.log("Loaded Transport Identity from storage", RNS.LOG_VERBOSE)

        packet_hashlist_path = RNS.Reticulum.storagepath+"/packet_hashlist"
        if not Transport.owner.is_connected_to_shared_instance:
            if os.path.isfile(packet_hashlist_path):
                try:
                    file = open(packet_hashlist_path, "rb")
                    hashlist_data = umsgpack.unpackb(file.read())
                    Transport.packet_hashlist = set(hashlist_data)
                    file.close()
                except Exception as e:
                    RNS.log("Could not load packet hashlist from storage, the contained exception was: "+str(e), RNS.LOG_ERROR)

        # Create transport-specific destinations
        Transport.path_request_destination = RNS.Destination(None, RNS.Destination.IN, RNS.Destination.PLAIN, Transport.APP_NAME, "path", "request")
        Transport.path_request_destination.set_packet_callback(Transport.path_request_handler)
        Transport.control_destinations.append(Transport.path_request_destination)
        Transport.control_hashes.append(Transport.path_request_destination.hash)

        Transport.tunnel_synthesize_destination = RNS.Destination(None, RNS.Destination.IN, RNS.Destination.PLAIN, Transport.APP_NAME, "tunnel", "synthesize")
        Transport.tunnel_synthesize_destination.set_packet_callback(Transport.tunnel_synthesize_handler)
        Transport.control_destinations.append(Transport.tunnel_synthesize_handler)
        Transport.control_hashes.append(Transport.tunnel_synthesize_destination.hash)

        if RNS.Reticulum.remote_management_enabled() and not Transport.owner.is_connected_to_shared_instance:
            Transport.remote_management_destination = RNS.Destination(Transport.identity, RNS.Destination.IN, RNS.Destination.SINGLE, Transport.APP_NAME, "remote", "management")
            Transport.remote_management_destination.register_request_handler("/status", response_generator = Transport.remote_status_handler, allow = RNS.Destination.ALLOW_LIST, allowed_list=Transport.remote_management_allowed)
            Transport.remote_management_destination.register_request_handler("/path", response_generator = Transport.remote_path_handler, allow = RNS.Destination.ALLOW_LIST, allowed_list=Transport.remote_management_allowed)
            Transport.control_destinations.append(Transport.remote_management_destination)
            Transport.control_hashes.append(Transport.remote_management_destination.hash)
            RNS.log("Enabled remote management on "+str(Transport.remote_management_destination), RNS.LOG_NOTICE)

        # Defer cleaning packet cache for 30 seconds
        Transport.cache_last_cleaned = time.time() + 60
        
        # Start job loops
        Transport.jobs_running = False
        threading.Thread(target=Transport.jobloop, daemon=True).start()
        threading.Thread(target=Transport.count_traffic_loop, daemon=True).start()

        # Load transport-related data
        if RNS.Reticulum.transport_enabled():
            path_table_path = RNS.Reticulum.storagepath+"/destination_table"
            tunnel_table_path = RNS.Reticulum.storagepath+"/tunnels"

            if os.path.isfile(path_table_path) and not Transport.owner.is_connected_to_shared_instance:
                serialised_destinations = []
                try:
                    file = open(path_table_path, "rb")
                    serialised_destinations = umsgpack.unpackb(file.read())
                    file.close()

                    for serialised_entry in serialised_destinations:
                        destination_hash = serialised_entry[0]

                        if len(destination_hash) == RNS.Reticulum.TRUNCATED_HASHLENGTH//8:
                            timestamp = serialised_entry[1]
                            received_from = serialised_entry[2]
                            hops = serialised_entry[3]
                            expires = serialised_entry[4]
                            random_blobs = serialised_entry[5]
                            receiving_interface = Transport.find_interface_from_hash(serialised_entry[6])
                            announce_packet = Transport.get_cached_packet(serialised_entry[7], packet_type="announce")

                            if announce_packet != None and receiving_interface != None:
                                announce_packet.unpack()
                                # We increase the hops, since reading a packet
                                # from cache is equivalent to receiving it again
                                # over an interface. It is cached with it's non-
                                # increased hop-count.
                                announce_packet.hops += 1
                                Transport.path_table[destination_hash] = [timestamp, received_from, hops, expires, random_blobs, receiving_interface, announce_packet.packet_hash]
                                RNS.log("Loaded path table entry for "+RNS.prettyhexrep(destination_hash)+" from storage", RNS.LOG_DEBUG)
                            else:
                                RNS.log("Could not reconstruct path table entry from storage for "+RNS.prettyhexrep(destination_hash), RNS.LOG_DEBUG)
                                if announce_packet == None:
                                    RNS.log("The announce packet could not be loaded from cache", RNS.LOG_DEBUG)
                                if receiving_interface == None:
                                    RNS.log("The interface is no longer available", RNS.LOG_DEBUG)

                    if len(Transport.path_table) == 1:
                        specifier = "entry"
                    else:
                        specifier = "entries"

                    RNS.log("Loaded "+str(len(Transport.path_table))+" path table "+specifier+" from storage", RNS.LOG_VERBOSE)
                    gc.collect()

                except Exception as e:
                    RNS.log("Could not load destination table from storage, the contained exception was: "+str(e), RNS.LOG_ERROR)
                    gc.collect()

            if os.path.isfile(tunnel_table_path) and not Transport.owner.is_connected_to_shared_instance:
                serialised_tunnels = []
                try:
                    file = open(tunnel_table_path, "rb")
                    serialised_tunnels = umsgpack.unpackb(file.read())
                    file.close()

                    for serialised_tunnel in serialised_tunnels:
                        tunnel_id = serialised_tunnel[IDX_TT_TUNNEL_ID]
                        interface_hash = serialised_tunnel[IDX_TT_IF]
                        serialised_paths = serialised_tunnel[IDX_TT_PATHS]
                        expires = serialised_tunnel[IDX_TT_EXPIRES]

                        tunnel_paths = {}
                        for serialised_entry in serialised_paths:
                            destination_hash = serialised_entry[0]
                            timestamp = serialised_entry[1]
                            received_from = serialised_entry[2]
                            hops = serialised_entry[3]
                            expires = serialised_entry[4]
                            random_blobs = list(set(serialised_entry[5]))
                            receiving_interface = Transport.find_interface_from_hash(serialised_entry[6])
                            announce_packet = Transport.get_cached_packet(serialised_entry[7], packet_type="announce")

                            if announce_packet != None:
                                announce_packet.unpack()
                                # We increase the hops, since reading a packet
                                # from cache is equivalent to receiving it again
                                # over an interface. It is cached with it's non-
                                # increased hop-count.
                                announce_packet.hops += 1

                                tunnel_path = [timestamp, received_from, hops, expires, random_blobs, receiving_interface, announce_packet.packet_hash]
                                tunnel_paths[destination_hash] = tunnel_path

                        if len(tunnel_paths) > 0:
                            tunnel = [tunnel_id, None, tunnel_paths, expires]
                            Transport.tunnels[tunnel_id] = tunnel

                    if len(Transport.path_table) == 1: specifier = "entry"
                    else: specifier = "entries"

                    RNS.log("Loaded "+str(len(Transport.tunnels))+" tunnel table "+specifier+" from storage", RNS.LOG_VERBOSE)
                    gc.collect()

                except Exception as e:
                    RNS.log("Could not load tunnel table from storage, the contained exception was: "+str(e), RNS.LOG_ERROR)
                    gc.collect()

            if RNS.Reticulum.probe_destination_enabled():
                Transport.probe_destination = RNS.Destination(Transport.identity, RNS.Destination.IN, RNS.Destination.SINGLE, Transport.APP_NAME, "probe")
                Transport.probe_destination.accepts_links(False)
                Transport.probe_destination.set_proof_strategy(RNS.Destination.PROVE_ALL)
                Transport.probe_destination.announce()
                RNS.log("Transport Instance will respond to probe requests on "+str(Transport.probe_destination), RNS.LOG_NOTICE)
            else:
                Transport.probe_destination = None

            RNS.log("Transport instance "+str(Transport.identity)+" started", RNS.LOG_VERBOSE)
            Transport.start_time = time.time()

        # Sort interfaces according to bitrate
        Transport.prioritize_interfaces()

        # Synthesize tunnels for any interfaces wanting it
        for interface in Transport.interfaces:
            interface.tunnel_id = None
            if hasattr(interface, "wants_tunnel") and interface.wants_tunnel:
                Transport.synthesize_tunnel(interface)

        gc.collect()

    @staticmethod
    def prioritize_interfaces():
        try:
            Transport.interfaces.sort(key=lambda interface: interface.bitrate, reverse=True)

        except Exception as e:
            RNS.log(f"Could not prioritize interfaces according to bitrate. The contained exception was: {e}", RNS.LOG_ERROR)

    @staticmethod
    def count_traffic_loop():
        while True:
            time.sleep(1)
            try:
                rxb = 0; txb = 0;
                rxs = 0; txs = 0;
                for interface in Transport.interfaces:
                    if not hasattr(interface, "parent_interface") or interface.parent_interface == None:
                        if hasattr(interface, "transport_traffic_counter"):
                            now = time.time(); irxb = interface.rxb; itxb = interface.txb
                            tc = interface.transport_traffic_counter
                            rx_diff = irxb - tc["rxb"]
                            tx_diff = itxb - tc["txb"]
                            ts_diff = now  - tc["ts"]
                            rxb    += rx_diff; crxs = (rx_diff*8)/ts_diff
                            txb    += tx_diff; ctxs = (tx_diff*8)/ts_diff
                            interface.current_rx_speed = crxs; rxs += crxs
                            interface.current_tx_speed = ctxs; txs += ctxs
                            tc["rxb"] = irxb;
                            tc["txb"] = itxb;
                            tc["ts"] = now;

                        else:
                            interface.transport_traffic_counter = {"ts": time.time(), "rxb": interface.rxb, "txb": interface.txb}

                Transport.traffic_rxb += rxb
                Transport.traffic_txb += txb
                Transport.speed_rx    = rxs
                Transport.speed_tx    = txs
            
            except Exception as e:
                RNS.log(f"An error occurred while counting interface traffic: {e}", RNS.LOG_ERROR)

    @staticmethod
    def jobloop():
        while (True):
            Transport.jobs()
            sleep(Transport.job_interval)

    @staticmethod
    def jobs():
        outgoing = []
        path_requests = {}
        blocked_if = None
        Transport.jobs_running = True

        try:
            if not Transport.jobs_locked:
                should_collect = False

                # Process active and pending link lists
                if time.time() > Transport.links_last_checked+Transport.links_check_interval:

                    for link in Transport.pending_links:
                        if link.status == RNS.Link.CLOSED:
                            # If we are not a Transport Instance, finding a pending link
                            # that was never activated will trigger an expiry of the path
                            # to the destination, and an attempt to rediscover the path.
                            if not RNS.Reticulum.transport_enabled():
                                Transport.expire_path(link.destination.hash)

                                # If we are connected to a shared instance, it will take
                                # care of sending out a new path request. If not, we will
                                # send one directly.
                                if not Transport.owner.is_connected_to_shared_instance:
                                    last_path_request = 0
                                    if link.destination.hash in Transport.path_requests:
                                        last_path_request = Transport.path_requests[link.destination.hash]

                                    if time.time() - last_path_request > Transport.PATH_REQUEST_MI:
                                        RNS.log("Trying to rediscover path for "+RNS.prettyhexrep(link.destination.hash)+" since an attempted link was never established", RNS.LOG_DEBUG)
                                        if not link.destination.hash in path_requests:
                                            blocked_if = None
                                            path_requests[link.destination.hash] = blocked_if

                            Transport.pending_links.remove(link)

                    for link in Transport.active_links:
                        if link.status == RNS.Link.CLOSED:
                            Transport.active_links.remove(link)

                    Transport.links_last_checked = time.time()

                # Process receipts list for timed-out packets
                if time.time() > Transport.receipts_last_checked+Transport.receipts_check_interval:
                    while len(Transport.receipts) > Transport.MAX_RECEIPTS:
                        culled_receipt = Transport.receipts.pop(0)
                        culled_receipt.timeout = -1
                        culled_receipt.check_timeout()
                        should_collect = True

                    for receipt in Transport.receipts:
                        receipt.check_timeout()
                        if receipt.status != RNS.PacketReceipt.SENT:
                            if receipt in Transport.receipts:
                                Transport.receipts.remove(receipt)

                    Transport.receipts_last_checked = time.time()

                # Process announces needing retransmission
                if time.time() > Transport.announces_last_checked+Transport.announces_check_interval:
                    completed_announces = []
                    for destination_hash in Transport.announce_table:
                        announce_entry = Transport.announce_table[destination_hash]
                        if announce_entry[IDX_AT_RETRIES] > Transport.PATHFINDER_R:
                            RNS.log("Completed announce processing for "+RNS.prettyhexrep(destination_hash)+", retry limit reached", RNS.LOG_EXTREME)
                            completed_announces.append(destination_hash)
                        else:
                            if time.time() > announce_entry[IDX_AT_RTRNS_TMO]:
                                announce_entry[IDX_AT_RTRNS_TMO] = time.time() + Transport.PATHFINDER_G + Transport.PATHFINDER_RW
                                announce_entry[IDX_AT_RETRIES] += 1
                                packet = announce_entry[IDX_AT_PACKET]
                                block_rebroadcasts = announce_entry[IDX_AT_BLCK_RBRD]
                                attached_interface = announce_entry[IDX_AT_ATTCHD_IF]
                                announce_context = RNS.Packet.NONE
                                if block_rebroadcasts: announce_context = RNS.Packet.PATH_RESPONSE
                                announce_data = packet.data
                                announce_identity = RNS.Identity.recall(packet.destination_hash)
                                announce_destination = RNS.Destination(announce_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, "unknown", "unknown");
                                announce_destination.hash = packet.destination_hash
                                announce_destination.hexhash = announce_destination.hash.hex()
                                
                                new_packet = RNS.Packet(
                                    announce_destination,
                                    announce_data,
                                    RNS.Packet.ANNOUNCE,
                                    context = announce_context,
                                    header_type = RNS.Packet.HEADER_2,
                                    transport_type = Transport.TRANSPORT,
                                    transport_id = Transport.identity.hash,
                                    attached_interface = attached_interface,
                                    context_flag = packet.context_flag,
                                )

                                new_packet.hops = announce_entry[4]
                                if block_rebroadcasts:
                                    RNS.log("Rebroadcasting announce as path response for "+RNS.prettyhexrep(announce_destination.hash)+" with hop count "+str(new_packet.hops), RNS.LOG_DEBUG)
                                else:
                                    RNS.log("Rebroadcasting announce for "+RNS.prettyhexrep(announce_destination.hash)+" with hop count "+str(new_packet.hops), RNS.LOG_DEBUG)
                                
                                outgoing.append(new_packet)

                                # This handles an edge case where a peer sends a past
                                # request for a destination just after an announce for
                                # said destination has arrived, but before it has been
                                # rebroadcast locally. In such a case the actual announce
                                # is temporarily held, and then reinserted when the path
                                # request has been served to the peer.
                                if destination_hash in Transport.held_announces:
                                    held_entry = Transport.held_announces.pop(destination_hash)
                                    Transport.announce_table[destination_hash] = held_entry
                                    RNS.log("Reinserting held announce into table", RNS.LOG_DEBUG)

                    for destination_hash in completed_announces:
                        if destination_hash in Transport.announce_table:
                            Transport.announce_table.pop(destination_hash)

                    Transport.announces_last_checked = time.time()


                # Cull the packet hashlist if it has reached its max size
                if len(Transport.packet_hashlist) > Transport.hashlist_maxsize//2:
                    Transport.packet_hashlist_prev = Transport.packet_hashlist
                    Transport.packet_hashlist = set()

                # Cull invalidated path requests
                if time.time() > Transport.pending_prs_last_checked+Transport.pending_prs_check_interval:
                    for destination_hash in Transport.pending_local_path_requests.copy():
                        if not Transport.pending_local_path_requests[destination_hash] in Transport.interfaces:
                            Transport.pending_local_path_requests.pop(destination_hash)

                    Transport.pending_prs_last_checked = time.time()

                # Cull the path request tags list if it has reached its max size
                if len(Transport.discovery_pr_tags) > Transport.max_pr_tags:
                    Transport.discovery_pr_tags = Transport.discovery_pr_tags[len(Transport.discovery_pr_tags)-Transport.max_pr_tags:len(Transport.discovery_pr_tags)-1]

                if time.time() > Transport.tables_last_culled + Transport.tables_cull_interval:
                    # Remove unneeded path state entries
                    stale_path_states = []
                    for destination_hash in Transport.path_states:
                        if not destination_hash in Transport.path_table:
                            stale_path_states.append(destination_hash)

                    # Cull the reverse table according to timeout
                    stale_reverse_entries = []
                    for truncated_packet_hash in Transport.reverse_table:
                        reverse_entry = Transport.reverse_table[truncated_packet_hash]
                        if time.time() > reverse_entry[IDX_RT_TIMESTAMP] + Transport.REVERSE_TIMEOUT:
                            stale_reverse_entries.append(truncated_packet_hash)
                        elif not reverse_entry[IDX_RT_OUTB_IF] in Transport.interfaces:
                            stale_reverse_entries.append(truncated_packet_hash)
                        elif not reverse_entry[IDX_RT_RCVD_IF] in Transport.interfaces:
                            stale_reverse_entries.append(truncated_packet_hash)

                    # Cull the link table according to timeout
                    stale_links = []
                    for link_id in Transport.link_table:
                        link_entry = Transport.link_table[link_id]

                        if link_entry[IDX_LT_VALIDATED] == True:
                            if time.time() > link_entry[IDX_LT_TIMESTAMP] + Transport.LINK_TIMEOUT:
                                stale_links.append(link_id)
                            elif not link_entry[IDX_LT_NH_IF] in Transport.interfaces:
                                stale_links.append(link_id)
                            elif not link_entry[IDX_LT_RCVD_IF] in Transport.interfaces:
                                stale_links.append(link_id)
                        else:
                            if time.time() > link_entry[IDX_LT_PROOF_TMO]:
                                stale_links.append(link_id)

                                last_path_request = 0
                                if link_entry[IDX_LT_DSTHASH] in Transport.path_requests:
                                    last_path_request = Transport.path_requests[link_entry[IDX_LT_DSTHASH]]

                                lr_taken_hops = link_entry[IDX_LT_HOPS]

                                path_request_throttle = time.time() - last_path_request < Transport.PATH_REQUEST_MI
                                path_request_conditions = False
                                
                                # If the path has been invalidated between the time of
                                # making the link request and now, try to rediscover it
                                if not Transport.has_path(link_entry[IDX_LT_DSTHASH]):
                                    RNS.log("Trying to rediscover path for "+RNS.prettyhexrep(link_entry[IDX_LT_DSTHASH])+" since an attempted link was never established, and path is now missing", RNS.LOG_DEBUG)
                                    path_request_conditions =True

                                # If this link request was originated from a local client
                                # attempt to rediscover a path to the destination, if this
                                # has not already happened recently.
                                elif not path_request_throttle and lr_taken_hops == 0:
                                    RNS.log("Trying to rediscover path for "+RNS.prettyhexrep(link_entry[IDX_LT_DSTHASH])+" since an attempted local client link was never established", RNS.LOG_DEBUG)
                                    path_request_conditions = True

                                # If the link destination was previously only 1 hop
                                # away, this likely means that it was local to one
                                # of our interfaces, and that it roamed somewhere else.
                                # In that case, try to discover a new path, and mark
                                # the old one as unresponsive.
                                elif not path_request_throttle and Transport.hops_to(link_entry[IDX_LT_DSTHASH]) == 1:
                                    RNS.log("Trying to rediscover path for "+RNS.prettyhexrep(link_entry[IDX_LT_DSTHASH])+" since an attempted link was never established, and destination was previously local to an interface on this instance", RNS.LOG_DEBUG)
                                    path_request_conditions = True
                                    blocked_if = link_entry[IDX_LT_RCVD_IF]

                                    # TODO: This might result in the path re-resolution
                                    # only being able to happen once, since new path found
                                    # after allowing update from higher hop-count path, after
                                    # marking old path unresponsive, might be more than 1 hop away,
                                    # thus dealocking us into waiting for a new announce all-together.
                                    # Is this problematic, or does it actually not matter?
                                    # Best would be to have full support for alternative paths,
                                    # and score them according to number of unsuccessful tries or
                                    # similar.
                                    if RNS.Reticulum.transport_enabled():
                                        if hasattr(link_entry[IDX_LT_RCVD_IF], "mode") and link_entry[IDX_LT_RCVD_IF].mode != RNS.Interfaces.Interface.Interface.MODE_BOUNDARY:
                                            Transport.mark_path_unresponsive(link_entry[IDX_LT_DSTHASH])

                                # If the link initiator is only 1 hop away,
                                # this likely means that network topology has
                                # changed. In that case, we try to discover a new path,
                                # and mark the old one as potentially unresponsive.
                                elif not path_request_throttle and lr_taken_hops == 1:
                                    RNS.log("Trying to rediscover path for "+RNS.prettyhexrep(link_entry[IDX_LT_DSTHASH])+" since an attempted link was never established, and link initiator is local to an interface on this instance", RNS.LOG_DEBUG)
                                    path_request_conditions = True
                                    blocked_if = link_entry[IDX_LT_RCVD_IF]

                                    if RNS.Reticulum.transport_enabled():
                                        if hasattr(link_entry[IDX_LT_RCVD_IF], "mode") and link_entry[IDX_LT_RCVD_IF].mode != RNS.Interfaces.Interface.Interface.MODE_BOUNDARY:
                                            Transport.mark_path_unresponsive(link_entry[IDX_LT_DSTHASH])

                                if path_request_conditions:
                                    if not link_entry[IDX_LT_DSTHASH] in path_requests:
                                        path_requests[link_entry[IDX_LT_DSTHASH]] = blocked_if

                                    if not RNS.Reticulum.transport_enabled():
                                        # Drop current path if we are not a transport instance, to
                                        # allow using higher-hop count paths or reused announces
                                        # from newly adjacent transport instances.
                                        Transport.expire_path(link_entry[IDX_LT_DSTHASH])

                    # Cull the path table
                    stale_paths = []
                    for destination_hash in Transport.path_table:
                        destination_entry = Transport.path_table[destination_hash]
                        attached_interface = destination_entry[IDX_PT_RVCD_IF]

                        if attached_interface != None and hasattr(attached_interface, "mode") and attached_interface.mode == RNS.Interfaces.Interface.Interface.MODE_ACCESS_POINT:
                            destination_expiry = destination_entry[IDX_PT_TIMESTAMP] + Transport.AP_PATH_TIME
                        elif attached_interface != None and hasattr(attached_interface, "mode") and attached_interface.mode == RNS.Interfaces.Interface.Interface.MODE_ROAMING:
                            destination_expiry = destination_entry[IDX_PT_TIMESTAMP] + Transport.ROAMING_PATH_TIME
                        else:
                            destination_expiry = destination_entry[IDX_PT_TIMESTAMP] + Transport.DESTINATION_TIMEOUT

                        if time.time() > destination_expiry:
                            stale_paths.append(destination_hash)
                            should_collect = True
                            RNS.log("Path to "+RNS.prettyhexrep(destination_hash)+" timed out and was removed", RNS.LOG_DEBUG)
                        elif not attached_interface in Transport.interfaces:
                            stale_paths.append(destination_hash)
                            should_collect = True
                            RNS.log("Path to "+RNS.prettyhexrep(destination_hash)+" was removed since the attached interface no longer exists", RNS.LOG_DEBUG)

                    # Cull the pending discovery path requests table
                    stale_discovery_path_requests = []
                    for destination_hash in Transport.discovery_path_requests:
                        entry = Transport.discovery_path_requests[destination_hash]

                        if time.time() > entry["timeout"]:
                            stale_discovery_path_requests.append(destination_hash)
                            should_collect = True
                            RNS.log("Waiting path request for "+RNS.prettyhexrep(destination_hash)+" timed out and was removed", RNS.LOG_DEBUG)

                    # Cull the tunnel table
                    stale_tunnels = []; ti = 0
                    for tunnel_id in Transport.tunnels:
                        tunnel_entry = Transport.tunnels[tunnel_id]

                        expires = tunnel_entry[IDX_TT_EXPIRES]
                        if time.time() > expires:
                            stale_tunnels.append(tunnel_id)
                            should_collect = True
                            RNS.log("Tunnel "+RNS.prettyhexrep(tunnel_id)+" timed out and was removed", RNS.LOG_EXTREME)
                        else:
                            if tunnel_entry[IDX_TT_IF] and not tunnel_entry[IDX_TT_IF] in Transport.interfaces:
                                RNS.log(f"Removing non-existent tunnel interface {tunnel_entry[IDX_TT_IF]}", RNS.LOG_EXTREME)
                                tunnel_entry[IDX_TT_IF] = None

                            stale_tunnel_paths = []
                            tunnel_paths = tunnel_entry[IDX_TT_PATHS]
                            for tunnel_path in tunnel_paths:
                                tunnel_path_entry = tunnel_paths[tunnel_path]

                                if time.time() > tunnel_path_entry[0] + Transport.DESTINATION_TIMEOUT:
                                    stale_tunnel_paths.append(tunnel_path)
                                    should_collect = True
                                    RNS.log("Tunnel path to "+RNS.prettyhexrep(tunnel_path)+" timed out and was removed", RNS.LOG_EXTREME)

                            for tunnel_path in stale_tunnel_paths:
                                tunnel_paths.pop(tunnel_path)
                                ti += 1


                    if ti > 0:
                        if ti == 1: RNS.log("Removed "+str(ti)+" tunnel path", RNS.LOG_EXTREME)
                        else: RNS.log("Removed "+str(ti)+" tunnel paths", RNS.LOG_EXTREME)

                    i = 0
                    for truncated_packet_hash in stale_reverse_entries:
                        Transport.reverse_table.pop(truncated_packet_hash)
                        i += 1

                    if i > 0:
                        if i == 1: RNS.log("Released "+str(i)+" reverse table entry", RNS.LOG_EXTREME)
                        else: RNS.log("Released "+str(i)+" reverse table entries", RNS.LOG_EXTREME)

                    i = 0
                    for link_id in stale_links:
                        Transport.link_table.pop(link_id)
                        i += 1

                    if i > 0:
                        if i == 1: RNS.log("Released "+str(i)+" link", RNS.LOG_EXTREME)
                        else: RNS.log("Released "+str(i)+" links", RNS.LOG_EXTREME)

                    i = 0
                    for destination_hash in stale_paths:
                        Transport.path_table.pop(destination_hash)
                        i += 1

                    if i > 0:
                        if i == 1: RNS.log("Removed "+str(i)+" path", RNS.LOG_EXTREME)
                        else: RNS.log("Removed "+str(i)+" paths", RNS.LOG_EXTREME)

                    i = 0
                    for destination_hash in stale_discovery_path_requests:
                        Transport.discovery_path_requests.pop(destination_hash)
                        i += 1

                    if i > 0:
                        if i == 1: RNS.log("Removed "+str(i)+" waiting path request", RNS.LOG_EXTREME)
                        else: RNS.log("Removed "+str(i)+" waiting path requests", RNS.LOG_EXTREME)

                    i = 0
                    for tunnel_id in stale_tunnels:
                        Transport.tunnels.pop(tunnel_id)
                        i += 1

                    if i > 0:
                        if i == 1: RNS.log("Removed "+str(i)+" tunnel", RNS.LOG_EXTREME)
                        else: RNS.log("Removed "+str(i)+" tunnels", RNS.LOG_EXTREME)

                    i = 0
                    for destination_hash in stale_path_states:
                        Transport.path_states.pop(destination_hash)
                        i += 1

                    if i > 0:
                        if i == 1: RNS.log("Removed "+str(i)+" path state entry", RNS.LOG_EXTREME)
                        else: RNS.log("Removed "+str(i)+" path state entries", RNS.LOG_EXTREME)

                    Transport.tables_last_culled = time.time()

                # Run interface-related jobs
                if time.time() > Transport.interface_last_jobs + Transport.interface_jobs_interval:
                    Transport.prioritize_interfaces()
                    for interface in Transport.interfaces:
                        interface.process_held_announces()
                    Transport.interface_last_jobs = time.time()

                # Clean packet caches
                if time.time() > Transport.cache_last_cleaned+Transport.cache_clean_interval:
                    Transport.clean_cache()

                if should_collect: gc.collect()

            else:
                # Transport jobs were locked, do nothing
                pass

        except Exception as e:
            RNS.log("An exception occurred while running Transport jobs.", RNS.LOG_ERROR)
            RNS.log("The contained exception was: "+str(e), RNS.LOG_ERROR)

        Transport.jobs_running = False

        for packet in outgoing:
            packet.send()

        for destination_hash in path_requests:
            blocked_if = path_requests[destination_hash]
            if blocked_if == None:
                Transport.request_path(destination_hash)
            else:
                for interface in Transport.interfaces:
                    if interface != blocked_if:
                        # RNS.log("Transmitting path request on "+str(interface), RNS.LOG_DEBUG)
                        Transport.request_path(destination_hash, on_interface=interface)
                    else:
                        pass
                        # RNS.log("Blocking path request on "+str(interface), RNS.LOG_DEBUG)

    @staticmethod
    def transmit(interface, raw):
        try:
            if hasattr(interface, "ifac_identity") and interface.ifac_identity != None:
                # Calculate packet access code
                ifac = interface.ifac_identity.sign(raw)[-interface.ifac_size:]

                # Generate mask
                mask = RNS.Cryptography.hkdf(
                    length=len(raw)+interface.ifac_size,
                    derive_from=ifac,
                    salt=interface.ifac_key,
                    context=None,
                )

                # Set IFAC flag
                new_header = bytes([raw[0] | 0x80, raw[1]])

                # Assemble new payload with IFAC
                new_raw    = new_header+ifac+raw[2:]
                
                # Mask payload
                i = 0; masked_raw = b""
                for byte in new_raw:
                    if i == 0:
                        # Mask first header byte, but make sure the
                        # IFAC flag is still set
                        masked_raw += bytes([byte ^ mask[i] | 0x80])
                    elif i == 1 or i > interface.ifac_size+1:
                        # Mask second header byte and payload
                        masked_raw += bytes([byte ^ mask[i]])
                    else:
                        # Don't mask the IFAC itself
                        masked_raw += bytes([byte])
                    i += 1

                # Send it
                interface.process_outgoing(masked_raw)

            else:
                interface.process_outgoing(raw)

        except Exception as e:
            RNS.log("Error while transmitting on "+str(interface)+". The contained exception was: "+str(e), RNS.LOG_ERROR)

    @staticmethod
    def outbound(packet):
        while (Transport.jobs_running):
            sleep(0.0005)

        Transport.jobs_locked = True

        sent = False
        outbound_time = time.time()

        generate_receipt = False
        if (packet.create_receipt == True and
            # Only generate receipts for DATA packets
            packet.packet_type == RNS.Packet.DATA and
            # Don't generate receipts for PLAIN destinations
            packet.destination.type != RNS.Destination.PLAIN and
            # Don't generate receipts for link-related packets
            not (packet.context >= RNS.Packet.KEEPALIVE and packet.context <= RNS.Packet.LRPROOF) and
            # Don't generate receipts for resource packets
            not (packet.context >= RNS.Packet.RESOURCE and packet.context <= RNS.Packet.RESOURCE_RCL)):

            generate_receipt = True

        def packet_sent(packet):
            packet.sent = True
            packet.sent_at = time.time()

            if generate_receipt:
                packet.receipt = RNS.PacketReceipt(packet)
                Transport.receipts.append(packet.receipt)
            
            # TODO: Enable when caching has been redesigned
            # Transport.cache(packet)

        # Check if we have a known path for the destination in the path table
        if packet.packet_type != RNS.Packet.ANNOUNCE and packet.destination.type != RNS.Destination.PLAIN and packet.destination.type != RNS.Destination.GROUP and packet.destination_hash in Transport.path_table:
            outbound_interface = Transport.path_table[packet.destination_hash][IDX_PT_RVCD_IF]

            # If there's more than one hop to the destination, and we know
            # a path, we insert the packet into transport by adding the next
            # transport nodes address to the header, and modifying the flags.
            # This rule applies both for "normal" transport, and when connected
            # to a local shared Reticulum instance.
            if Transport.path_table[packet.destination_hash][IDX_PT_HOPS] > 1:
                if packet.header_type == RNS.Packet.HEADER_1:
                    # Insert packet into transport
                    new_flags = (RNS.Packet.HEADER_2) << 6 | (Transport.TRANSPORT) << 4 | (packet.flags & 0b00001111)
                    new_raw = struct.pack("!B", new_flags)
                    new_raw += packet.raw[1:2]
                    new_raw += Transport.path_table[packet.destination_hash][IDX_PT_NEXT_HOP]
                    new_raw += packet.raw[2:]
                    packet_sent(packet)
                    Transport.transmit(outbound_interface, new_raw)
                    Transport.path_table[packet.destination_hash][IDX_PT_TIMESTAMP] = time.time()
                    sent = True

            # In the special case where we are connected to a local shared
            # Reticulum instance, and the destination is one hop away, we
            # also add transport headers to inject the packet into transport
            # via the shared instance. Normally a packet for a destination
            # one hop away would just be broadcast directly, but since we
            # are "behind" a shared instance, we need to get that instance
            # to transport it onto the network.
            elif Transport.path_table[packet.destination_hash][IDX_PT_HOPS] == 1 and Transport.owner.is_connected_to_shared_instance:
                if packet.header_type == RNS.Packet.HEADER_1:
                    # Insert packet into transport
                    new_flags = (RNS.Packet.HEADER_2) << 6 | (Transport.TRANSPORT) << 4 | (packet.flags & 0b00001111)
                    new_raw = struct.pack("!B", new_flags)
                    new_raw += packet.raw[1:2]
                    new_raw += Transport.path_table[packet.destination_hash][IDX_PT_NEXT_HOP]
                    new_raw += packet.raw[2:]
                    packet_sent(packet)
                    Transport.transmit(outbound_interface, new_raw)
                    Transport.path_table[packet.destination_hash][IDX_PT_TIMESTAMP] = time.time()
                    sent = True

            # If none of the above applies, we know the destination is
            # directly reachable, and also on which interface, so we
            # simply transmit the packet directly on that one.
            else:
                packet_sent(packet)
                Transport.transmit(outbound_interface, packet.raw)
                sent = True

        # If we don't have a known path for the destination, we'll
        # broadcast the packet on all outgoing interfaces, or the
        # just the relevant interface if the packet has an attached
        # interface, or belongs to a link.
        else:
            stored_hash = False
            for interface in Transport.interfaces:
                if interface.OUT:
                    should_transmit = True

                    if packet.destination.type == RNS.Destination.LINK:
                        if packet.destination.status == RNS.Link.CLOSED:
                            should_transmit = False
                        if interface != packet.destination.attached_interface:
                            should_transmit = False
                    
                    if packet.attached_interface != None and interface != packet.attached_interface:
                        should_transmit = False

                    if packet.packet_type == RNS.Packet.ANNOUNCE:
                        if packet.attached_interface == None:
                            if interface.mode == RNS.Interfaces.Interface.Interface.MODE_ACCESS_POINT:
                                RNS.log("Blocking announce broadcast on "+str(interface)+" due to AP mode", RNS.LOG_EXTREME)
                                should_transmit = False

                            elif interface.mode == RNS.Interfaces.Interface.Interface.MODE_ROAMING:
                                local_destination = next((d for d in Transport.destinations if d.hash == packet.destination_hash), None)
                                if local_destination != None:
                                    # RNS.log("Allowing announce broadcast on roaming-mode interface from instance-local destination", RNS.LOG_EXTREME)
                                    pass
                                else:
                                    from_interface = Transport.next_hop_interface(packet.destination_hash)
                                    if from_interface == None or not hasattr(from_interface, "mode"):
                                        should_transmit = False
                                        if from_interface == None:
                                            RNS.log("Blocking announce broadcast on "+str(interface)+" since next hop interface doesn't exist", RNS.LOG_EXTREME)
                                        elif not hasattr(from_interface, "mode"):
                                            RNS.log("Blocking announce broadcast on "+str(interface)+" since next hop interface has no mode configured", RNS.LOG_EXTREME)
                                    else:
                                        if from_interface.mode == RNS.Interfaces.Interface.Interface.MODE_ROAMING:
                                            RNS.log("Blocking announce broadcast on "+str(interface)+" due to roaming-mode next-hop interface", RNS.LOG_EXTREME)
                                            should_transmit = False
                                        elif from_interface.mode == RNS.Interfaces.Interface.Interface.MODE_BOUNDARY:
                                            RNS.log("Blocking announce broadcast on "+str(interface)+" due to boundary-mode next-hop interface", RNS.LOG_EXTREME)
                                            should_transmit = False

                            elif interface.mode == RNS.Interfaces.Interface.Interface.MODE_BOUNDARY:
                                local_destination = next((d for d in Transport.destinations if d.hash == packet.destination_hash), None)
                                if local_destination != None:
                                    # RNS.log("Allowing announce broadcast on boundary-mode interface from instance-local destination", RNS.LOG_EXTREME)
                                    pass
                                else:
                                    from_interface = Transport.next_hop_interface(packet.destination_hash)
                                    if from_interface == None or not hasattr(from_interface, "mode"):
                                        should_transmit = False
                                        if from_interface == None:
                                            RNS.log("Blocking announce broadcast on "+str(interface)+" since next hop interface doesn't exist", RNS.LOG_EXTREME)
                                        elif not hasattr(from_interface, "mode"):
                                            RNS.log("Blocking announce broadcast on "+str(interface)+" since next hop interface has no mode configured", RNS.LOG_EXTREME)
                                    else:
                                        if from_interface.mode == RNS.Interfaces.Interface.Interface.MODE_ROAMING:
                                            RNS.log("Blocking announce broadcast on "+str(interface)+" due to roaming-mode next-hop interface", RNS.LOG_EXTREME)
                                            should_transmit = False

                            else:
                                # Currently, annouces originating locally are always
                                # allowed, and do not conform to bandwidth caps.
                                # TODO: Rethink whether this is actually optimal.
                                if packet.hops > 0:

                                    if not hasattr(interface, "announce_cap"):
                                        interface.announce_cap = RNS.Reticulum.ANNOUNCE_CAP

                                    if not hasattr(interface, "announce_allowed_at"):
                                        interface.announce_allowed_at = 0

                                    if not hasattr(interface, "announce_queue"):
                                            interface.announce_queue = []

                                    queued_announces = True if len(interface.announce_queue) > 0 else False
                                    if not queued_announces and outbound_time > interface.announce_allowed_at and interface.bitrate != None and interface.bitrate != 0:
                                        tx_time   = (len(packet.raw)*8) / interface.bitrate
                                        wait_time = (tx_time / interface.announce_cap)
                                        interface.announce_allowed_at = outbound_time + wait_time
                                    
                                    else:
                                        should_transmit = False
                                        if not len(interface.announce_queue) >= RNS.Reticulum.MAX_QUEUED_ANNOUNCES:
                                            should_queue = True

                                            already_queued = False
                                            for e in interface.announce_queue:
                                                if e["destination"] == packet.destination_hash:
                                                    already_queued = True
                                                    existing_entry = e

                                            emission_timestamp = Transport.announce_emitted(packet)
                                            if already_queued:
                                                should_queue = False

                                                if emission_timestamp > existing_entry["emitted"]:
                                                    e["time"] = outbound_time
                                                    e["hops"] = packet.hops
                                                    e["emitted"] = emission_timestamp
                                                    e["raw"] = packet.raw

                                            if should_queue:
                                                entry = {
                                                    "destination": packet.destination_hash,
                                                    "time": outbound_time,
                                                    "hops": packet.hops,
                                                    "emitted": Transport.announce_emitted(packet),
                                                    "raw": packet.raw
                                                }

                                                queued_announces = True if len(interface.announce_queue) > 0 else False
                                                interface.announce_queue.append(entry)

                                                if not queued_announces:
                                                    wait_time = max(interface.announce_allowed_at - time.time(), 0)
                                                    timer = threading.Timer(wait_time, interface.process_announce_queue)
                                                    timer.start()

                                                    if wait_time < 1:
                                                        wait_time_str = str(round(wait_time*1000,2))+"ms"
                                                    else:
                                                        wait_time_str = str(round(wait_time*1,2))+"s"

                                                    ql_str = str(len(interface.announce_queue))
                                                    RNS.log("Added announce to queue (height "+ql_str+") on "+str(interface)+" for processing in "+wait_time_str, RNS.LOG_EXTREME)

                                                else:
                                                    wait_time = max(interface.announce_allowed_at - time.time(), 0)

                                                    if wait_time < 1:
                                                        wait_time_str = str(round(wait_time*1000,2))+"ms"
                                                    else:
                                                        wait_time_str = str(round(wait_time*1,2))+"s"

                                                    ql_str = str(len(interface.announce_queue))
                                                    RNS.log("Added announce to queue (height "+ql_str+") on "+str(interface)+" for processing in "+wait_time_str, RNS.LOG_EXTREME)

                                        else:
                                            pass
                                
                                else:
                                    pass

                    if should_transmit:
                        if not stored_hash:
                            Transport.add_packet_hash(packet.packet_hash)
                            stored_hash = True

                        Transport.transmit(interface, packet.raw)
                        if packet.packet_type == RNS.Packet.ANNOUNCE:
                            interface.sent_announce()
                        packet_sent(packet)
                        sent = True

        Transport.jobs_locked = False
        return sent

    @staticmethod
    def add_packet_hash(packet_hash):
        if not Transport.owner.is_connected_to_shared_instance:
            Transport.packet_hashlist.add(packet_hash)

    @staticmethod
    def packet_filter(packet):
        # If connected to a shared instance, it will handle
        # packet filtering
        if Transport.owner.is_connected_to_shared_instance: return True

        # Filter packets intended for other transport instances
        if packet.transport_id != None and packet.packet_type != RNS.Packet.ANNOUNCE:
            if packet.transport_id != Transport.identity.hash:
                RNS.log("Ignored packet "+RNS.prettyhexrep(packet.packet_hash)+" in transport for other transport instance", RNS.LOG_EXTREME)
                return False

        if packet.context == RNS.Packet.KEEPALIVE:
            return True
        if packet.context == RNS.Packet.RESOURCE_REQ:
            return True
        if packet.context == RNS.Packet.RESOURCE_PRF:
            return True
        if packet.context == RNS.Packet.RESOURCE:
            return True
        if packet.context == RNS.Packet.CACHE_REQUEST:
            return True
        if packet.context == RNS.Packet.CHANNEL:
            return True

        if packet.destination_type == RNS.Destination.PLAIN:
            if packet.packet_type != RNS.Packet.ANNOUNCE:
                if packet.hops > 1:
                    RNS.log("Dropped PLAIN packet "+RNS.prettyhexrep(packet.packet_hash)+" with "+str(packet.hops)+" hops", RNS.LOG_DEBUG)
                    return False
                else:
                    return True
            else:
                RNS.log("Dropped invalid PLAIN announce packet", RNS.LOG_DEBUG)
                return False

        if packet.destination_type == RNS.Destination.GROUP:
            if packet.packet_type != RNS.Packet.ANNOUNCE:
                if packet.hops > 1:
                    RNS.log("Dropped GROUP packet "+RNS.prettyhexrep(packet.packet_hash)+" with "+str(packet.hops)+" hops", RNS.LOG_DEBUG)
                    return False
                else:
                    return True
            else:
                RNS.log("Dropped invalid GROUP announce packet", RNS.LOG_DEBUG)
                return False

        if not packet.packet_hash in Transport.packet_hashlist and not packet.packet_hash in Transport.packet_hashlist_prev:
            return True
        else:
            if packet.packet_type == RNS.Packet.ANNOUNCE:
                if packet.destination_type == RNS.Destination.SINGLE:
                    return True
                else:
                    RNS.log("Dropped invalid announce packet", RNS.LOG_DEBUG)
                    return False

        RNS.log("Filtered packet with hash "+RNS.prettyhexrep(packet.packet_hash), RNS.LOG_EXTREME)
        return False

    @staticmethod
    def inbound(raw, interface=None):
        # If interface access codes are enabled,
        # we must authenticate each packet.
        if len(raw) > 2:
            if interface != None and hasattr(interface, "ifac_identity") and interface.ifac_identity != None:
                # Check that IFAC flag is set
                if raw[0] & 0x80 == 0x80:
                    if len(raw) > 2+interface.ifac_size:
                        # Extract IFAC
                        ifac = raw[2:2+interface.ifac_size]

                        # Generate mask
                        mask = RNS.Cryptography.hkdf(
                            length=len(raw),
                            derive_from=ifac,
                            salt=interface.ifac_key,
                            context=None,
                        )

                        # Unmask payload
                        i = 0; unmasked_raw = b""
                        for byte in raw:
                            if i <= 1 or i > interface.ifac_size+1:
                                # Unmask header bytes and payload
                                unmasked_raw += bytes([byte ^ mask[i]])
                            else:
                                # Don't unmask IFAC itself
                                unmasked_raw += bytes([byte])
                            i += 1
                        raw = unmasked_raw

                        # Unset IFAC flag
                        new_header = bytes([raw[0] & 0x7f, raw[1]])

                        # Re-assemble packet
                        new_raw = new_header+raw[2+interface.ifac_size:]

                        # Calculate expected IFAC
                        expected_ifac = interface.ifac_identity.sign(new_raw)[-interface.ifac_size:]

                        # Check it
                        if ifac == expected_ifac:
                            raw = new_raw
                        else:
                            return

                    else:
                        return

                else:
                    # If the IFAC flag is not set, but should be,
                    # drop the packet.
                    return

            else:
                # If the interface does not have IFAC enabled,
                # check the received packet IFAC flag.
                if raw[0] & 0x80 == 0x80:
                    # If the flag is set, drop the packet
                    return

        else:
            return

        while (Transport.jobs_running):
            sleep(0.0005)

        if Transport.identity == None:
            return
            
        Transport.jobs_locked = True
        
        packet = RNS.Packet(None, raw)
        if not packet.unpack():
            Transport.jobs_locked = False
            return
            
        packet.receiving_interface = interface
        packet.hops += 1

        if interface != None:
            if hasattr(interface, "r_stat_rssi"):
                if interface.r_stat_rssi != None:
                    packet.rssi = interface.r_stat_rssi
                    Transport.local_client_rssi_cache.append([packet.packet_hash, packet.rssi])
                    while len(Transport.local_client_rssi_cache) > Transport.LOCAL_CLIENT_CACHE_MAXSIZE:
                        Transport.local_client_rssi_cache.pop(0)

            if hasattr(interface, "r_stat_snr"):
                if interface.r_stat_rssi != None:
                    packet.snr = interface.r_stat_snr
                    Transport.local_client_snr_cache.append([packet.packet_hash, packet.snr])
                    while len(Transport.local_client_snr_cache) > Transport.LOCAL_CLIENT_CACHE_MAXSIZE:
                        Transport.local_client_snr_cache.pop(0)

            if hasattr(interface, "r_stat_q"):
                if interface.r_stat_q != None:
                    packet.q = interface.r_stat_q
                    Transport.local_client_q_cache.append([packet.packet_hash, packet.q])
                    while len(Transport.local_client_q_cache) > Transport.LOCAL_CLIENT_CACHE_MAXSIZE:
                        Transport.local_client_q_cache.pop(0)

        if len(Transport.local_client_interfaces) > 0:
            if Transport.is_local_client_interface(interface):
                packet.hops -= 1

        elif Transport.interface_to_shared_instance(interface):
            packet.hops -= 1

        if Transport.packet_filter(packet):
            # By default, remember packet hashes to avoid routing
            # loops in the network, using the packet filter.
            remember_packet_hash = True

            # If this packet belongs to a link in our link table,
            # we'll have to defer adding it to the filter list.
            # In some cases, we might see a packet over a shared-
            # medium interface, belonging to a link that transports
            # or terminates with this instance, but before it would
            # normally reach us. If the packet is appended to the
            # filter list at this point, link transport will break.
            if packet.destination_hash in Transport.link_table:
                remember_packet_hash = False

            # If this is a link request proof, don't add it until
            # we are sure it's not actually somewhere else in the
            # routing chain.
            if packet.packet_type == RNS.Packet.PROOF and packet.context == RNS.Packet.LRPROOF:
                remember_packet_hash = False

            if remember_packet_hash:
                Transport.add_packet_hash(packet.packet_hash)
                # TODO: Enable when caching has been redesigned
                # Transport.cache(packet)
            
            # Check special conditions for local clients connected
            # through a shared Reticulum instance
            from_local_client         = (packet.receiving_interface in Transport.local_client_interfaces)
            for_local_client          = (packet.packet_type != RNS.Packet.ANNOUNCE) and (packet.destination_hash in Transport.path_table and Transport.path_table[packet.destination_hash][IDX_PT_HOPS] == 0)
            for_local_client_link     = (packet.packet_type != RNS.Packet.ANNOUNCE) and (packet.destination_hash in Transport.link_table and Transport.link_table[packet.destination_hash][IDX_LT_RCVD_IF] in Transport.local_client_interfaces)
            for_local_client_link    |= (packet.packet_type != RNS.Packet.ANNOUNCE) and (packet.destination_hash in Transport.link_table and Transport.link_table[packet.destination_hash][IDX_LT_NH_IF] in Transport.local_client_interfaces)
            proof_for_local_client    = (packet.destination_hash in Transport.reverse_table) and (Transport.reverse_table[packet.destination_hash][IDX_RT_RCVD_IF] in Transport.local_client_interfaces)

            # Plain broadcast packets from local clients are sent
            # directly on all attached interfaces, since they are
            # never injected into transport.
            if not packet.destination_hash in Transport.control_hashes:
                if packet.destination_type == RNS.Destination.PLAIN and packet.transport_type == Transport.BROADCAST:
                    # Send to all interfaces except the originator
                    if from_local_client:
                        for interface in Transport.interfaces:
                            if interface != packet.receiving_interface:
                                Transport.transmit(interface, packet.raw)
                    # If the packet was not from a local client, send
                    # it directly to all local clients
                    else:
                        for interface in Transport.local_client_interfaces:
                            Transport.transmit(interface, packet.raw)


            # General transport handling. Takes care of directing
            # packets according to transport tables and recording
            # entries in reverse and link tables.
            if RNS.Reticulum.transport_enabled() or from_local_client or for_local_client or for_local_client_link:

                # If there is no transport id, but the packet is
                # for a local client, we generate the transport
                # id (it was stripped on the previous hop, since
                # we "spoof" the hop count for clients behind a
                # shared instance, so they look directly reach-
                # able), and reinsert, so the normal transport
                # implementation can handle the packet.
                if packet.transport_id == None and for_local_client:
                    packet.transport_id = Transport.identity.hash

                # If this is a cache request, and we can fullfill
                # it, do so and stop processing. Otherwise resume
                # normal processing.
                if packet.context == RNS.Packet.CACHE_REQUEST:
                    if Transport.cache_request_packet(packet):
                        Transport.jobs_locked = False
                        return

                # If the packet is in transport, check whether we
                # are the designated next hop, and process it
                # accordingly if we are.
                if packet.transport_id != None and packet.packet_type != RNS.Packet.ANNOUNCE:
                    if packet.transport_id == Transport.identity.hash:
                        if packet.destination_hash in Transport.path_table:
                            next_hop = Transport.path_table[packet.destination_hash][IDX_PT_NEXT_HOP]
                            remaining_hops = Transport.path_table[packet.destination_hash][IDX_PT_HOPS]
                            
                            if remaining_hops > 1:
                                # Just increase hop count and transmit
                                new_raw  = packet.raw[0:1]
                                new_raw += struct.pack("!B", packet.hops)
                                new_raw += next_hop
                                new_raw += packet.raw[(RNS.Identity.TRUNCATED_HASHLENGTH//8)+2:]
                            elif remaining_hops == 1:
                                # Strip transport headers and transmit
                                new_flags = (RNS.Packet.HEADER_1) << 6 | (Transport.BROADCAST) << 4 | (packet.flags & 0b00001111)
                                new_raw = struct.pack("!B", new_flags)
                                new_raw += struct.pack("!B", packet.hops)
                                new_raw += packet.raw[(RNS.Identity.TRUNCATED_HASHLENGTH//8)+2:]
                            elif remaining_hops == 0:
                                # Just increase hop count and transmit
                                new_raw  = packet.raw[0:1]
                                new_raw += struct.pack("!B", packet.hops)
                                new_raw += packet.raw[2:]

                            outbound_interface = Transport.path_table[packet.destination_hash][IDX_PT_RVCD_IF]

                            if packet.packet_type == RNS.Packet.LINKREQUEST:
                                now = time.time()
                                proof_timeout  = Transport.extra_link_proof_timeout(packet.receiving_interface)
                                proof_timeout += now + RNS.Link.ESTABLISHMENT_TIMEOUT_PER_HOP * max(1, remaining_hops)
                                
                                path_mtu       = RNS.Link.mtu_from_lr_packet(packet)
                                mode           = RNS.Link.mode_from_lr_packet(packet)
                                nh_mtu         = outbound_interface.HW_MTU
                                if path_mtu:
                                    if outbound_interface.HW_MTU == None:
                                        RNS.log(f"No next-hop HW MTU, disabling link MTU upgrade", RNS.LOG_DEBUG) # TODO: Remove debug
                                        path_mtu = None
                                        new_raw  = new_raw[:-RNS.Link.LINK_MTU_SIZE]
                                    elif not outbound_interface.AUTOCONFIGURE_MTU and not outbound_interface.FIXED_MTU:
                                        RNS.log(f"Outbound interface doesn't support MTU autoconfiguration, disabling link MTU upgrade", RNS.LOG_DEBUG) # TODO: Remove debug
                                        path_mtu = None
                                        new_raw  = new_raw[:-RNS.Link.LINK_MTU_SIZE]
                                    else:
                                        if nh_mtu < path_mtu:
                                            try:
                                                path_mtu = nh_mtu
                                                clamped_mtu = RNS.Link.signalling_bytes(path_mtu, mode)
                                                RNS.log(f"Clamping link MTU to {RNS.prettysize(nh_mtu)}", RNS.LOG_DEBUG) # TODO: Remove debug
                                                new_raw  = new_raw[:-RNS.Link.LINK_MTU_SIZE]+clamped_mtu
                                            except Exception as e:
                                                RNS.log(f"Dropping link request packet. The contained exception was: {e}", RNS.LOG_WARNING)
                                                return

                                # Entry format is
                                link_entry = [  now,                            # 0: Timestamp,
                                                next_hop,                       # 1: Next-hop transport ID
                                                outbound_interface,             # 2: Next-hop interface
                                                remaining_hops,                 # 3: Remaining hops
                                                packet.receiving_interface,     # 4: Received on interface
                                                packet.hops,                    # 5: Taken hops
                                                packet.destination_hash,        # 6: Original destination hash
                                                False,                          # 7: Validated
                                                proof_timeout]                  # 8: Proof timeout timestamp

                                Transport.link_table[RNS.Link.link_id_from_lr_packet(packet)] = link_entry

                            else:
                                # Entry format is
                                reverse_entry = [   packet.receiving_interface, # 0: Received on interface
                                                    outbound_interface,         # 1: Outbound interface
                                                    time.time()]                # 2: Timestamp

                                Transport.reverse_table[packet.getTruncatedHash()] = reverse_entry

                            Transport.transmit(outbound_interface, new_raw)
                            Transport.path_table[packet.destination_hash][IDX_PT_TIMESTAMP] = time.time()

                        else:
                            # TODO: There should probably be some kind of REJECT
                            # mechanism here, to signal to the source that their
                            # expected path failed.
                            RNS.log("Got packet in transport, but no known path to final destination "+RNS.prettyhexrep(packet.destination_hash)+". Dropping packet.", RNS.LOG_EXTREME)

                # Link transport handling. Directs packets according
                # to entries in the link tables
                if packet.packet_type != RNS.Packet.ANNOUNCE and packet.packet_type != RNS.Packet.LINKREQUEST and packet.context != RNS.Packet.LRPROOF:
                    if packet.destination_hash in Transport.link_table:
                        link_entry = Transport.link_table[packet.destination_hash]
                        # If receiving and outbound interface is
                        # the same for this link, direction doesn't
                        # matter, and we simply repeat the packet.
                        outbound_interface = None
                        if link_entry[IDX_LT_NH_IF] == link_entry[IDX_LT_RCVD_IF]:
                            # But check that taken hops matches one
                            # of the expectede values.
                            if packet.hops == link_entry[IDX_LT_REM_HOPS] or packet.hops == link_entry[IDX_LT_HOPS]:
                                outbound_interface = link_entry[IDX_LT_NH_IF]
                        else:
                            # If interfaces differ, we transmit on
                            # the opposite interface of what the
                            # packet was received on.
                            if packet.receiving_interface == link_entry[IDX_LT_NH_IF]:
                                # Also check that expected hop count matches
                                if packet.hops == link_entry[IDX_LT_REM_HOPS]:
                                    outbound_interface = link_entry[IDX_LT_RCVD_IF]
                            elif packet.receiving_interface == link_entry[IDX_LT_RCVD_IF]:
                                # Also check that expected hop count matches
                                if packet.hops == link_entry[IDX_LT_HOPS]:
                                    outbound_interface = link_entry[IDX_LT_NH_IF]

                        if outbound_interface != None:
                            # Add this packet to the filter hashlist if we
                            # have determined that it's actually our turn
                            # to process it.
                            Transport.add_packet_hash(packet.packet_hash)

                            new_raw = packet.raw[0:1]
                            new_raw += struct.pack("!B", packet.hops)
                            new_raw += packet.raw[2:]
                            Transport.transmit(outbound_interface, new_raw)
                            Transport.link_table[packet.destination_hash][IDX_LT_TIMESTAMP] = time.time()
                        
                        # TODO: Test and possibly enable this at some point
                        # Transport.jobs_locked = False
                        # return


            # Announce handling. Handles logic related to incoming
            # announces, queueing rebroadcasts of these, and removal
            # of queued announce rebroadcasts once handed to the next node.
            if packet.packet_type == RNS.Packet.ANNOUNCE:
                if interface != None and RNS.Identity.validate_announce(packet, only_validate_signature=True):
                    interface.received_announce()

                if not packet.destination_hash in Transport.path_table:
                    # This is an unknown destination, and we'll apply
                    # potential ingress limiting. Already known
                    # destinations will have re-announces controlled
                    # by normal announce rate limiting.
                    if interface.should_ingress_limit():
                        interface.hold_announce(packet)
                        Transport.jobs_locked = False
                        return

                local_destination = next((d for d in Transport.destinations if d.hash == packet.destination_hash), None)
                if local_destination == None and RNS.Identity.validate_announce(packet):
                    if packet.transport_id != None:
                        received_from = packet.transport_id
                        
                        # Check if this is a next retransmission from
                        # another node. If it is, we're removing the
                        # announce in question from our pending table
                        if RNS.Reticulum.transport_enabled() and packet.destination_hash in Transport.announce_table:
                            announce_entry = Transport.announce_table[packet.destination_hash]
                            
                            if packet.hops-1 == announce_entry[IDX_AT_HOPS]:
                                RNS.log("Heard a local rebroadcast of announce for "+RNS.prettyhexrep(packet.destination_hash), RNS.LOG_DEBUG)
                                announce_entry[IDX_AT_LCL_RBRD] += 1
                                if announce_entry[IDX_AT_LCL_RBRD] >= Transport.LOCAL_REBROADCASTS_MAX:
                                    RNS.log("Max local rebroadcasts of announce for "+RNS.prettyhexrep(packet.destination_hash)+" reached, dropping announce from our table", RNS.LOG_DEBUG)
                                    if packet.destination_hash in Transport.announce_table:
                                        Transport.announce_table.pop(packet.destination_hash)

                            if packet.hops-1 == announce_entry[IDX_AT_HOPS]+1 and announce_entry[IDX_AT_RETRIES] > 0:
                                now = time.time()
                                if now < announce_entry[IDX_AT_RTRNS_TMO]:
                                    RNS.log("Rebroadcasted announce for "+RNS.prettyhexrep(packet.destination_hash)+" has been passed on to another node, no further tries needed", RNS.LOG_DEBUG)
                                    if packet.destination_hash in Transport.announce_table:
                                        Transport.announce_table.pop(packet.destination_hash)

                    else:
                        received_from = packet.destination_hash

                    # Check if this announce should be inserted into
                    # announce and destination tables
                    should_add = False

                    # First, check that the announce is not for a destination
                    # local to this system, and that hops are less than the max
                    if (not any(packet.destination_hash == d.hash for d in Transport.destinations) and packet.hops < Transport.PATHFINDER_M+1):
                        announce_emitted = Transport.announce_emitted(packet)
                        
                        random_blob = packet.data[RNS.Identity.KEYSIZE//8+RNS.Identity.NAME_HASH_LENGTH//8:RNS.Identity.KEYSIZE//8+RNS.Identity.NAME_HASH_LENGTH//8+10]
                        random_blobs = []
                        if packet.destination_hash in Transport.path_table:
                            random_blobs = Transport.path_table[packet.destination_hash][IDX_PT_RANDBLOBS]

                            # If we already have a path to the announced
                            # destination, but the hop count is equal or
                            # less, we'll update our tables.
                            if packet.hops <= Transport.path_table[packet.destination_hash][IDX_PT_HOPS]:
                                # Make sure we haven't heard the random
                                # blob before, so announces can't be
                                # replayed to forge paths.
                                # TODO: Check whether this approach works
                                # under all circumstances
                                path_timebase = Transport.timebase_from_random_blobs(random_blobs)
                                if not random_blob in random_blobs and announce_emitted > path_timebase:
                                    Transport.mark_path_unknown_state(packet.destination_hash)
                                    should_add = True
                                else:
                                    should_add = False
                            else:
                                # If an announce arrives with a larger hop
                                # count than we already have in the table,
                                # ignore it, unless the path is expired, or
                                # the emission timestamp is more recent.
                                now = time.time()
                                path_expires = Transport.path_table[packet.destination_hash][IDX_PT_EXPIRES]
                                
                                path_announce_emitted = 0
                                for path_random_blob in random_blobs:
                                    path_announce_emitted = max(path_announce_emitted, int.from_bytes(path_random_blob[5:10], "big"))
                                    if path_announce_emitted >= announce_emitted:
                                        break

                                # If the path has expired, consider this
                                # announce for adding to the path table.
                                if (now >= path_expires):
                                    # We check that the announce is
                                    # different from ones we've already heard,
                                    # to avoid loops in the network
                                    if not random_blob in random_blobs:
                                        # TODO: Check that this ^ approach actually
                                        # works under all circumstances
                                        RNS.log("Replacing destination table entry for "+str(RNS.prettyhexrep(packet.destination_hash))+" with new announce due to expired path", RNS.LOG_DEBUG)
                                        Transport.mark_path_unknown_state(packet.destination_hash)
                                        should_add = True
                                    else:
                                        should_add = False
                                else:
                                    # If the path is not expired, but the emission
                                    # is more recent, and we haven't already heard
                                    # this announce before, update the path table.
                                    if (announce_emitted > path_announce_emitted):
                                        if not random_blob in random_blobs:
                                            RNS.log("Replacing destination table entry for "+str(RNS.prettyhexrep(packet.destination_hash))+" with new announce, since it was more recently emitted", RNS.LOG_DEBUG)
                                            Transport.mark_path_unknown_state(packet.destination_hash)
                                            should_add = True
                                        else:
                                            should_add = False
                                    
                                    # If we have already heard this announce before,
                                    # but the path has been marked as unresponsive
                                    # by a failed communications attempt or similar,
                                    # allow updating the path table to this one.
                                    elif announce_emitted == path_announce_emitted:
                                        if Transport.path_is_unresponsive(packet.destination_hash):
                                            RNS.log("Replacing destination table entry for "+str(RNS.prettyhexrep(packet.destination_hash))+" with new announce, since previously tried path was unresponsive", RNS.LOG_DEBUG)
                                            should_add = True
                                        else:
                                            should_add = False

                        else:
                            # If this destination is unknown in our table
                            # we should add it
                            should_add = True

                        if should_add:
                            now = time.time()

                            rate_blocked = False
                            if packet.context != RNS.Packet.PATH_RESPONSE and packet.receiving_interface.announce_rate_target != None:
                                if not packet.destination_hash in Transport.announce_rate_table:
                                    rate_entry = { "last": now, "rate_violations": 0, "blocked_until": 0, "timestamps": [now]}
                                    Transport.announce_rate_table[packet.destination_hash] = rate_entry

                                else:
                                    rate_entry = Transport.announce_rate_table[packet.destination_hash]
                                    rate_entry["timestamps"].append(now)

                                    while len(rate_entry["timestamps"]) > Transport.MAX_RATE_TIMESTAMPS:
                                        rate_entry["timestamps"].pop(0)

                                    current_rate = now - rate_entry["last"]

                                    if now > rate_entry["blocked_until"]:
                                        if current_rate < packet.receiving_interface.announce_rate_target: rate_entry["rate_violations"] += 1
                                        else: rate_entry["rate_violations"] = max(0, rate_entry["rate_violations"]-1)

                                        if rate_entry["rate_violations"] > packet.receiving_interface.announce_rate_grace:
                                            rate_target = packet.receiving_interface.announce_rate_target
                                            rate_penalty = packet.receiving_interface.announce_rate_penalty
                                            rate_entry["blocked_until"] = rate_entry["last"] + rate_target + rate_penalty
                                            rate_blocked = True
                                        else:
                                            rate_entry["last"] = now

                                    else:
                                        rate_blocked = True
                                        

                            retries            = 0
                            announce_hops      = packet.hops
                            local_rebroadcasts = 0
                            block_rebroadcasts = False
                            attached_interface = None
                            
                            retransmit_timeout = now + (RNS.rand() * Transport.PATHFINDER_RW)

                            if hasattr(packet.receiving_interface, "mode") and packet.receiving_interface.mode == RNS.Interfaces.Interface.Interface.MODE_ACCESS_POINT:
                                expires            = now + Transport.AP_PATH_TIME
                            elif hasattr(packet.receiving_interface, "mode") and packet.receiving_interface.mode == RNS.Interfaces.Interface.Interface.MODE_ROAMING:
                                expires            = now + Transport.ROAMING_PATH_TIME
                            else:
                                expires            = now + Transport.PATHFINDER_E
                            
                            if not random_blob in random_blobs:
                                random_blobs.append(random_blob)
                                random_blobs = random_blobs[-Transport.MAX_RANDOM_BLOBS:]

                            if (RNS.Reticulum.transport_enabled() or Transport.from_local_client(packet)) and packet.context != RNS.Packet.PATH_RESPONSE:
                                # Insert announce into announce table for retransmission

                                if rate_blocked:
                                    RNS.log("Blocking rebroadcast of announce from "+RNS.prettyhexrep(packet.destination_hash)+" due to excessive announce rate", RNS.LOG_DEBUG)
                                
                                else:
                                    if Transport.from_local_client(packet):
                                        # If the announce is from a local client,
                                        # it is announced immediately, but only one time.
                                        retransmit_timeout = now
                                        retries = Transport.PATHFINDER_R

                                    Transport.announce_table[packet.destination_hash] = [
                                        now,                # 0: IDX_AT_TIMESTAMP
                                        retransmit_timeout, # 1: IDX_AT_RTRNS_TMO
                                        retries,            # 2: IDX_AT_RETRIES
                                        received_from,      # 3: IDX_AT_RCVD_IF
                                        announce_hops,      # 4: IDX_AT_HOPS
                                        packet,             # 5: IDX_AT_PACKET
                                        local_rebroadcasts, # 6: IDX_AT_LCL_RBRD
                                        block_rebroadcasts, # 7: IDX_AT_BLCK_RBRD
                                        attached_interface, # 8: IDX_AT_ATTCHD_IF
                                    ]

                            # TODO: Check from_local_client once and store result
                            elif Transport.from_local_client(packet) and packet.context == RNS.Packet.PATH_RESPONSE:
                                # If this is a path response from a local client,
                                # check if any external interfaces have pending
                                # path requests.
                                if packet.destination_hash in Transport.pending_local_path_requests:
                                    desiring_interface = Transport.pending_local_path_requests.pop(packet.destination_hash)
                                    retransmit_timeout = now
                                    retries = Transport.PATHFINDER_R

                                    Transport.announce_table[packet.destination_hash] = [
                                        now,
                                        retransmit_timeout,
                                        retries,
                                        received_from,
                                        announce_hops,
                                        packet,
                                        local_rebroadcasts,
                                        block_rebroadcasts,
                                        attached_interface
                                    ]

                            # If we have any local clients connected, we re-
                            # transmit the announce to them immediately
                            if (len(Transport.local_client_interfaces)):
                                announce_identity = RNS.Identity.recall(packet.destination_hash)
                                announce_destination = RNS.Destination(announce_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, "unknown", "unknown");
                                announce_destination.hash = packet.destination_hash
                                announce_destination.hexhash = announce_destination.hash.hex()
                                announce_context = RNS.Packet.NONE
                                announce_data = packet.data

                                # TODO: Shouldn't the context be PATH_RESPONSE in the first case here?
                                if Transport.from_local_client(packet) and packet.context == RNS.Packet.PATH_RESPONSE:
                                    for local_interface in Transport.local_client_interfaces:
                                        if packet.receiving_interface != local_interface:
                                            new_announce = RNS.Packet(
                                                announce_destination,
                                                announce_data,
                                                RNS.Packet.ANNOUNCE,
                                                context = announce_context,
                                                header_type = RNS.Packet.HEADER_2,
                                                transport_type = Transport.TRANSPORT,
                                                transport_id = Transport.identity.hash,
                                                attached_interface = local_interface,
                                                context_flag = packet.context_flag,
                                            )
                                            
                                            new_announce.hops = packet.hops
                                            new_announce.send()

                                else:
                                    for local_interface in Transport.local_client_interfaces:
                                        if packet.receiving_interface != local_interface:
                                            new_announce = RNS.Packet(
                                                announce_destination,
                                                announce_data,
                                                RNS.Packet.ANNOUNCE,
                                                context = announce_context,
                                                header_type = RNS.Packet.HEADER_2,
                                                transport_type = Transport.TRANSPORT,
                                                transport_id = Transport.identity.hash,
                                                attached_interface = local_interface,
                                                context_flag = packet.context_flag,
                                            )

                                            new_announce.hops = packet.hops
                                            new_announce.send()

                            # If we have any waiting discovery path requests
                            # for this destination, we retransmit to that
                            # interface immediately
                            if packet.destination_hash in Transport.discovery_path_requests:
                                pr_entry = Transport.discovery_path_requests[packet.destination_hash]
                                attached_interface = pr_entry["requesting_interface"]

                                interface_str = " on "+str(attached_interface)

                                RNS.log("Got matching announce, answering waiting discovery path request for "+RNS.prettyhexrep(packet.destination_hash)+interface_str, RNS.LOG_DEBUG)
                                announce_identity = RNS.Identity.recall(packet.destination_hash)
                                announce_destination = RNS.Destination(announce_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, "unknown", "unknown");
                                announce_destination.hash = packet.destination_hash
                                announce_destination.hexhash = announce_destination.hash.hex()
                                announce_context = RNS.Packet.NONE
                                announce_data = packet.data

                                new_announce = RNS.Packet(
                                    announce_destination,
                                    announce_data,
                                    RNS.Packet.ANNOUNCE,
                                    context = RNS.Packet.PATH_RESPONSE,
                                    header_type = RNS.Packet.HEADER_2,
                                    transport_type = Transport.TRANSPORT,
                                    transport_id = Transport.identity.hash,
                                    attached_interface = attached_interface,
                                    context_flag = packet.context_flag,
                                )

                                new_announce.hops = packet.hops
                                new_announce.send()

                            if not Transport.owner.is_connected_to_shared_instance: Transport.cache(packet, force_cache=True, packet_type="announce")
                            path_table_entry = [now, received_from, announce_hops, expires, random_blobs, packet.receiving_interface, packet.packet_hash]
                            Transport.path_table[packet.destination_hash] = path_table_entry
                            RNS.log("Destination "+RNS.prettyhexrep(packet.destination_hash)+" is now "+str(announce_hops)+" hops away via "+RNS.prettyhexrep(received_from)+" on "+str(packet.receiving_interface), RNS.LOG_DEBUG)

                            # If the receiving interface is a tunnel, we add the
                            # announce to the tunnels table
                            if hasattr(packet.receiving_interface, "tunnel_id") and packet.receiving_interface.tunnel_id != None:
                                tunnel_entry = Transport.tunnels[packet.receiving_interface.tunnel_id]
                                paths = tunnel_entry[IDX_TT_PATHS]
                                paths[packet.destination_hash] = [now, received_from, announce_hops, expires, random_blobs, None, packet.packet_hash]
                                expires = time.time() + Transport.DESTINATION_TIMEOUT
                                tunnel_entry[IDX_TT_EXPIRES] = expires
                                RNS.log("Path to "+RNS.prettyhexrep(packet.destination_hash)+" associated with tunnel "+RNS.prettyhexrep(packet.receiving_interface.tunnel_id), RNS.LOG_DEBUG)

                            # Call externally registered callbacks from apps
                            # wanting to know when an announce arrives
                            for handler in Transport.announce_handlers:
                                try:
                                    # Check that the announced destination matches
                                    # the handlers aspect filter
                                    execute_callback = False
                                    announce_identity = RNS.Identity.recall(packet.destination_hash)
                                    if handler.aspect_filter == None:
                                        # If the handlers aspect filter is set to
                                        # None, we execute the callback in all cases
                                        execute_callback = True
                                    else:
                                        handler_expected_hash = RNS.Destination.hash_from_name_and_identity(handler.aspect_filter, announce_identity)
                                        if packet.destination_hash == handler_expected_hash:
                                            execute_callback = True

                                    # If this is a path response, check whether the
                                    # handler wants to receive it.
                                    if packet.context == RNS.Packet.PATH_RESPONSE:
                                        if hasattr(handler, "receive_path_responses") and handler.receive_path_responses == True:
                                            pass
                                        else:
                                            execute_callback = False

                                    if execute_callback:

                                        if len(inspect.signature(handler.received_announce).parameters) == 3:
                                            handler.received_announce(destination_hash=packet.destination_hash,
                                                                      announced_identity=announce_identity,
                                                                      app_data=RNS.Identity.recall_app_data(packet.destination_hash))
                                        
                                        elif len(inspect.signature(handler.received_announce).parameters) == 4:
                                            handler.received_announce(destination_hash=packet.destination_hash,
                                                                      announced_identity=announce_identity,
                                                                      app_data=RNS.Identity.recall_app_data(packet.destination_hash),
                                                                      announce_packet_hash = packet.packet_hash)
                                        else:
                                            raise TypeError("Invalid signature for announce handler callback")

                                except Exception as e:
                                    RNS.log("Error while processing external announce callback.", RNS.LOG_ERROR)
                                    RNS.log("The contained exception was: "+str(e), RNS.LOG_ERROR)
                                    RNS.trace_exception(e)

            # Handling for link requests to local destinations
            elif packet.packet_type == RNS.Packet.LINKREQUEST:
                if packet.transport_id == None or packet.transport_id == Transport.identity.hash:
                    for destination in Transport.destinations:
                        if destination.hash == packet.destination_hash and destination.type == packet.destination_type:
                            path_mtu       = RNS.Link.mtu_from_lr_packet(packet)
                            mode           = RNS.Link.mode_from_lr_packet(packet)
                            if packet.receiving_interface.AUTOCONFIGURE_MTU or packet.receiving_interface.FIXED_MTU:
                                nh_mtu     = packet.receiving_interface.HW_MTU
                            else:
                                nh_mtu     = RNS.Reticulum.MTU

                            if path_mtu:
                                if packet.receiving_interface.HW_MTU == None:
                                    RNS.log(f"No next-hop HW MTU, disabling link MTU upgrade", RNS.LOG_DEBUG) # TODO: Remove debug
                                    path_mtu = None
                                    packet.data  = packet.data[:-RNS.Link.LINK_MTU_SIZE]
                                else:
                                    if nh_mtu < path_mtu:
                                        try:
                                            path_mtu = nh_mtu
                                            clamped_mtu = RNS.Link.signalling_bytes(path_mtu, mode)
                                            RNS.log(f"Clamping link MTU to {RNS.prettysize(nh_mtu)}", RNS.LOG_DEBUG) # TODO: Remove debug
                                            packet.data  = packet.data[:-RNS.Link.LINK_MTU_SIZE]+clamped_mtu
                                        except Exception as e:
                                            RNS.log(f"Dropping link request packet to local destination. The contained exception was: {e}", RNS.LOG_WARNING)
                                            return

                            packet.destination = destination
                            destination.receive(packet)
            
            # Handling for local data packets
            elif packet.packet_type == RNS.Packet.DATA:
                if packet.destination_type == RNS.Destination.LINK:
                    for link in Transport.active_links:
                        if link.link_id == packet.destination_hash:
                            if link.attached_interface == packet.receiving_interface:
                                packet.link = link
                                if packet.context == RNS.Packet.CACHE_REQUEST:
                                    cached_packet = Transport.get_cached_packet(packet.data)
                                    if cached_packet != None:
                                        cached_packet.unpack()
                                        RNS.Packet(destination=link, data=cached_packet.data,
                                                   packet_type=cached_packet.packet_type, context=cached_packet.context).send()

                                    Transport.jobs_locked = False
                                else:
                                    link.receive(packet)
                            else:
                                # In the strange and rare case that an interface
                                # is partly malfunctioning, and a link-associated
                                # packet is being received on an interface that
                                # has failed sending, and transport has failed over
                                # to another path, we remove this packet hash from
                                # the filter hashlist so the link can receive the
                                # packet when it finally arrives over another path.
                                while packet.packet_hash in Transport.packet_hashlist:
                                    Transport.packet_hashlist.remove(packet.packet_hash)
                else:
                    for destination in Transport.destinations:
                        if destination.hash == packet.destination_hash and destination.type == packet.destination_type:
                            packet.destination = destination
                            if destination.receive(packet):
                                if destination.proof_strategy == RNS.Destination.PROVE_ALL:
                                    packet.prove()

                                elif destination.proof_strategy == RNS.Destination.PROVE_APP:
                                    if destination.callbacks.proof_requested:
                                        try:
                                            if destination.callbacks.proof_requested(packet):
                                                packet.prove()
                                        except Exception as e:
                                            RNS.log("Error while executing proof request callback. The contained exception was: "+str(e), RNS.LOG_ERROR)

            # Handling for proofs and link-request proofs
            elif packet.packet_type == RNS.Packet.PROOF:
                if packet.context == RNS.Packet.LRPROOF:
                    # This is a link request proof, check if it
                    # needs to be transported
                    if (RNS.Reticulum.transport_enabled() or for_local_client_link or from_local_client) and packet.destination_hash in Transport.link_table:
                        link_entry = Transport.link_table[packet.destination_hash]
                        if packet.hops == link_entry[IDX_LT_REM_HOPS]:
                            if packet.receiving_interface == link_entry[IDX_LT_NH_IF]:
                                try:
                                    if len(packet.data) == RNS.Identity.SIGLENGTH//8+RNS.Link.ECPUBSIZE//2 or len(packet.data) == RNS.Identity.SIGLENGTH//8+RNS.Link.ECPUBSIZE//2+RNS.Link.LINK_MTU_SIZE:
                                        signalling_bytes = b""
                                        if len(packet.data) == RNS.Identity.SIGLENGTH//8+RNS.Link.ECPUBSIZE//2+RNS.Link.LINK_MTU_SIZE:
                                            signalling_bytes = RNS.Link.signalling_bytes(RNS.Link.mtu_from_lp_packet(packet), RNS.Link.mode_from_lp_packet(packet))

                                        peer_pub_bytes = packet.data[RNS.Identity.SIGLENGTH//8:RNS.Identity.SIGLENGTH//8+RNS.Link.ECPUBSIZE//2]
                                        peer_identity = RNS.Identity.recall(link_entry[IDX_LT_DSTHASH])
                                        peer_sig_pub_bytes = peer_identity.get_public_key()[RNS.Link.ECPUBSIZE//2:RNS.Link.ECPUBSIZE]

                                        signed_data = packet.destination_hash+peer_pub_bytes+peer_sig_pub_bytes+signalling_bytes
                                        signature = packet.data[:RNS.Identity.SIGLENGTH//8]

                                        if peer_identity.validate(signature, signed_data):
                                            RNS.log("Link request proof validated for transport via "+str(link_entry[IDX_LT_RCVD_IF]), RNS.LOG_EXTREME)
                                            new_raw = packet.raw[0:1]
                                            new_raw += struct.pack("!B", packet.hops)
                                            new_raw += packet.raw[2:]
                                            Transport.link_table[packet.destination_hash][IDX_LT_VALIDATED] = True
                                            Transport.transmit(link_entry[IDX_LT_RCVD_IF], new_raw)

                                        else:
                                            RNS.log("Invalid link request proof in transport for link "+RNS.prettyhexrep(packet.destination_hash)+", dropping proof.", RNS.LOG_DEBUG)

                                except Exception as e:
                                    RNS.log("Error while transporting link request proof. The contained exception was: "+str(e), RNS.LOG_ERROR)

                            else:
                                RNS.log("Link request proof received on wrong interface, not transporting it.", RNS.LOG_DEBUG)
                        else:
                            RNS.log("Received link request proof with hop mismatch, not transporting it", RNS.LOG_DEBUG)
                    else:
                        # Check if we can deliver it to a local
                        # pending link
                        for link in Transport.pending_links:
                            if link.link_id == packet.destination_hash:
                                # We need to also allow an expected hops value of
                                # PATHFINDER_M, since in some cases, the number of hops
                                # to the destination will be unknown at link creation
                                # time. The real chance of this occuring is likely to be
                                # extremely small, and this allowance could probably
                                # be discarded without major issues, but it is kept
                                # for now to ensure backwards compatibility.

                                # TODO: Probably reset check back to
                                # if packet.hops == link.expected_hops:
                                # within one of the next releases

                                if packet.hops == link.expected_hops or link.expected_hops == RNS.Transport.PATHFINDER_M:
                                    # Add this packet to the filter hashlist if we
                                    # have determined that it's actually destined
                                    # for this system, and then validate the proof
                                    Transport.add_packet_hash(packet.packet_hash)
                                    link.validate_proof(packet)

                elif packet.context == RNS.Packet.RESOURCE_PRF:
                    for link in Transport.active_links:
                        if link.link_id == packet.destination_hash:
                            link.receive(packet)
                else:
                    if packet.destination_type == RNS.Destination.LINK:
                        for link in Transport.active_links:
                            if link.link_id == packet.destination_hash:
                                packet.link = link
                                
                    if len(packet.data) == RNS.PacketReceipt.EXPL_LENGTH:
                        proof_hash = packet.data[:RNS.Identity.HASHLENGTH//8]
                    else:
                        proof_hash = None

                    # Check if this proof needs to be transported
                    if (RNS.Reticulum.transport_enabled() or from_local_client or proof_for_local_client) and packet.destination_hash in Transport.reverse_table:
                        reverse_entry = Transport.reverse_table.pop(packet.destination_hash)
                        if packet.receiving_interface == reverse_entry[IDX_RT_OUTB_IF]:
                            RNS.log("Proof received on correct interface, transporting it via "+str(reverse_entry[IDX_RT_RCVD_IF]), RNS.LOG_EXTREME)
                            new_raw = packet.raw[0:1]
                            new_raw += struct.pack("!B", packet.hops)
                            new_raw += packet.raw[2:]
                            Transport.transmit(reverse_entry[IDX_RT_RCVD_IF], new_raw)
                        else:
                            RNS.log("Proof received on wrong interface, not transporting it.", RNS.LOG_DEBUG)

                    for receipt in Transport.receipts:
                        receipt_validated = False
                        if proof_hash != None:
                            # Only test validation if hash matches
                            if receipt.hash == proof_hash:
                                receipt_validated = receipt.validate_proof_packet(packet)
                        else:
                            # In case of an implicit proof, we have
                            # to check every single outstanding receipt
                            receipt_validated = receipt.validate_proof_packet(packet)

                        if receipt_validated:
                            if receipt in Transport.receipts:
                                Transport.receipts.remove(receipt)

        Transport.jobs_locked = False

    @staticmethod
    def synthesize_tunnel(interface):
        interface_hash = interface.get_hash()
        public_key     = RNS.Transport.identity.get_public_key()
        random_hash    = RNS.Identity.get_random_hash()
        
        tunnel_id_data = public_key+interface_hash
        tunnel_id      = RNS.Identity.full_hash(tunnel_id_data)

        signed_data    = tunnel_id_data+random_hash
        signature      = Transport.identity.sign(signed_data)
        
        data           = signed_data+signature

        tnl_snth_dst   = RNS.Destination(None, RNS.Destination.OUT, RNS.Destination.PLAIN, Transport.APP_NAME, "tunnel", "synthesize")

        packet = RNS.Packet(tnl_snth_dst, data, packet_type = RNS.Packet.DATA, transport_type = RNS.Transport.BROADCAST, header_type = RNS.Packet.HEADER_1, attached_interface = interface)
        packet.send()

        interface.wants_tunnel = False

    @staticmethod
    def tunnel_synthesize_handler(data, packet):
        try:
            expected_length = RNS.Identity.KEYSIZE//8+RNS.Identity.HASHLENGTH//8+RNS.Reticulum.TRUNCATED_HASHLENGTH//8+RNS.Identity.SIGLENGTH//8
            if len(data) == expected_length:
                public_key     = data[:RNS.Identity.KEYSIZE//8]
                interface_hash = data[RNS.Identity.KEYSIZE//8:RNS.Identity.KEYSIZE//8+RNS.Identity.HASHLENGTH//8]
                tunnel_id_data = public_key+interface_hash
                tunnel_id      = RNS.Identity.full_hash(tunnel_id_data)
                random_hash    = data[RNS.Identity.KEYSIZE//8+RNS.Identity.HASHLENGTH//8:RNS.Identity.KEYSIZE//8+RNS.Identity.HASHLENGTH//8+RNS.Reticulum.TRUNCATED_HASHLENGTH//8]
                
                signature      = data[RNS.Identity.KEYSIZE//8+RNS.Identity.HASHLENGTH//8+RNS.Reticulum.TRUNCATED_HASHLENGTH//8:expected_length]
                signed_data    = tunnel_id_data+random_hash

                remote_transport_identity = RNS.Identity(create_keys=False)
                remote_transport_identity.load_public_key(public_key)

                if remote_transport_identity.validate(signature, signed_data):
                    Transport.handle_tunnel(tunnel_id, packet.receiving_interface)

        except Exception as e:
            RNS.log("An error occurred while validating tunnel establishment packet.", RNS.LOG_DEBUG)
            RNS.log("The contained exception was: "+str(e), RNS.LOG_DEBUG)

    @staticmethod
    def void_tunnel_interface(tunnel_id):
        if tunnel_id in Transport.tunnels:
            RNS.log(f"Voiding tunnel interface {Transport.tunnels[tunnel_id][IDX_TT_IF]}", RNS.LOG_EXTREME)
            Transport.tunnels[tunnel_id][IDX_TT_IF] = None

    @staticmethod
    def handle_tunnel(tunnel_id, interface):
        expires = time.time() + Transport.DESTINATION_TIMEOUT
        if not tunnel_id in Transport.tunnels:
            RNS.log("Tunnel endpoint "+RNS.prettyhexrep(tunnel_id)+" established.", RNS.LOG_DEBUG)
            paths = {}
            tunnel_entry = [tunnel_id, interface, paths, expires]
            interface.tunnel_id = tunnel_id
            Transport.tunnels[tunnel_id] = tunnel_entry
        else:
            RNS.log("Tunnel endpoint "+RNS.prettyhexrep(tunnel_id)+" reappeared. Restoring paths...", RNS.LOG_DEBUG)
            tunnel_entry = Transport.tunnels[tunnel_id]
            tunnel_entry[IDX_TT_IF] = interface
            tunnel_entry[IDX_TT_EXPIRES] = expires
            interface.tunnel_id = tunnel_id
            paths = tunnel_entry[IDX_TT_PATHS]

            deprecated_paths = []
            for destination_hash, path_entry in paths.items():
                received_from = path_entry[1]
                announce_hops = path_entry[2]
                expires = path_entry[3]
                random_blobs = list(set(path_entry[4]))
                receiving_interface = interface
                packet_hash = path_entry[6]
                new_entry = [time.time(), received_from, announce_hops, expires, random_blobs, receiving_interface, packet_hash]

                should_add = False
                if destination_hash in Transport.path_table:
                    old_entry = Transport.path_table[destination_hash]
                    old_hops = old_entry[IDX_PT_HOPS]
                    old_expires = old_entry[IDX_PT_EXPIRES]
                    if announce_hops <= old_hops or time.time() > old_expires: should_add = True
                    else: RNS.log("Did not restore path to "+RNS.prettyhexrep(destination_hash)+" because a newer path with fewer hops exist", RNS.LOG_DEBUG)
                
                else:
                    if time.time() < expires: should_add = True
                    else: RNS.log("Did not restore path to "+RNS.prettyhexrep(destination_hash)+" because it has expired", RNS.LOG_DEBUG)

                if should_add:
                    Transport.path_table[destination_hash] = new_entry
                    RNS.log("Restored path to "+RNS.prettyhexrep(destination_hash)+" is now "+str(announce_hops)+" hops away via "+RNS.prettyhexrep(received_from)+" on "+str(receiving_interface), RNS.LOG_DEBUG)
                else:
                    deprecated_paths.append(destination_hash)

            for deprecated_path in deprecated_paths:
                RNS.log("Removing path to "+RNS.prettyhexrep(deprecated_path)+" from tunnel "+RNS.prettyhexrep(tunnel_id), RNS.LOG_DEBUG)
                paths.pop(deprecated_path)

    @staticmethod
    def register_destination(destination):
        destination.MTU = RNS.Reticulum.MTU
        if destination.direction == RNS.Destination.IN:
            for registered_destination in Transport.destinations:
                if destination.hash == registered_destination.hash:
                    raise KeyError("Attempt to register an already registered destination.")
            
            Transport.destinations.append(destination)

            if Transport.owner.is_connected_to_shared_instance:
                if destination.type == RNS.Destination.SINGLE:
                    destination.announce(path_response=True)

    @staticmethod
    def deregister_destination(destination):
        if destination in Transport.destinations:
            Transport.destinations.remove(destination)

    @staticmethod
    def register_link(link):
        RNS.log("Registering link "+str(link), RNS.LOG_EXTREME)
        if link.initiator:
            Transport.pending_links.append(link)
        else:
            Transport.active_links.append(link)

    @staticmethod
    def activate_link(link):
        RNS.log("Activating link "+str(link), RNS.LOG_EXTREME)
        if link in Transport.pending_links:
            if link.status != RNS.Link.ACTIVE:
                raise IOError("Invalid link state for link activation: "+str(link.status))
            Transport.pending_links.remove(link)
            Transport.active_links.append(link)
            link.status = RNS.Link.ACTIVE
        else:
            RNS.log("Attempted to activate a link that was not in the pending table", RNS.LOG_ERROR)

    @staticmethod
    def register_announce_handler(handler):
        """
        Registers an announce handler.

        :param handler: Must be an object with an *aspect_filter* attribute and a *received_announce(destination_hash, announced_identity, app_data)*
                        or *received_announce(destination_hash, announced_identity, app_data, announce_packet_hash)* callable. Can optionally have a
                        *receive_path_responses* attribute set to ``True``, to also receive all path responses, in addition to live announces. See
                        the :ref:`Announce Example<example-announce>` for more info.
        """
        if hasattr(handler, "received_announce") and callable(handler.received_announce):
            if hasattr(handler, "aspect_filter"):
                Transport.announce_handlers.append(handler)

    @staticmethod
    def deregister_announce_handler(handler):
        """
        Deregisters an announce handler.

        :param handler: The announce handler to be deregistered.
        """
        while handler in Transport.announce_handlers: Transport.announce_handlers.remove(handler)
        gc.collect()

    @staticmethod
    def find_interface_from_hash(interface_hash):
        for interface in Transport.interfaces:
            if interface.get_hash() == interface_hash:
                return interface

        return None

    @staticmethod
    def should_cache(packet):
        # TODO: Rework the caching system. It's currently
        # not very useful to even cache Resource proofs,
        # disabling it for now, until redesigned.
        # if packet.context == RNS.Packet.RESOURCE_PRF:
        #     return True

        return False

    @staticmethod
    def clean_cache():
        if not Transport.owner.is_connected_to_shared_instance:
            Transport.clean_announce_cache()
            Transport.cache_last_cleaned = time.time()

    @staticmethod
    def clean_announce_cache():
        st = time.time()
        target_path = os.path.join(RNS.Reticulum.cachepath, "announces")
        active_paths = [Transport.path_table[dst_hash][6] for dst_hash in Transport.path_table]
        tunnel_paths = list(set([path_dict[dst_hash][6] for path_dict in [Transport.tunnels[tunnel_id][2] for tunnel_id in Transport.tunnels] for dst_hash in path_dict]))
        removed = 0
        for packet_hash in os.listdir(target_path):
            remove = False
            full_path = os.path.join(target_path, packet_hash)
            if os.path.isfile(full_path):
                try: target_hash = bytes.fromhex(packet_hash)
                except: remove = True
                if (not target_hash in active_paths) and (not target_hash in tunnel_paths): remove = True
                if remove: os.unlink(full_path); removed += 1

        if removed > 0:
            RNS.log(f"Removed {removed} cached announces in {RNS.prettytime(time.time()-st)}", RNS.LOG_DEBUG)

    # When caching packets to storage, they are written
    # exactly as they arrived over their interface. This
    # means that they have not had their hop count
    # increased yet! Take note of this when reading from
    # the packet cache.
    @staticmethod
    def cache(packet, force_cache=False, packet_type=None):
        if force_cache or RNS.Transport.should_cache(packet):
            try:
                packet_hash = RNS.hexrep(packet.get_hash(), delimit=False)
                interface_reference = None
                if packet.receiving_interface != None: interface_reference = str(packet.receiving_interface)
                if packet_type == "announce": cachepath = os.path.join(RNS.Reticulum.cachepath, "announces", packet_hash)
                else:                         cachepath = os.path.join(RNS.Reticulum.cachepath, packet_hash)

                file = open(cachepath, "wb")
                file.write(umsgpack.packb([packet.raw, interface_reference]))
                file.close()

            except Exception as e:
                RNS.log("Error writing packet to cache. The contained exception was: "+str(e), RNS.LOG_ERROR)

    @staticmethod
    def get_cached_packet(packet_hash, packet_type=None):
        try:
            packet_hash = RNS.hexrep(packet_hash, delimit=False)
            if packet_type == "announce": path = os.path.join(RNS.Reticulum.cachepath, "announces", packet_hash)
            else:                         path = os.path.join(RNS.Reticulum.cachepath, packet_hash)

            if os.path.isfile(path):
                file = open(path, "rb")
                cached_data = umsgpack.unpackb(file.read())
                file.close()

                packet = RNS.Packet(None, cached_data[0])
                interface_reference = cached_data[1]

                for interface in Transport.interfaces:
                    if str(interface) == interface_reference:
                        packet.receiving_interface = interface

                return packet

            else: return None
        
        except Exception as e:
            RNS.log("Exception occurred while getting cached packet.", RNS.LOG_ERROR)
            RNS.log("The contained exception was: "+str(e), RNS.LOG_ERROR)
            return None

    @staticmethod
    def cache_request_packet(packet):
        if len(packet.data) == RNS.Identity.HASHLENGTH/8:
            packet = Transport.get_cached_packet(packet.data)

            if packet != None:
                # If the packet was retrieved from the local
                # cache, replay it to the Transport instance,
                # so that it can be directed towards it original
                # destination.
                Transport.inbound(packet.raw, packet.receiving_interface)
                return True
            else:
                return False
        else:
            return False

    @staticmethod
    def cache_request(packet_hash, destination):
        cached_packet = Transport.get_cached_packet(packet_hash)
        if cached_packet:
            # The packet was found in the local cache,
            # replay it to the Transport instance.
            Transport.inbound(cached_packet.raw, cached_packet.receiving_interface)
        else:
            # The packet is not in the local cache,
            # query the network.
            RNS.Packet(destination, packet_hash, context = RNS.Packet.CACHE_REQUEST).send()

    @staticmethod
    def has_path(destination_hash):
        """
        :param destination_hash: A destination hash as *bytes*.
        :returns: *True* if a path to the destination is known, otherwise *False*.
        """
        if destination_hash in Transport.path_table: return True
        else: return False

    @staticmethod
    def hops_to(destination_hash):
        """
        :param destination_hash: A destination hash as *bytes*.
        :returns: The number of hops to the specified destination, or ``RNS.Transport.PATHFINDER_M`` if the number of hops is unknown.
        """
        if destination_hash in Transport.path_table: return Transport.path_table[destination_hash][IDX_PT_HOPS]
        else: return Transport.PATHFINDER_M

    @staticmethod
    def next_hop(destination_hash):
        """
        :param destination_hash: A destination hash as *bytes*.
        :returns: The destination hash as *bytes* for the next hop to the specified destination, or *None* if the next hop is unknown.
        """
        if destination_hash in Transport.path_table: return Transport.path_table[destination_hash][IDX_PT_NEXT_HOP]
        else: return None

    @staticmethod
    def next_hop_interface(destination_hash):
        """
        :param destination_hash: A destination hash as *bytes*.
        :returns: The interface for the next hop to the specified destination, or *None* if the interface is unknown.
        """
        if destination_hash in Transport.path_table: return Transport.path_table[destination_hash][IDX_PT_RVCD_IF]
        else: return None

    @staticmethod
    def next_hop_interface_bitrate(destination_hash):
        next_hop_interface = Transport.next_hop_interface(destination_hash)
        if next_hop_interface != None: return next_hop_interface.bitrate
        else: return None

    @staticmethod
    def next_hop_interface_hw_mtu(destination_hash):
        next_hop_interface = Transport.next_hop_interface(destination_hash)
        if next_hop_interface != None:
            if next_hop_interface.AUTOCONFIGURE_MTU or next_hop_interface.FIXED_MTU: return next_hop_interface.HW_MTU
            else: return None
        else:
            return None

    @staticmethod
    def next_hop_per_bit_latency(destination_hash):
        next_hop_interface_bitrate = Transport.next_hop_interface_bitrate(destination_hash)
        if next_hop_interface_bitrate != None: return (1/next_hop_interface_bitrate)
        else: return None

    @staticmethod
    def next_hop_per_byte_latency(destination_hash):
        per_bit_latency = Transport.next_hop_per_bit_latency(destination_hash)
        if per_bit_latency != None: return per_bit_latency*8
        else: return None

    @staticmethod
    def first_hop_timeout(destination_hash):
        latency = Transport.next_hop_per_byte_latency(destination_hash)
        if latency != None: return RNS.Reticulum.MTU * latency + RNS.Reticulum.DEFAULT_PER_HOP_TIMEOUT
        else: return RNS.Reticulum.DEFAULT_PER_HOP_TIMEOUT

    @staticmethod
    def extra_link_proof_timeout(interface):
        if interface != None: return ((1/interface.bitrate)*8)*RNS.Reticulum.MTU
        else: return 0

    @staticmethod
    def expire_path(destination_hash):
        if destination_hash in Transport.path_table:
            Transport.path_table[destination_hash][IDX_PT_TIMESTAMP] = 0
            Transport.tables_last_culled = 0
            return True
        else:
            return False

    @staticmethod
    def mark_path_unresponsive(destination_hash):
        if destination_hash in Transport.path_table:
            Transport.path_states[destination_hash] = Transport.STATE_UNRESPONSIVE
            return True
        else:
            return False

    @staticmethod
    def mark_path_responsive(destination_hash):
        if destination_hash in Transport.path_table:
            Transport.path_states[destination_hash] = Transport.STATE_RESPONSIVE
            return True
        else:
            return False

    @staticmethod
    def mark_path_unknown_state(destination_hash):
        if destination_hash in Transport.path_table:
            Transport.path_states[destination_hash] = Transport.STATE_UNKNOWN
            return True
        else:
            return False

    @staticmethod
    def path_is_unresponsive(destination_hash):
        if destination_hash in Transport.path_states:
            if Transport.path_states[destination_hash] == Transport.STATE_UNRESPONSIVE:
                return True

        return False

    @staticmethod
    def request_path(destination_hash, on_interface=None, tag=None, recursive=False):
        """
        Requests a path to the destination from the network. If
        another reachable peer on the network knows a path, it
        will announce it.

        :param destination_hash: A destination hash as *bytes*.
        :param on_interface: If specified, the path request will only be sent on this interface. In normal use, Reticulum handles this automatically, and this parameter should not be used.
        """
        if tag == None:
            request_tag = RNS.Identity.get_random_hash()
        else:
            request_tag = tag

        if RNS.Reticulum.transport_enabled():
            path_request_data = destination_hash+Transport.identity.hash+request_tag
        else:
            path_request_data = destination_hash+request_tag

        path_request_dst = RNS.Destination(None, RNS.Destination.OUT, RNS.Destination.PLAIN, Transport.APP_NAME, "path", "request")
        packet = RNS.Packet(path_request_dst, path_request_data, packet_type = RNS.Packet.DATA, transport_type = RNS.Transport.BROADCAST, header_type = RNS.Packet.HEADER_1, attached_interface = on_interface)

        if on_interface != None and recursive:
            if not hasattr(on_interface, "announce_cap"):
                on_interface.announce_cap = RNS.Reticulum.ANNOUNCE_CAP

            if not hasattr(on_interface, "announce_allowed_at"):
                on_interface.announce_allowed_at = 0

            if not hasattr(on_interface, "announce_queue"):
                on_interface.announce_queue = []

            queued_announces = True if len(on_interface.announce_queue) > 0 else False
            if queued_announces:
                RNS.log("Blocking recursive path request on "+str(on_interface)+" due to queued announces", RNS.LOG_EXTREME)
                return
            else:
                now = time.time()
                if now < on_interface.announce_allowed_at:
                    RNS.log("Blocking recursive path request on "+str(on_interface)+" due to active announce cap", RNS.LOG_EXTREME)
                    return
                else:
                    tx_time   = ((len(path_request_data)+RNS.Reticulum.HEADER_MINSIZE)*8) / on_interface.bitrate
                    wait_time = (tx_time / on_interface.announce_cap)
                    on_interface.announce_allowed_at = now + wait_time

        packet.send()
        Transport.path_requests[destination_hash] = time.time()

    @staticmethod
    def remote_status_handler(path, data, request_id, link_id, remote_identity, requested_at):
        if remote_identity != None:
            response = None
            try:
                if isinstance(data, list) and len(data) > 0:
                    response = []
                    response.append(Transport.owner.get_interface_stats())
                    if data[0] == True:
                        response.append(Transport.owner.get_link_count())

                    return response

            except Exception as e:
                RNS.log("An error occurred while processing remote status request from "+str(remote_identity), RNS.LOG_ERROR)
                RNS.log("The contained exception was: "+str(e), RNS.LOG_ERROR)

            return None

    @staticmethod
    def remote_path_handler(path, data, request_id, link_id, remote_identity, requested_at):
        if remote_identity != None:
            response = None
            try:
                if isinstance(data, list) and len(data) > 0:
                    command = data[0]
                    destination_hash = None
                    max_hops = None
                    if len(data) > 1:
                        destination_hash = data[1]
                    if len(data) > 2:
                        max_hops = data[2]

                    if command == "table":
                        table = Transport.owner.get_path_table(max_hops=max_hops)
                        response = []
                        for path in table:
                            if destination_hash == None or destination_hash == path["hash"]:
                                response.append(path)

                    elif command == "rates":
                        table = Transport.owner.get_rate_table()
                        response = []
                        for path in table:
                            if destination_hash == None or destination_hash == path["hash"]:
                                response.append(path)

                    return response

            except Exception as e:
                RNS.log("An error occurred while processing remote status request from "+str(remote_identity), RNS.LOG_ERROR)
                RNS.log("The contained exception was: "+str(e), RNS.LOG_ERROR)

            return None

    @staticmethod
    def path_request_handler(data, packet):
        try:
            # If there is at least bytes enough for a destination
            # hash in the packet, we assume those bytes are the
            # destination being requested.
            if len(data) >= RNS.Identity.TRUNCATED_HASHLENGTH//8:
                destination_hash = data[:RNS.Identity.TRUNCATED_HASHLENGTH//8]
                # If there is also enough bytes for a transport
                # instance ID and at least one tag byte, we
                # assume the next bytes to be the trasport ID
                # of the requesting transport instance.
                if len(data) > (RNS.Identity.TRUNCATED_HASHLENGTH//8)*2:
                    requesting_transport_instance = data[RNS.Identity.TRUNCATED_HASHLENGTH//8:(RNS.Identity.TRUNCATED_HASHLENGTH//8)*2]
                else:
                    requesting_transport_instance = None

                tag_bytes = None
                if len(data) > (RNS.Identity.TRUNCATED_HASHLENGTH//8)*2:
                    tag_bytes = data[RNS.Identity.TRUNCATED_HASHLENGTH//8*2:]

                elif len(data) > (RNS.Identity.TRUNCATED_HASHLENGTH//8):
                    tag_bytes = data[RNS.Identity.TRUNCATED_HASHLENGTH//8:]

                if tag_bytes != None:
                    if len(tag_bytes) > RNS.Identity.TRUNCATED_HASHLENGTH//8:
                        tag_bytes = tag_bytes[:RNS.Identity.TRUNCATED_HASHLENGTH//8]

                    unique_tag = destination_hash+tag_bytes

                    if not unique_tag in Transport.discovery_pr_tags:
                        Transport.discovery_pr_tags.append(unique_tag)

                        Transport.path_request(
                            destination_hash,
                            Transport.from_local_client(packet),
                            packet.receiving_interface,
                            requestor_transport_id = requesting_transport_instance,
                            tag=tag_bytes
                        )

                    else:
                        RNS.log("Ignoring duplicate path request for "+RNS.prettyhexrep(destination_hash)+" with tag "+RNS.prettyhexrep(unique_tag), RNS.LOG_DEBUG)

                else:
                    RNS.log("Ignoring tagless path request for "+RNS.prettyhexrep(destination_hash), RNS.LOG_DEBUG)

        except Exception as e:
            RNS.log("Error while handling path request. The contained exception was: "+str(e), RNS.LOG_ERROR)

    @staticmethod
    def path_request(destination_hash, is_from_local_client, attached_interface, requestor_transport_id=None, tag=None):
        should_search_for_unknown = False

        if attached_interface != None:
            if RNS.Reticulum.transport_enabled() and attached_interface.mode in RNS.Interfaces.Interface.Interface.DISCOVER_PATHS_FOR:
                should_search_for_unknown = True

            interface_str = " on "+str(attached_interface)
        else:
            interface_str = ""

        RNS.log("Path request for "+RNS.prettyhexrep(destination_hash)+interface_str, RNS.LOG_DEBUG)

        destination_exists_on_local_client = False
        if len(Transport.local_client_interfaces) > 0:
            if destination_hash in Transport.path_table:
                destination_interface = Transport.path_table[destination_hash][IDX_PT_RVCD_IF]
                
                if Transport.is_local_client_interface(destination_interface):
                    destination_exists_on_local_client = True
                    Transport.pending_local_path_requests[destination_hash] = attached_interface
        
        local_destination = next((d for d in Transport.destinations if d.hash == destination_hash), None)
        if local_destination != None:
            local_destination.announce(path_response=True, tag=tag, attached_interface=attached_interface)
            RNS.log("Answering path request for "+RNS.prettyhexrep(destination_hash)+interface_str+", destination is local to this system", RNS.LOG_DEBUG)

        elif (RNS.Reticulum.transport_enabled() or is_from_local_client) and (destination_hash in Transport.path_table):
            packet = Transport.get_cached_packet(Transport.path_table[destination_hash][IDX_PT_PACKET], packet_type="announce")
            next_hop = Transport.path_table[destination_hash][IDX_PT_NEXT_HOP]
            received_from = Transport.path_table[destination_hash][IDX_PT_RVCD_IF]

            if packet == None:
                RNS.log("Could not retrieve announce packet from cache while answering path request for "+RNS.prettyhexrep(destination_hash), RNS.LOG_ERROR)

            elif attached_interface.mode == RNS.Interfaces.Interface.Interface.MODE_ROAMING and attached_interface == received_from:
                RNS.log("Not answering path request on roaming-mode interface, since next hop is on same roaming-mode interface", RNS.LOG_DEBUG)

            else:
                packet.unpack()
                packet.hops = Transport.path_table[destination_hash][IDX_PT_HOPS]

                if requestor_transport_id != None and next_hop == requestor_transport_id:
                    # TODO: Find a bandwidth efficient way to invalidate our
                    # known path on this signal. The obvious way of signing
                    # path requests with transport instance keys is quite
                    # inefficient. There is probably a better way. Doing
                    # path invalidation here would decrease the network
                    # convergence time. Maybe just drop it?
                    RNS.log("Not answering path request for "+RNS.prettyhexrep(destination_hash)+interface_str+", since next hop is the requestor", RNS.LOG_DEBUG)
                else:
                    RNS.log("Answering path request for "+RNS.prettyhexrep(destination_hash)+interface_str+", path is known", RNS.LOG_DEBUG)

                    now = time.time()
                    retries = Transport.PATHFINDER_R
                    local_rebroadcasts = 0
                    block_rebroadcasts = True
                    announce_hops      = packet.hops

                    if is_from_local_client:
                        retransmit_timeout = now
                    else:
                        if Transport.is_local_client_interface(Transport.next_hop_interface(destination_hash)):
                            RNS.log("Path request destination "+RNS.prettyhexrep(destination_hash)+" is on a local client interface, rebroadcasting immediately", RNS.LOG_EXTREME)
                            retransmit_timeout = now

                        else:
                            retransmit_timeout = now + Transport.PATH_REQUEST_GRACE

                            # If we are answering on a roaming-mode interface, wait a
                            # little longer, to allow potential more well-connected
                            # peers to answer first.
                            if attached_interface.mode == RNS.Interfaces.Interface.Interface.MODE_ROAMING:
                                retransmit_timeout += Transport.PATH_REQUEST_RG

                    # This handles an edge case where a peer sends a past
                    # request for a destination just after an announce for
                    # said destination has arrived, but before it has been
                    # rebroadcast locally. In such a case the actual announce
                    # is temporarily held, and then reinserted when the path
                    # request has been served to the peer.
                    if packet.destination_hash in Transport.announce_table:
                        held_entry = Transport.announce_table[packet.destination_hash]
                        Transport.held_announces[packet.destination_hash] = held_entry
                    
                    Transport.announce_table[packet.destination_hash] = [now, retransmit_timeout, retries, received_from, announce_hops, packet, local_rebroadcasts, block_rebroadcasts, attached_interface]

        elif is_from_local_client:
            # Forward path request on all interfaces
            # except the local client
            RNS.log("Forwarding path request from local client for "+RNS.prettyhexrep(destination_hash)+interface_str+" to all other interfaces", RNS.LOG_DEBUG)
            request_tag = RNS.Identity.get_random_hash()
            for interface in Transport.interfaces:
                if not interface == attached_interface:
                    Transport.request_path(destination_hash, interface, tag = request_tag)

        elif should_search_for_unknown:
            if destination_hash in Transport.discovery_path_requests:
                RNS.log("There is already a waiting path request for "+RNS.prettyhexrep(destination_hash)+" on behalf of path request"+interface_str, RNS.LOG_DEBUG)
            else:
                # Forward path request on all interfaces
                # except the requestor interface
                RNS.log("Attempting to discover unknown path to "+RNS.prettyhexrep(destination_hash)+" on behalf of path request"+interface_str, RNS.LOG_DEBUG)
                pr_entry = { "destination_hash": destination_hash, "timeout": time.time()+Transport.PATH_REQUEST_TIMEOUT, "requesting_interface": attached_interface }
                Transport.discovery_path_requests[destination_hash] = pr_entry

                for interface in Transport.interfaces:
                    if not interface == attached_interface:
                        # Use the previously extracted tag from this path request
                        # on the new path requests as well, to avoid potential loops
                        Transport.request_path(destination_hash, on_interface=interface, tag=tag, recursive=True)

        elif not is_from_local_client and len(Transport.local_client_interfaces) > 0:
            # Forward the path request on all local
            # client interfaces
            RNS.log("Forwarding path request for "+RNS.prettyhexrep(destination_hash)+interface_str+" to local clients", RNS.LOG_DEBUG)
            for interface in Transport.local_client_interfaces:
                Transport.request_path(destination_hash, on_interface=interface)

        else:
            RNS.log("Ignoring path request for "+RNS.prettyhexrep(destination_hash)+interface_str+", no path known", RNS.LOG_DEBUG)

    @staticmethod
    def from_local_client(packet):
        if hasattr(packet.receiving_interface, "parent_interface"):
            return Transport.is_local_client_interface(packet.receiving_interface)
        else:
            return False

    @staticmethod
    def is_local_client_interface(interface):
        if hasattr(interface, "parent_interface"):
            if hasattr(interface.parent_interface, "is_local_shared_instance"):
                return True
            else:
                return False
        else:
            return False

    @staticmethod
    def interface_to_shared_instance(interface):
        if hasattr(interface, "is_connected_to_shared_instance"):
            return True
        else:
            return False

    @staticmethod
    def detach_interfaces():
        detachable_interfaces = []

        for interface in Transport.interfaces:
            # Currently no rules are being applied
            # here, and all interfaces will be sent
            # the detach call on RNS teardown.
            if not interface.detached:
                detachable_interfaces.append(interface)
            else:
                pass
        
        for interface in Transport.local_client_interfaces:
            # Currently no rules are being applied
            # here, and all interfaces will be sent
            # the detach call on RNS teardown.
            if not interface.detached:
                detachable_interfaces.append(interface)
            else:
                pass

        shared_instance_master = None
        local_interfaces = []
        detach_threads = []
        RNS.log("Detaching interfaces", RNS.LOG_DEBUG)
        for interface in detachable_interfaces:
            try:
                if type(interface) == RNS.Interfaces.LocalInterface.LocalServerInterface:
                    shared_instance_master = interface
                elif type(interface) == RNS.Interfaces.LocalInterface.LocalClientInterface:
                    local_interfaces.append(interface)
                else:
                    def detach_job():
                        RNS.log(f"Detaching {interface}", RNS.LOG_EXTREME)
                        interface.detach()
                    dt = threading.Thread(target=detach_job, daemon=False)
                    dt.start()
                    detach_threads.append(dt)

            except Exception as e:
                RNS.log("An error occurred while detaching "+str(interface)+". The contained exception was: "+str(e), RNS.LOG_ERROR)

        for dt in detach_threads:
            dt.join()

        RNS.log("Detaching local clients", RNS.LOG_DEBUG)
        for li in local_interfaces:
            li.detach()

        RNS.log("Detaching shared instance", RNS.LOG_DEBUG)
        if shared_instance_master != None: shared_instance_master.detach()
        BackboneInterface.deregister_listeners()

        RNS.log("All interfaces detached", RNS.LOG_DEBUG)

    @staticmethod
    def shared_connection_disappeared():
        for link in Transport.active_links:
            link.teardown()

        for link in Transport.pending_links:
            link.teardown()

        Transport.announce_table    = {}
        Transport.path_table        = {}
        Transport.reverse_table     = {}
        Transport.link_table        = {}
        Transport.held_announces    = {}
        Transport.tunnels           = {}

    @staticmethod
    def shared_connection_reappeared():
        if Transport.owner.is_connected_to_shared_instance:
            for registered_destination in Transport.destinations:
                if registered_destination.type == RNS.Destination.SINGLE:
                    registered_destination.announce(path_response=True)


    @staticmethod
    def drop_announce_queues():
        for interface in Transport.interfaces:
            if hasattr(interface, "announce_queue") and interface.announce_queue != None:
                na = len(interface.announce_queue)
                if na > 0:
                    if na == 1: na_str = "1 announce"
                    else: na_str = str(na)+" announces"
                    interface.announce_queue = []
                    RNS.log("Dropped "+na_str+" on "+str(interface), RNS.LOG_VERBOSE)

        gc.collect()

    @staticmethod
    def timebase_from_random_blob(random_blob):
        return int.from_bytes(random_blob[5:10], "big")

    @staticmethod
    def timebase_from_random_blobs(random_blobs):
        timebase = 0
        for random_blob in random_blobs:
            emitted = Transport.timebase_from_random_blob(random_blob)
            if emitted > timebase: timebase = emitted

        return timebase

    @staticmethod
    def announce_emitted(packet):
        random_blob = packet.data[RNS.Identity.KEYSIZE//8+RNS.Identity.NAME_HASH_LENGTH//8:RNS.Identity.KEYSIZE//8+RNS.Identity.NAME_HASH_LENGTH//8+10]
        announce_emitted = Transport.timebase_from_random_blob(random_blob)

        return announce_emitted

    @staticmethod
    def save_packet_hashlist():
        if not Transport.owner.is_connected_to_shared_instance:
            if hasattr(Transport, "saving_packet_hashlist"):
                wait_interval = 0.2
                wait_timeout = 5
                wait_start = time.time()
                while Transport.saving_packet_hashlist:
                    time.sleep(wait_interval)
                    if time.time() > wait_start+wait_timeout:
                        RNS.log("Could not save packet hashlist to storage, waiting for previous save operation timed out.", RNS.LOG_ERROR)
                        return False

            try:
                Transport.saving_packet_hashlist = True
                save_start = time.time()

                if not RNS.Reticulum.transport_enabled(): Transport.packet_hashlist = set()
                else: RNS.log("Saving packet hashlist to storage...", RNS.LOG_DEBUG)

                packet_hashlist_path = RNS.Reticulum.storagepath+"/packet_hashlist"
                file = open(packet_hashlist_path, "wb")
                file.write(umsgpack.packb(list(Transport.packet_hashlist.copy())))
                file.close()

                save_time = time.time() - save_start
                if save_time < 1: time_str = str(round(save_time*1000,2))+"ms"
                else: time_str = str(round(save_time,2))+"s"
                RNS.log("Saved packet hashlist in "+time_str, RNS.LOG_DEBUG)

            except Exception as e:
                RNS.log("Could not save packet hashlist to storage, the contained exception was: "+str(e), RNS.LOG_ERROR)

            Transport.saving_packet_hashlist = False
            gc.collect()


    @staticmethod
    def save_path_table():
        if not Transport.owner.is_connected_to_shared_instance:
            if hasattr(Transport, "saving_path_table"):
                wait_interval = 0.2
                wait_timeout = 5
                wait_start = time.time()
                while Transport.saving_path_table:
                    time.sleep(wait_interval)
                    if time.time() > wait_start+wait_timeout:
                        RNS.log("Could not save path table to storage, waiting for previous save operation timed out.", RNS.LOG_ERROR)
                        return False

            try:
                Transport.saving_path_table = True
                save_start = time.time()
                RNS.log("Saving path table to storage...", RNS.LOG_DEBUG)

                serialised_destinations = []
                for destination_hash in Transport.path_table.copy():
                    # Get the destination entry from the destination table
                    de = Transport.path_table[destination_hash]
                    interface_hash = de[IDX_PT_RVCD_IF].get_hash()

                    # Only store destination table entry if the associated
                    # interface is still active
                    interface = Transport.find_interface_from_hash(interface_hash)
                    if interface != None:
                        # Get the destination entry from the destination table
                        de = Transport.path_table[destination_hash]
                        timestamp = de[IDX_PT_TIMESTAMP]
                        received_from = de[IDX_PT_NEXT_HOP]
                        hops = de[IDX_PT_HOPS]
                        expires = de[IDX_PT_EXPIRES]
                        random_blobs = de[IDX_PT_RANDBLOBS]
                        packet_hash = de[IDX_PT_PACKET]

                        serialised_entry = [
                            destination_hash,
                            timestamp,
                            received_from,
                            hops,
                            expires,
                            random_blobs,
                            interface_hash,
                            packet_hash
                        ]

                        serialised_destinations.append(serialised_entry)

                        # TODO: Reevaluate whether there is any cases where this is needed
                        # Transport.cache(de[IDX_PT_PACKET], force_cache=True)

                path_table_path = RNS.Reticulum.storagepath+"/destination_table"
                file = open(path_table_path, "wb")
                file.write(umsgpack.packb(serialised_destinations))
                file.close()

                save_time = time.time() - save_start
                if save_time < 1: time_str = str(round(save_time*1000,2))+"ms"
                else: time_str = str(round(save_time,2))+"s"
                RNS.log("Saved "+str(len(serialised_destinations))+" path table entries in "+time_str, RNS.LOG_DEBUG)

            except Exception as e:
                RNS.log("Could not save path table to storage, the contained exception was: "+str(e), RNS.LOG_ERROR)
                RNS.trace_exception(e)

            Transport.saving_path_table = False
            gc.collect()


    @staticmethod
    def save_tunnel_table():
        if not Transport.owner.is_connected_to_shared_instance:
            if hasattr(Transport, "saving_tunnel_table"):
                wait_interval = 0.2
                wait_timeout = 5
                wait_start = time.time()
                while Transport.saving_tunnel_table:
                    time.sleep(wait_interval)
                    if time.time() > wait_start+wait_timeout:
                        RNS.log("Could not save tunnel table to storage, waiting for previous save operation timed out.", RNS.LOG_ERROR)
                        return False

            try:
                Transport.saving_tunnel_table = True
                save_start = time.time()
                RNS.log("Saving tunnel table to storage...", RNS.LOG_DEBUG)

                serialised_tunnels = []
                for tunnel_id in Transport.tunnels.copy():
                    te = Transport.tunnels[tunnel_id]
                    interface = te[1]
                    tunnel_paths = te[2].copy()
                    expires = te[3]

                    if interface != None: interface_hash = interface.get_hash()
                    else: interface_hash = None

                    serialised_paths = []
                    for destination_hash in tunnel_paths:
                        de = tunnel_paths[destination_hash]

                        timestamp = de[0]
                        received_from = de[1]
                        hops = de[2]
                        expires = de[3]
                        random_blobs = de[4][-Transport.PERSIST_RANDOM_BLOBS:]
                        packet_hash = de[6]

                        serialised_entry = [
                            destination_hash,
                            timestamp,
                            received_from,
                            hops,
                            expires,
                            random_blobs,
                            interface_hash,
                            packet_hash
                        ]

                        serialised_paths.append(serialised_entry)

                        # TODO: Reevaluate whether there are any cases where this is needed
                        # Transport.cache(de[6], force_cache=True)

                    serialised_tunnel = [tunnel_id, interface_hash, serialised_paths, expires]
                    serialised_tunnels.append(serialised_tunnel)

                tunnels_path = RNS.Reticulum.storagepath+"/tunnels"
                file = open(tunnels_path, "wb")
                file.write(umsgpack.packb(serialised_tunnels))
                file.close()

                save_time = time.time() - save_start
                if save_time < 1: time_str = str(round(save_time*1000,2))+"ms"
                else: time_str = str(round(save_time,2))+"s"
                RNS.log("Saved "+str(len(serialised_tunnels))+" tunnel table entries in "+time_str, RNS.LOG_DEBUG)
            
            except Exception as e:
                RNS.log("Could not save tunnel table to storage, the contained exception was: "+str(e), RNS.LOG_ERROR)

            Transport.saving_tunnel_table = False
            gc.collect()

    @staticmethod
    def persist_data():
        Transport.save_packet_hashlist()
        Transport.save_path_table()
        Transport.save_tunnel_table()

    @staticmethod
    def exit_handler():
        if not Transport.owner.is_connected_to_shared_instance:
            Transport.persist_data()


# Table entry indices

# Transport.path_table entry indices
IDX_PT_TIMESTAMP = 0
IDX_PT_NEXT_HOP  = 1
IDX_PT_HOPS      = 2
IDX_PT_EXPIRES   = 3
IDX_PT_RANDBLOBS = 4
IDX_PT_RVCD_IF   = 5
IDX_PT_PACKET    = 6

# Transport.reverse_table entry indices
IDX_RT_RCVD_IF   = 0
IDX_RT_OUTB_IF   = 1
IDX_RT_TIMESTAMP = 2

# Transport.announce_table entry indices
IDX_AT_TIMESTAMP = 0
IDX_AT_RTRNS_TMO = 1
IDX_AT_RETRIES   = 2
IDX_AT_RCVD_IF   = 3
IDX_AT_HOPS      = 4
IDX_AT_PACKET    = 5
IDX_AT_LCL_RBRD  = 6
IDX_AT_BLCK_RBRD = 7
IDX_AT_ATTCHD_IF = 8

# Transport.link_table entry indices
IDX_LT_TIMESTAMP = 0
IDX_LT_NH_TRID   = 1
IDX_LT_NH_IF     = 2
IDX_LT_REM_HOPS  = 3
IDX_LT_RCVD_IF   = 4
IDX_LT_HOPS      = 5
IDX_LT_DSTHASH   = 6
IDX_LT_VALIDATED = 7
IDX_LT_PROOF_TMO = 8

# Transport.tunnels entry indices
IDX_TT_TUNNEL_ID = 0
IDX_TT_IF        = 1
IDX_TT_PATHS     = 2
IDX_TT_EXPIRES   = 3