####################################################
# LSrouter.py
# Name: Phạm Hà Nguyên An
# HUID: 24020375
#####################################################

import heapq
import json

from packet import Packet
from router import Router


class LSrouter(Router):
    """Link-state routing with sequenced flooding and Dijkstra's algorithm.

    LSPs are flooded whenever a link state changes, and refreshed once per
    heartbeat even when nothing changed.  A heartbeat simply re-sends the
    current LSP (peers already holding that sequence number ignore it), while
    every ``REFRESH_EVERY`` heartbeats the sequence number is bumped so that
    every router accepts and re-floods the LSP; this lets a peer that missed
    an update recover.  When a new adjacency comes up, the router also sends
    the LSPs it already knows to the new neighbor (database exchange), so a
    router that was just connected/partitioned can build the full topology
    without waiting for every originator to re-originate.
    """

    # Heartbeat ticks between two re-originations (sequence-number bumps) of
    # our own LSP.
    REFRESH_EVERY = 5

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)  # Initialize base class - DO NOT REMOVE
        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        self.heartbeats = 0  # heartbeat ticks since startup
        # port -> (neighbor address, outgoing link cost)
        self.neighbors = {}
        self.sequence = 0
        # origin -> (sequence number, {neighbor address: outgoing cost})
        self.link_states = {addr: (self.sequence, {})}
        # destination -> (distance, outgoing port); the local address has no port
        self.routes = {addr: (0, None)}

    def _recompute(self):
        graph = {origin: links for origin, (_, links) in self.link_states.items()}
        distances = {self.addr: 0}
        first_hop = {self.addr: None}
        pending = [(0, self.addr)]

        while pending:
            distance, node = heapq.heappop(pending)
            if distance != distances.get(node):
                continue
            for neighbor, cost in graph.get(node, {}).items():
                candidate = distance + cost
                if candidate < distances.get(neighbor, float("inf")):
                    distances[neighbor] = candidate
                    if node == self.addr:
                        first_hop[neighbor] = self._port_for_neighbor(neighbor)
                    else:
                        first_hop[neighbor] = first_hop[node]
                    heapq.heappush(pending, (candidate, neighbor))

        routes = {destination: (distance, first_hop[destination])
                  for destination, distance in distances.items()}
        changed = routes != self.routes
        self.routes = routes
        return changed

    def _port_for_neighbor(self, neighbor):
        for port, (address, _) in self.neighbors.items():
            if address == neighbor:
                return port
        return None

    def _send_lsp(self, port, origin, sequence, links):
        neighbor = self.neighbors[port][0]
        content = json.dumps({"origin": origin, "sequence": sequence,
                              "links": links})
        self.send(port, Packet(Packet.ROUTING, origin, neighbor, content))

    def _broadcast(self, origin, sequence, links, exclude_port=None):
        for port in list(self.neighbors):
            if port == exclude_port:
                continue
            self._send_lsp(port, origin, sequence, links)

    def _sync_database(self, port):
        """Send the LSPs we already know to a newly attached neighbor.

        Heartbeats reuse the current sequence number, so a router that already
        holds that sequence number ignores them and does not flood them onward.
        Without this exchange a newly connected router could stay unaware of
        non-adjacent routers' link states until those routers change their
        links.
        """
        for origin, (sequence, links) in self.link_states.items():
            if origin != self.addr:
                self._send_lsp(port, origin, sequence, links)

    def _publish(self):
        self.sequence += 1
        links = {entry[0]: entry[1] for entry in self.neighbors.values()}
        self.link_states[self.addr] = (self.sequence, links)
        self._recompute()
        self._broadcast(self.addr, self.sequence, links)

    def handle_packet(self, port, packet):
        if packet.is_traceroute:
            route = self.routes.get(packet.dst_addr)
            if route is not None and route[1] is not None:
                self.send(route[1], packet)
            return

        if not packet.is_routing or port not in self.neighbors:
            return
        try:
            message = json.loads(packet.content)
            origin = message["origin"]
            sequence = message["sequence"]
            links = message["links"]
            if (not isinstance(origin, str) or isinstance(sequence, bool)
                    or not isinstance(sequence, int) or sequence < 0
                    or not isinstance(links, dict)):
                return
            clean_links = {}
            for neighbor, cost in links.items():
                if (not isinstance(neighbor, str) or isinstance(cost, bool)
                        or not isinstance(cost, (int, float)) or cost < 0):
                    return
                clean_links[neighbor] = cost
        except (TypeError, ValueError, KeyError, json.JSONDecodeError):
            return

        previous = self.link_states.get(origin)
        if previous is not None and sequence <= previous[0]:
            return
        self.link_states[origin] = (sequence, clean_links)
        self._recompute()
        # Re-flood a fresh advertisement so every reachable router learns it.
        self._broadcast(origin, sequence, clean_links, exclude_port=port)

    def handle_new_link(self, port, endpoint, cost):
        self.neighbors[port] = (endpoint, cost)
        self._sync_database(port)
        self._publish()

    def handle_remove_link(self, port):
        self.neighbors.pop(port, None)
        self._publish()

    def handle_time(self, time_ms):
        if time_ms - self.last_time < self.heartbeat_time:
            return
        self.last_time = time_ms
        self.heartbeats += 1
        if self.heartbeats % self.REFRESH_EVERY == 0:
            # Re-originate so that peers recover any update they missed.
            self._publish()
        else:
            # Cheap refresh: peers already hold this sequence number.
            self._broadcast(self.addr, self.sequence,
                            self.link_states[self.addr][1])

    def __repr__(self):
        return f"LSrouter(addr={self.addr}, routes={self.routes})"
