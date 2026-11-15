####################################################
# DVrouter.py
# Name: Nguyễn Đỗ Đức Anh
# HUID: 24020383
#####################################################

import json

from packet import Packet
from router import Router


class DVrouter(Router):
    """Distance-vector routing with poisoned reverse and bounded infinity."""

    INFINITY = 16

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)  # Initialize base class - DO NOT REMOVE
        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        # port -> (neighbor address, outgoing link cost)
        self.neighbors = {}
        # port -> most recently received distance vector from that neighbor
        self.neighbor_vectors = {}
        # destination -> (distance, outgoing port); the local address has no port
        self.routes = {addr: (0, None)}

    def _recompute(self):
        routes = {self.addr: (0, None)}
        for port, (neighbor, cost) in self.neighbors.items():
            # A directly connected client or router is always a viable route.
            current = routes.get(neighbor)
            if current is None or cost < current[0]:
                routes[neighbor] = (cost, port)

            vector = self.neighbor_vectors.get(port, {})
            for destination, distance in vector.items():
                if destination == self.addr:
                    continue
                try:
                    distance = float(distance)
                except (TypeError, ValueError):
                    continue
                candidate = min(self.INFINITY, cost + distance)
                if candidate >= self.INFINITY:
                    continue
                current = routes.get(destination)
                if current is None or candidate < current[0]:
                    routes[destination] = (candidate, port)
        changed = routes != self.routes
        self.routes = routes
        return changed

    def _broadcast(self):
        for port in list(self.neighbors):
            vector = {}
            for destination, (distance, next_port) in self.routes.items():
                if destination == self.addr:
                    vector[destination] = 0
                elif next_port == port:
                    # Poison reverse prevents a neighbor from routing back to us.
                    vector[destination] = self.INFINITY
                else:
                    vector[destination] = min(self.INFINITY, distance)
            packet = Packet(Packet.ROUTING, self.addr, self.neighbors[port][0],
                            json.dumps(vector))
            self.send(port, packet)

    def handle_packet(self, port, packet):
        if packet.is_traceroute:
            route = self.routes.get(packet.dst_addr)
            if route is not None and route[1] is not None:
                self.send(route[1], packet)
            return

        if not packet.is_routing or port not in self.neighbors:
            return
        # Only accept routing information from the neighbor on this port.
        if packet.src_addr != self.neighbors[port][0]:
            return
        try:
            vector = json.loads(packet.content)
            if not isinstance(vector, dict):
                return
            # Ignore malformed values while retaining only string-like addresses
            # and finite nonnegative distances.
            clean = {}
            for destination, distance in vector.items():
                if not isinstance(destination, str):
                    continue
                if isinstance(distance, bool) or not isinstance(distance, (int, float)):
                    continue
                if distance < 0:
                    continue
                clean[destination] = min(self.INFINITY, distance)
        except (TypeError, ValueError, json.JSONDecodeError):
            return

        if self.neighbor_vectors.get(port) == clean:
            return
        self.neighbor_vectors[port] = clean
        if self._recompute():
            self._broadcast()

    def handle_new_link(self, port, endpoint, cost):
        self.neighbors[port] = (endpoint, cost)
        self.neighbor_vectors.pop(port, None)
        self._recompute()
        self._broadcast()

    def handle_remove_link(self, port):
        self.neighbors.pop(port, None)
        self.neighbor_vectors.pop(port, None)
        self._recompute()
        self._broadcast()

    def handle_time(self, time_ms):
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self._broadcast()

    def __repr__(self):
        return f"DVrouter(addr={self.addr}, routes={self.routes})"
