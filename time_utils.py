import time
from typing import List

import numpy as np
from netaddr import IPAddress


class Counters:

    # length of Counters attributes
    len = 12

    # known public IPs
    ipset = set(['89.46.74.106'])

    def __init__(self) -> None:
        self.packet_count = 0
        self.ip_external = set()
        self.ip_internal = set()
        self.port_high = 0
        self.port_low = 0
        self.tcp_syn = 0
        self.tcp_fin = 0
        self.tcp_rst = 0

        # gen 2
        self.volume_download = 0
        self.volume_upload = 0
        self.volume_internal = 0  # internal communication between two private ips
        self.less_64b = 0

        # gen 3
        # distance of contacted IPs

        super().__init__()

    def __getitem__(self, item):
        return self.unroll()

    def __str__(self) -> str:
        return f"Packet count: {self.packet_count}, <64: {self.less_64b}, IP_ext: {self.ip_external}, " \
               f"IP_int:{self.ip_internal}, Port H: {self.port_high}, Port L: {self.port_low}," \
               f"SYN/FIN/RST: {self.tcp_syn}/{self.tcp_fin}/{self.tcp_rst}, Volume Down/up/internal:" \
               f"{self.volume_download}/{self.volume_upload}/{self.volume_internal}"

    def inc_stats(self, packet: dict):
        """
        Increments stats of the current Counters
        :param packet: packet to process into the increment
        """
        ip_origin = IPAddress(packet['origin']['ip'])
        ip_destination = IPAddress(packet['destination']['ip'])

        if ip_origin.is_reserved() or ip_destination.is_reserved():
            return

        # infer direction
        # if both are private then is a private connection
        # if just one is private or known the we infer the direction
        internal_ips = ip_origin.is_private() + ip_destination.is_private() + (str(ip_origin) in Counters.ipset) + (
                ip_destination in Counters.ipset)

        if internal_ips == 2:
            # communication between two internal addresses
            self.volume_internal = self.volume_internal + packet['length']
            self.ip_internal.add(ip_origin)
            self.ip_internal.add(ip_destination)

        elif internal_ips == 1:
            # comunication with and outside entity

            # infer direction
            if ip_origin.is_private() or (ip_origin in Counters.ipset):
                # it's an upload
                self.volume_upload = self.volume_upload + packet['length']
                self.ip_external.add(ip_destination)
                self.ip_internal.add(ip_origin)

            elif ip_destination.is_private() or (str(ip_destination) in Counters.ipset):
                # it's a download
                self.volume_download = self.volume_download + packet['length']
                self.ip_internal.add(ip_destination)
                self.ip_external.add(ip_origin)

            else:
                raise RuntimeError(
                    f"Internal IP is 1 but can't figure out which one: {str(ip_origin)} - {str(ip_destination)} {ip_origin.is_private()} {ip_destination.is_private()}")

            if packet['protocol'] != "ICMP":
                if packet['destination']['port'] > 1024:
                    self.port_high = self.port_high + 1
                else:
                    self.port_low = self.port_low + 1

        else:
            raise RuntimeError(f"Two public IPs and none is known. {str(ip_origin)} - {str(ip_destination)}")

        if packet['protocol'] == "TCP":
            self.tcp_syn = self.tcp_syn + packet['tcp_flags']['SYN']
            self.tcp_fin = self.tcp_fin + packet['tcp_flags']['FIN']
            self.tcp_rst = self.tcp_rst + packet['tcp_flags']['RST']

        self.packet_count = self.packet_count + 1

        # in bytes
        if int(packet['length']) <= 64:
            self.less_64b = self.less_64b + 1

    def unroll(self):
        """
        Unroll Counter attributes
        :return:
        """
        return [self.packet_count,
                len(self.ip_external),
                len(self.ip_internal),
                self.port_high,
                self.port_low,
                self.tcp_syn,
                self.tcp_fin,
                self.tcp_rst,
                self.volume_download,
                self.volume_upload,
                self.volume_internal,
                self.less_64b]


class Timebar:
    def __init__(self, slot_count: int = 86400) -> None:
        """
        Creates a Timebar array
        :param slot_count: number of Timebar slices
        """
        assert slot_count >= 1, "Minimum slot resolution is 1"

        self.slots: List[Counters] = []

        # Slices initalization
        for _ in range(slot_count):
            self.slots.append(None)

        self.ref_epoch: int = 0

        super().__init__()

    def __getitem__(self, item):
        return self.slots[item]

    def __setitem__(self, key, value):
        self.slots[key] = value

    def is_empty(self):
        return self.slots.count(None) == len(self.slots)

    def hint(self, hint: int):
        """
        Updates the hint of the date of this Timebar
        :param hint: epoch time of the int
        """
        self.ref_epoch = hint

    def is_weekend(self):
        """
        Checks if the Timebar is on a Weekend
        :return: true for weekend, false for weekday
        """
        t = time.gmtime(self.ref_epoch)  # type: time.struct_time

        # time returns [0,6], where 0 is monday
        return t.tm_wday >= 5

    def get_weekday(self):
        """
        Returns [0,6], where 0 is monday
        :return: weekday number
        """
        t = time.gmtime(self.ref_epoch)  # type: time.struct_time
        return t.tm_wday

    def unroll_to_np(self):
        """
        Unrolls the Timebar into a list of arrays representing each Counter slot
        :return: unrolled timebar into a list of Counters
        """
        timeline_unroll = []

        for counter in self.slots:
            if counter is None:
                timeline_unroll.append([0] * Counters.len)
            else:
                timeline_unroll.append(counter.unroll())

        return np.array(timeline_unroll)
