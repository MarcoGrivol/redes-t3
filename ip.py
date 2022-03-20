from posixpath import split
from socket import IPPROTO_ICMP, IPPROTO_TCP
import struct
from tabnanny import check
from grader.tcputils import calc_checksum, str2addr
from iputils import *

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.id = 0

    def _datagrama(
        self, segment, src_addr, dst_addr,
        version_ihl    = 0x45,
        dscp_ecn       = 0,
        flags_fragment = 0,
        ttl            = 64,
        protocol       = IPPROTO_TCP,
        checksum       = 0
    ):
        total_length = 20 + len(segment)
        identification = self.id
        datagrama = struct.pack(
            '!BBHHHBBH',
            version_ihl,
            dscp_ecn,
            total_length,
            identification,
            flags_fragment,
            ttl,
            protocol,
            checksum
        )
        datagrama += src_addr + dst_addr
        checksum = calc_checksum(datagrama)
        datagrama = struct.pack(
            '!BBHHHBBH',
            version_ihl,
            dscp_ecn,
            total_length,
            identification,
            flags_fragment,
            ttl,
            protocol,
            checksum
        )
        datagrama += src_addr + dst_addr + segment
        return datagrama

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            ttl -= 1
            if ttl > 0:
                next_hop = self._next_hop(dst_addr)
                src_addr = str2addr(src_addr)
                dst_addr = str2addr(dst_addr)
                datagrama = self._datagrama(payload, src_addr, dst_addr, ttl=ttl)
            else:
                # TTL == 0
                next_hop = self._next_hop(src_addr)
                dst_addr = str2addr(src_addr)
                src_addr = str2addr(self.meu_endereco)
                ttl = 64
                _type = 11
                code = 0
                payload = struct.pack('!BBHI', _type, code, 0, 0) + datagrama[:28]
                payload = struct.pack(
                    '!BBHI', _type, code, calc_checksum(payload), 0
                ) + datagrama[:28]
                datagrama = self._datagrama(
                    payload, src_addr, dst_addr, ttl=ttl, protocol=IPPROTO_ICMP
                )
            self.enlace.enviar(datagrama, next_hop)


    def _next_hop(self, dest_addr):
        addr, = struct.unpack('!I', str2addr(dest_addr))
        aux = (None, 33) # next_hop, nbits
        for cidr, nexth, nbits in self.tabela:
            if (addr >> nbits << nbits) == cidr and nbits < aux[1]:
                aux = (nexth, nbits)
        return aux[0]

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        self.tabela = []
        for cidr, nh in tabela:
            cidr, nbits = cidr.split('/')
            nbits = 32 - int(nbits)
            cidr, = struct.unpack('!I', str2addr(cidr))
            self.tabela.append((cidr, nh, nbits))

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        src_addr = str2addr(self.meu_endereco)
        dst_addr = str2addr(dest_addr)
        datagrama = self._datagrama(segmento, src_addr, dst_addr)
        self.enlace.enviar(datagrama, next_hop)
        self.id += 1