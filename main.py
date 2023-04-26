# This is a sample Python script.
import argparse
import ipaddress
import logging
import socket
import threading
import ssl
import re
from signal import signal, SIGINT
from scapy.all import *
from sys import platform
from tqdm import tqdm
from prettytable import PrettyTable, ALL
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


#clase equipo para almacenar los equipos que se encuentren
class Equipo:
    def __init__(self, ip):
        self._ip = ip
        self._up = False
        self.nombre = ""
        self.mac = ""
        self.ttl = 0
        self.puertos = []
        self.firewalled = False
        self.idOS = {"ttl":"", "OS":""} #Para guardar la Indentificacion del OS cuando lo hacemos por icmp

    def __hash__(self):
        return hash(self.ip)
    def __eq__(self, other):
        if isinstance(other, Equipo):
            return self.ip == other.ip
        return NotImplemented
    def add_port(self, port):
        self.puertos.append(port)
    def setUp(self):
        self._up = True
    def setDown(self):
        self._up = False
    def getUP(self):
        return self._up

    @property
    def ip(self):
        return self._ip
    @ip.setter
    def ip(self, value):
        if not isinstance(value, ipaddress):
            raise TypeError("La ip debe ser un objeto de ipaddress")
        self._ip = value


#clases tipo puerto para almacenar los puertos abiertos en un equipo
class Puerto:
    def __init__(self, numero, tipo):
        self._numero = numero
        self._tipo = tipo #tcp,udp,sctp
        self._estado = "" #open,closed,filtered,open/filtered
        self._banner = ""
        self.ttl = "" #para guardar el ttl del host que responde al paquete
        self.mac = "" #para guardar la mac del host que responde al paquete
        self.idOS = {} #Para guardar la Indentificacion del OS cuando hay un puerto abierto
    def __hash__(self):
        return hash(self._numero)
    def __eq__(self, other):
        if isinstance(other, Puerto):
            return self._numero == other._numero
        return NotImplemented

    def bannergrabbing(self, target, tout):
        resp = ""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((str(target), int(self.numero)))
            s.settimeout(tout)

            if self.numero == 80:
                s.sendall(b"GET / HTTP/1.1\r\nHost: " + str(target).encode('utf-8') + b"\r\n\r\n")
                resp = s.recv(1024).decode('utf-8')
                s.close()
            elif self.numero == 443:
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ssl._create_default_https_context = ssl._create_unverified_context
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                s = context.wrap_socket(s, server_hostname=str(target))
                s.connect((str(target), int(self.numero)))
                s.sendall(b"GET / HTTP/1.1\r\nHost: " + str(target).encode('utf-8') + b"\r\n\r\n")
                resp = s.recv(1024).decode('utf-8')
                s.close()
            elif self.numero == 21:
                resp = s.recv(1024)
                s.sendall(b'HELP\r\n')
                resp += s.recv(1024)
                s.send(b'USER ANONYMOUS\r\n')
                s.recv(1024)
                s.send(b'PASS a@b\r\n')
                s.recv(1024)
                s.send(b'STAT\r\n')
                resp += s.recv(1024)
                s.sendall(b'QUIT\r\n')
                s.close()
            elif self.numero == 445:
                # NetBioS Session Service + Negotiate Protocol Request
                nbss = (b"\x00\x00\x00\xa4\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x08\x01\x40"
                        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x06"
                        b"\x00\x00\x01\x00\x00\x81\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f"
                        b"\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02"
                        b"\x4d\x49\x43\x52\x4f\x53\x4f\x46\x54\x20\x4e\x45\x54\x57\x4f\x52"
                        b"\x4b\x53\x20\x31\x2e\x30\x33\x00\x02\x4d\x49\x43\x52\x4f\x53\x4f"
                        b"\x46\x54\x20\x4e\x45\x54\x57\x4f\x52\x4b\x53\x20\x33\x2e\x30\x00"
                        b"\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x4c\x4d\x31\x2e"
                        b"\x32\x58\x30\x30\x32\x00\x02\x53\x61\x6d\x62\x61\x00\x02\x4e\x54"
                        b"\x20\x4c\x41\x4e\x4d\x41\x4e\x20\x31\x2e\x30\x00\x02\x4e\x54\x20"
                        b"\x4c\x4d\x20\x30\x2e\x31\x32\x00")
                s.send(nbss)
                resp = s.recv(1024).decode('utf-8', 'ignore')
                resp = re.sub('[^ -~]+', '', resp)
                s.close()
            elif self.numero == 111:
                rpcbind_packet = b"\x80\x00\x00\x28\x0b\x7a\x05\x41\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                s.sendall(rpcbind_packet)
                resp = s.recv(1024).decode('utf-8', 'ignore')
                resp = re.sub('[^ -~]+', '', resp)

                s.close()
            elif self.numero == 389:
                ldap_packet = b"\x30\x84\x00\x00\x00\x2d\x02\x01\x07\x63\x84\x00\x00\x00\x24\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x64\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x43\x6c\x61\x73\x73\x30\x84\x00\x00\x00\x00"
                s.sendall(ldap_packet)
                resp = s.recv(1024).decode('utf-8', 'ignore')
                resp = re.sub('[^ -~]+', '', resp)
                s.close()
            elif self.numero == 110:
                s.sendall(b'USER anonymous\r\n')
                resp = s.recv(1024).decode('utf-8', 'ignore')
                s.sendall(b'QUIT\r\n')
                s.close()
            elif self.numero == 143:
                s.sendall(b'* OK IMAP4 ready\r\n')
                resp = s.recv(1024).decode('utf-8', 'ignore')
                s.sendall(b'* BYE IMAP4 server terminating connection\r\n')
                resp += s.recv(1024).decode('utf-8', 'ignore')
                s.close()
            elif self.numero == 25:
                resp = s.recv(1024).decode('utf-8', 'ignore')
                s.sendall(b'EHLO test\r\n')
                resp += s.recv(1024).decode('utf-8', 'ignore')
                s.close()
            elif self.numero == 22:
                resp = s.recv(1024).decode('utf-8', 'ignore')
                resp = re.sub('[^ -~]+', '', resp)
                s.close()
            else:
                resp = s.recv(1024).decode('utf-8', 'ignore')
                resp = re.sub('[^ -~]+', '', resp)
                s.close()

        except socket.error as err:
            resp = "Error en el bannergrabbing"
            #pass
        self._banner = resp

    @property
    def numero(self):
        return self._numero
    @numero.setter
    def numero(self, value):
        if not isinstance(value, int):
            raise TypeError("El puerto debe ser un entero")
        if value <= 0 or value > 65535:
            raise TypeError("El valor del puerto debe estar en el rango 1-65535")
        self._numero = value

    @property
    def tipo(self):
        return self._tipo
    @tipo.setter
    def tipo(self, value):
        if not isinstance(value, str):
            raise TypeError("El tipo debe ser un string")
        if value not in ["tcp", "udp", "stcp"]:
            raise TypeError("el valor debe ser tcp, udp o stcp")
        self._tipo = value

    @property
    def estado(self):
        return self._estado
    @estado.setter
    def estado(self, value):
        if not isinstance(value, str):
            raise TypeError("El tido debe ser un string")
        if value not in ["open", "closed", "filtered", "open/filtered"]:
            raise TypeError("el valor debe ser open, closed o filtered")
        self._estado = value

    @property
    def banner(self):
        return self._banner
    @banner.setter
    def banner(self, value):
        if not isinstance(value, str):
            raise TypeError("El tipo debe ser un string")
        self._banner = value


def get_interfaces():
    interfaces = []
    if 'win' in platform:
        for inf in (IFACES.data).values():
            interfaces.append(inf.name)
    elif 'linux' in platform:
        interfaces = get_if_list()
    else:
        print("plataforma no soportada. Saliendo...")
        exit(1)
    return (interfaces)


def get_work_interface():
    interfaz = ""
    if 'win' in platform:
        interfaz = get_working_if().name
    elif 'linux' in platform:
        interfaz = get_working_if()
    else:
        print("plataforma no soportada. Saliendo...")
        exit(1)
    return (interfaz)


def get_default_IP():
    sip = get_if_addr(get_work_interface())
    return sip

def get_default_range():
    default_ip = get_if_addr(get_work_interface()) + "/24"
    rango = ipaddress.ip_network(default_ip, strict=False)
    return rango.exploded


def set_source(ip):
    try:
        sip = ipaddress.ip_address(ip)
        return sip
    except ValueError:
        print("Ups, algo fue mal con la IP Origen, revisa las IP proporcionada: {0}".format(ValueError))
        exit(1)

def set_targets(rango):
    """
    función para crear una lista de obtjetos tipo 'equipos'.
    recibe la entrada del usuario que puede ser:
    - rango CIDR
    - una IP
    - lista de equipos separados por coma
    - ...
    Primero comprueba que el formato es el correcto, tres posibles entradas
        - 192.168.1.2
        - 192.168.1.2/24
        - 192.168.1.2,192.168.2.2/24
    devuelve un listado de objetos tipo 'equipos' con las IP's de los objetivos
    """
    targets = set()
    try:
        for i in rango.split(','):
            if '/32' in i or not '/' in i:
                targets.add(Equipo(ipaddress.ip_address(i.split('/')[0])))
            else:
                red = ipaddress.ip_network(i, strict=False)
                for ip in red:
                    targets.add(Equipo(ip))
                targets.remove(Equipo(red.network_address))
                targets.remove(Equipo(red.broadcast_address))
    except ValueError:
        print("Ups, algo fue mal con los rangos de entrada, revisa las IP's proporcionadas: {0}".format(ValueError))
        exit(1)
    return targets


def set_ports(rango_puertos):
    """
    función para crear una lista de obtjetos tipo 'Puertos'.
    recibe la entrada del usuario que puede ser:
    - '-' indicando todos los puertos
    - rango de puertos inicial-final
    - lista de puertos separados por coma
    - ...
    Primero comprueba que el formato es el correcto, tres posibles entradas
        - 22,80,50-60
        - 443
        - -
    devuelve un listado de objetos tipo 'puertos' con las puertos objetivos
    """
    raw_ports = set()
    try:
        for i in rango_puertos.split(','):
            if '-' in i:
                puerto_inicial = 1 if i.split('-')[0] == '' else i.split('-')[0]
                puerto_final = 65535 if i.split('-')[1] == '' else i.split('-')[1]
                for puerto in range(int(puerto_inicial),int(puerto_final)+1):
                    raw_ports.add(puerto)
            else:
                raw_ports.add(int(i))
    except:
        print("Ups, algo fue mal con los puertos. Revisalos e intentalo de nuevo...")
    return raw_ports


def handler(signal, frame):
    print("[!] Ctrl+c pulsado, saliendo del script")
    exit(1)


# Definimos una serie de funciones para los escaneos
def arpping(ifaz, sip, target, tout):
    '''
    # Se emiten los paquetes a broadcast a traves de la interfaz indicada
    #print(
    #    'Se emiten paquetes ARP a traves de la interfaz {0} preguntando su dominio de broadcast por las IP solicitadas '
    #    .format(ifaz))
    #for target in targets:
    #print("se escanea el target:{0}".format(str(target.ip)))
    '''
    try:
        ans = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(target.ip)), iface=ifaz, timeout=tout, verbose=0)
        if ans is not None:
            target.setUp()
            target.mac = ans.hwsrc
        return target
    except Exception as e:
        print("Ocurrió un error al enviar el paquete ARPping: %s" % e)


def icmpping(ifaz, sip, target, tout):
    try:
        response = srp1(Ether()/IP(src=str(sip), dst=str(target.ip))/ICMP(), iface=ifaz, timeout=tout, verbose=0)
        if response is not None:
            #print(f"[+] el equipo {str(target.ip)} esta arriba")
            target.setUp()
            target.ttl = response.ttl
            target.mac = response.src
            target.idOS = identificacionOS(response)
        return target
    except Exception as e:
        print("Ocurrió un error al enviar el paquete ICMPping a {0}: {1}".format(str(target.ip), e))


def tcpping(ifaz, sip, target, dst_port, tout):
    '''
    TCP Syn Scan (-sS).
    1. Syn->
    2. <-Syn+Ack
    3. Rst->
    Verificado con wireshark y nmap
    :param target:
    :param dst_port:
    :param tout:
    :return:
    '''
    try:
        src_port = RandShort()._fix()
        seq_num = random.randint(1, 1000000)
        tcp_options = [('MSS', 1460), ('SAckOK', ''), ('NOP', None), ('Timestamp', (123, 0)), ('WScale', 7)]
        response = srp1(
            Ether() / IP(src=str(sip), dst=str(target.ip)) / TCP(sport=src_port, dport=dst_port, flags="S", seq=seq_num, options=tcp_options),
            iface=ifaz, timeout=tout, verbose=0)
        if response is not None:
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                send_rst = srp1(Ether() / IP(src=str(sip), dst=str(target.ip)) / TCP(sport=src_port, dport=int(dst_port), flags="R", seq=seq_num + 2, ack=response.getlayer(TCP).seq + len(response.getlayer(TCP).payload) + 1), iface=ifaz, timeout=tout, verbose=0)
                target.setUp()
                new_port=Puerto(dst_port, 'tcp')
                new_port.estado='open'
                new_port.bannergrabbing(str(target.ip),tout)
                new_port.ttl = response.ttl
                new_port.mac = response.src
                new_port.idOS = identificacionOS(response)
                target.add_port(new_port)
                target.ttl = response.ttl
                target.mac = response.src
            else:
                # si esta cerrado se recibe un Rst=1, Ack=1 (0x14), win=0, len=0
                pass
        return target
    except Exception as e:
        print("Ocurrió un error al enviar el paquete TCPping a {0}: {1}".format(str(target.ip), e))


def udpping(ifaz, sip, target, dst_port, tout):
    try:
        src_port = RandShort()._fix()
        response = srp1(Ether()/IP(src=str(sip), dst=str(target.ip)) / UDP(sport=src_port, dport=dst_port), iface=ifaz, timeout=tout, verbose=0)

        # Analiza la respuesta
        if response is None:
            new_port = Puerto(dst_port, 'udp')
            new_port.estado = 'open/filtered'
            target.add_port(new_port)
            target.setUp()
        elif response.haslayer(UDP):
            new_port = Puerto(dst_port, 'udp')
            new_port.estado = 'open'
            new_port.ttl = response.ttl
            new_port.mac = response.src
            new_port.idOS = identificacionOS(response)
            target.add_port(new_port)
            target.setUp()
            target.ttl = response.ttl
            target.mac = response.src
        elif response.haslayer(ICMP):
            if (int(response.getlayer(ICMP).type) == 3) and int(response.getlayer(ICMP).code) == 3:
                # puerto inalcanzable
                pass
            elif (int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) in [1, 2, 9, 10, 13]):
                new_port = Puerto(dst_port, 'udp')
                new_port.estado = 'filtered'
                new_port.ttl = response.ttl
                new_port.mac = response.src
                new_port.idOS = identificacionOS(response)
                target.setUp()
                target.add_port(new_port)
                target.ttl = response.ttl
                target.mac = response.src
                if int(response.getlayer(ICMP).code) in [9, 10, 13]:
                    # The destination network is administratively prohibited,
                    # The destination host is administratively prohibited,
                    # Communication administratively prohibited
                    target.firewalled = True
    except Exception as e:
        print("Ocurrió un error al enviar el paquete UDPping a {0}: {1}".format(str(target.ip), e))


def tcpconnectscan(ifaz, sip, target, dst_port, tout):
    '''
    TCP Syn Scan (-sS).
    1. Syn->
    2. <-Syn+Ack
    3. Ack->
    4. Rst->
    Tenemos el problema de que el SSOO manda el Rst antes de que nosotros mandemos el Ack y luego el Rst.
    Para determinar el estado del puerto es transparente
    :param target:
    :param dst_port:
    :param tout:
    :return:
    '''
    try:
        src_port = RandShort()._fix()
        seq_num = random.randint(1, 1000000)
        tcp_options = [('MSS', 1460), ('SAckOK', ''), ('NOP', None), ('Timestamp', (123, 0)), ('WScale', 7)]
        response = srp1(Ether()/IP(src=str(sip), dst=str(target.ip)) / TCP(sport=src_port, dport=int(dst_port), flags="S", seq=seq_num, options=tcp_options), iface=ifaz, timeout=tout, verbose=0)
        if(str(type(response))=="<class 'NoneType'>"):
            pass
        elif(response.haslayer(TCP)):
            if(response.getlayer(TCP).flags == 0x12):
                send_rst = srp1(Ether()/IP(src=str(sip), dst=str(target.ip))/TCP(sport=src_port, dport=int(dst_port), flags="A", seq=seq_num + 1, ack=response.getlayer(TCP).seq + len(response.getlayer(TCP).payload) + 1), iface=ifaz, timeout=tout, verbose=0)
                send_rst = srp1(Ether()/IP(src=str(sip), dst=str(target.ip))/TCP(sport=src_port, dport=int(dst_port), flags="R", seq=seq_num + 2, ack=response.getlayer(TCP).seq + len(response.getlayer(TCP).payload) + 1), iface=ifaz, timeout=tout, verbose=0)
                target.setUp()
                new_port=Puerto(dst_port, 'tcp')
                new_port.estado='open'
                new_port.ttl = response.ttl
                new_port.mac = response.src
                new_port.idOS = identificacionOS(response)
                new_port.bannergrabbing(str(target.ip), tout)
                target.add_port(new_port)
                target.ttl = response.ttl
                target.mac = response.src
            elif(response.getlayer(TCP).flags == 0x14):
                pass
        return target
    except Exception as e:
        print("Ocurrió un error al enviar el paquete tcpconnectscan a {0}: {1}".format(str(target.ip), e))


def tcpstealthscan(ifaz, sip, target, dst_port, tout):
    '''
    Poca diferencia con el connect scan en cuanto intercambio de paquetes.
    En esta ocasion, si no se recibe respuesta o esta es un paquete icmp se clasifica el puerto como filtered
    :param target:
    :param dst_port:
    :param tout:
    :return:
    '''
    try:
        src_port = RandShort()._fix()
        seq_num = random.randint(1, 1000000)
        tcp_options = [('MSS', 1460), ('SAckOK', ''), ('NOP', None), ('Timestamp', (123, 0)), ('WScale', 7)]
        response = srp1(Ether()/IP(src=str(sip), dst=str(target.ip)) / TCP(sport=src_port, dport=int(dst_port), flags="S", seq=seq_num, options=tcp_options), iface=ifaz, timeout=tout, verbose=0)
        if response is not None:
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                target.setUp()
                new_port=Puerto(dst_port, 'tcp')
                new_port.estado='open'
                new_port.ttl = response.ttl
                new_port.mac = response.src
                new_port.idOS = identificacionOS(response)
                new_port.bannergrabbing(str(target.ip), tout)
                target.add_port(new_port)
                target.ttl = response.ttl
                target.mac = response.src
                response_packet = srp1(Ether()/IP(src=str(sip), dst=str(target.ip))/TCP(sport=src_port, dport=int(dst_port), flags="R", seq=seq_num + 1, ack=response.getlayer(TCP).seq + len(response.getlayer(TCP).payload) + 1), iface=ifaz, timeout=tout, verbose=0)
            elif response.haslayer(TCP) and (response.getlayer(TCP).flags == 0x14):
                #print(f"[+] stealthscan:Port {dst_port} is closed on {str(target.ip)}")
                pass
            elif response.haslayer(ICMP):
                if(int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    new_port = Puerto(dst_port, 'tcp')
                    new_port.estado = 'filtered'
                    new_port.ttl = response.ttl
                    new_port.mac = response.src
                    new_port.idOS = identificacionOS(response)
                    target.add_port(new_port)
                    target.ttl = response.ttl
                    target.mac = response.src
                    if int(response.getlayer(ICMP).code) in [9, 10, 13]:
                        # The destination network is administratively prohibited,
                        # The destination host is administratively prohibited,
                        # Communication administratively prohibited
                        target.firewalled = True
        else:
            new_port=Puerto(dst_port, 'tcp')
            new_port.estado='filtered'
            target.add_port(new_port)
            target.firewalled = True
        return target
    except Exception as e:
        print("Ocurrió un error al enviar el paquete tcpstealthscan a {0}: {1}".format(str(target.ip), e))



def ackscan(ifaz, sip, target, dst_port, tout):
    '''
    nmap -sA
    Se busca determinar si el objetivo está detras de un firewall
    :param target:
    :param dst_port:
    :param tout:
    :return:
    '''
    try:
        src_port = RandShort()._fix()
        tcp_options = [('MSS', 1460), ('SAckOK', ''), ('NOP', None), ('Timestamp', (123, 0)), ('WScale', 7)]
        response = srp1(Ether()/IP(src=str(sip), dst=str(target.ip)) / TCP(sport=src_port, dport=dst_port, flags="A", options=tcp_options), iface=ifaz, timeout=tout, verbose=0)
        if response is not None:
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x4:
                target.setUp()
                target.ttl = response.ttl
                target.mac = response.src
                target.idOS = identificacionOS(response)
                # El puerto no esá filtrado, pero no podemos decir si está abierto o cerrado.
            elif response.haslayer(ICMP):
                if (int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                    new_port = Puerto(dst_port, 'tcp')
                    new_port.estado = 'filtered'
                    new_port.ttl = response.ttl
                    new_port.mac = response.src
                    new_port.idOS = identificacionOS(response)
                    target.add_port(new_port)
                    target.firewalled = True
                    target.ttl = response.ttl
                    target.mac = response.src
        else:
            target.firewalled = True
            new_port = Puerto(dst_port, 'tcp')
            new_port.estado = 'filtered'
            target.add_port(new_port)
            #solo se mostrará este puerto si la maquina se determina UP por otro puerto.
        return target
    except Exception as e:
        print("Ocurrió un error al enviar el paquete ackscan a {0}: {1}".format(str(target.ip), e))


def xmasscan(ifaz, sip, target, dst_port, tout):
    '''
    nmap -sX
    :param target:
    :param dst_port:
    :param tout:
    :return:
    '''
    try:
        src_port = RandShort()._fix()
        tcp_options = [('MSS', 1460), ('SAckOK', ''), ('NOP', None), ('Timestamp', (123, 0)), ('WScale', 7)]
        response = srp1(Ether()/IP(src=str(sip), dst=str(target.ip)) / TCP(sport=src_port, dport=dst_port, flags="FPU", options=tcp_options), iface=ifaz, timeout=tout, verbose=0)
        if response is None:
            new_port = Puerto(dst_port, 'tcp')
            new_port.estado = 'open/filtered'
            target.add_port(new_port)
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
            # Se supone que si el puerto está cerrado debería responder con un AR
            target.setUp()
            target.ttl = response.ttl
            target.mac = response.src
            target.idOS = identificacionOS(response)
        elif response.haslayer(ICMP) and int(response.getlayer(ICMP).type)==3:
            new_port = Puerto(dst_port, 'tcp')
            new_port.estado = 'filtered'
            new_port.ttl = response.ttl
            new_port.mac = response.src
            new_port.idOS = identificacionOS(response)
            target.add_port(new_port)
            target.setUp()
            target.ttl = response.ttl
            target.mac = response.src
            target.firewalled = True
    except Exception as e:
        print("Ocurrió un error al enviar el paquete xmasscan a {0}: {1}".format(str(target.ip), e))


def finscan(ifaz, sip, target, dst_port, tout):
    '''
    nmap -sF
    :param target:
    :param dst_port:
    :param tout:
    :return:
    '''
    try:
        src_port = RandShort()._fix()
        tcp_options = [('MSS', 1460), ('SAckOK', ''), ('NOP', None), ('Timestamp', (123, 0)), ('WScale', 7)]
        response = srp1(Ether()/IP(src=str(sip), dst=str(target.ip)) / TCP(sport=src_port, dport=dst_port, flags="F",options=tcp_options), iface=ifaz, timeout=tout, verbose=0)
        if response is None:
            new_port = Puerto(dst_port, 'tcp')
            new_port.estado = 'open/filtered'
            target.add_port(new_port)
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
                target.setUp()
                target.ttl = response.ttl
                target.mac = response.src
                target.idOS = identificacionOS(response)
        elif response.haslayer(ICMP):
            if int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                target.setUp()
                new_port=Puerto(dst_port, 'tcp')
                new_port.estado='filtered'
                new_port.ttl = response.ttl
                new_port.mac = response.src
                new_port.idOS = identificacionOS(response)
                target.add_port(new_port)
                target.ttl = response.ttl
                target.mac = response.src
                target.firewalled = True
    except Exception as e:
        print("Ocurrió un error al enviar el paquete finscan a {0}: {1}".format(str(target.ip), e))


def nullscan(ifaz, sip, target, dst_port, tout):
    '''
    nmap -sN
    :param target:
    :param dst_port:
    :param tout:
    :return:
    '''
    try:
        src_port = RandShort()._fix()
        tcp_options = [('MSS', 1460), ('SAckOK', ''), ('NOP', None), ('Timestamp', (123, 0)), ('WScale', 7)]
        response = srp1(Ether()/IP(src=str(sip), dst=str(target.ip)) / TCP(sport=src_port, dport=dst_port, flags=0x00, options=tcp_options), iface=ifaz, timeout=tout, verbose=0)
        if response is None:
            new_port = Puerto(dst_port, 'tcp')
            new_port.estado = 'open/filtered'
            target.add_port(new_port)
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
                target.setUp()
                target.ttl = response.ttl
                target.mac = response.src
                target.idOS = identificacionOS(response)
        elif response.haslayer(ICMP):
            if int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                target.setUp()
                new_port=Puerto(dst_port, 'tcp')
                new_port.estado='filtered'
                new_port.ttl = response.ttl
                new_port.mac = response.src
                new_port.idOS = identificacionOS(response)
                target.add_port(new_port)
                target.ttl = response.ttl
                target.mac = response.src
                target.firewalled = True
    except Exception as e:
        print("Ocurrió un error al enviar el paquete nullscan a {0}: {1}".format(str(target.ip), e))


def winscan(ifaz, sip, target, dst_port, tout):
    '''
    nmap -sW
    :param target:
    :param dst_port:
    :param tout:
    :return:
    '''
    try:
        src_port = RandShort()._fix()
        tcp_options = [('MSS', 1460), ('SAckOK', ''), ('NOP', None), ('Timestamp', (123, 0)), ('WScale', 7)]
        response = srp1(Ether()/IP(src=str(sip), dst=str(target.ip)) / TCP(sport=src_port, dport=dst_port, flags="A", options=tcp_options), iface=ifaz, timeout=tout, verbose=0)
        if response is None:
            target.firewalled = True
            new_port = Puerto(dst_port, 'tcp')
            new_port.estado = 'filtered'
            target.add_port(new_port)
        elif response.haslayer(TCP):
            if response.getlayer(TCP).window == 0:
                target.setUp()
                target.ttl = response.ttl
                target.mac = response.src
                target.idOS = identificacionOS(response)
                pass
            elif response.getlayer(TCP).window > 0:
                target.setUp()
                new_port = Puerto(dst_port, 'tcp')
                new_port.estado = 'open'
                new_port.ttl = response.ttl
                new_port.mac = response.src
                new_port.idOS = identificacionOS(response)
                new_port.bannergrabbing(str(target.ip), tout)
                target.add_port(new_port)
                target.ttl = response.ttl
                target.mac = response.src
        elif response.haslayer(ICMP):
            if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                target.setUp()
                new_port=Puerto(dst_port, 'tcp')
                new_port.estado='filtered'
                new_port.ttl = response.ttl
                new_port.mac = response.src
                new_port.idOS = identificacionOS(response)
                target.add_port(new_port)
                target.ttl = response.ttl
                target.mac = response.src
                target.firewalled = True
    except Exception as e:
        print("Ocurrió un error al enviar el paquete winscan a {0}: {1}".format(str(target.ip), e))


def identificacionOS(response):
    #https://github.com/Ettercap/ettercap/blob/master/share/etter.finger.os
    #WWWW: MSS:TTL: WS:S: N:D: T:F: LEN:OS
    # The fingerprint database has the following structure:                    #
    #                                                                          #
    # WWWW:MSS:TTL:WS:S:N:D:T:F:LEN:OS                                         #
    #                                                                          #
    # WWWW: 4 digit hex field indicating the TCP Window Size                   #
    # MSS : 4 digit hex field indicating the TCP Option Maximum Segment Size   #
    #       if omitted in the packet or unknown it is "_MSS"                   #
    # TTL : 2 digit hex field indicating the IP Time To Live                   #
    # WS  : 2 digit hex field indicating the TCP Option Window Scale           #
    #       if omitted in the packet or unknown it is "WS"                     #
    # S   : 1 digit field indicating if the TCP Option SACK permitted is true  #
    # N   : 1 digit field indicating if the TCP Options contain a NOP          #
    # D   : 1 digit field indicating if the IP Don't Fragment flag is set      #
    # T   : 1 digit field indicating if the TCP Timestamp is present           #
    # F   : 1 digit ascii field indicating the flag of the packet              #
    #       S = SYN                                                            #
    #       A = SYN + ACK                                                      #
    # LEN : 2 digit hex field indicating the length of the packet              #
    #       if irrilevant or unknown it is "LT"                                #
    # OS  : an ascii string representing the OS                                #
    #                                                                          #
    fingerestructure = {"wwww": "", "mss": "", "ttl": "", "WS": "", "S": "", "N": "", "D": "",  "T": "", "F": "", "LEN": "", "OS": ""}
    if response.haslayer(IP):
        # obtenemos el TTL
        ttl = response.ttl
        dist_32 = (32 - ttl) if ttl <= 32 else 300
        dist_64 = (64 - ttl) if ttl <= 64 else 300
        dist_128 = (128 - ttl) if ttl <= 128 else 300
        dist_255 = (255 - ttl)
        dist_min = min(dist_32, dist_64, dist_128, dist_255)
        # Dependiendo de la cercania, seleccionamos el valor en Hexadecimal
        if dist_min == dist_32:
            fingerestructure['ttl'] = "20"
        elif dist_min == dist_64:
            fingerestructure['ttl'] = "40"
        elif dist_min == dist_128:
            fingerestructure['ttl'] = "80"
        else:
            fingerestructure['ttl'] = "FF"
        # Obtenemos IP Don't Fragment flag is set
        fingerestructure['D'] = "0"
        if response.flags & 0x02:
            fingerestructure['D'] = "1"

    if response.haslayer(TCP):
        # obtenemos wwww -> el tamaño de ventana TCP:
        fingerestructure['wwww'] = "{:0>4X}".format(response[TCP].window)
        # obtenemos mss -> TCP Option Maximum Segment Size
        fingerestructure['mss'] = "{:0>4X}".format(response[TCP].options[0][1]) if response[TCP].options else "_MSS"
        # obtenemos ws -> TCP Option Window Scale
        fingerestructure['WS'] = "WS"
        for opt in response[TCP].options:
            if opt[0] == 'WScale':
                fingerestructure['WS'] = "{:0>2X}".format(opt[1])
                break
        # obtenemos TCP Option SACK permitted
        fingerestructure['S'] = "0"
        for opt in response[TCP].options:
            if opt[0] == 'SAckOK':
                fingerestructure['S'] = "1"
                break
        # obtenemos TCP Options contain a NOP
        fingerestructure['N'] = "0"
        if 'NOP' in [opt[0] for opt in response[TCP].options]:
            fingerestructure['N'] = "1"
        # obtenemos the TCP Timestamp is present
        fingerestructure['T'] = "0"
        if 'Timestamp' in [opt[0] for opt in response[TCP].options]:
            fingerestructure['T'] = "1"
        # obtenemos los flags de SYN y SYN+ACK
        if response[TCP].flags & 0x02:
            fingerestructure['F'] = "S"
        if response[TCP].flags & 0x12 == 0x12:
            fingerestructure['F'] = "A"
    # obtenemos la longitud del paquete:
    fingerestructure['LEN'] = "{:0>2X}".format(len(response))
    fingerestructure['OS'] = getOS(fingerestructure)
    return fingerestructure


def getOS(fingerestructure):
    # definimos un diccionario con valores conocidos de
    # SSOO - TTL - TCP Window Size
    # https://www.netresec.com/?page=Blog&month=2011-11&post=Passive-OS-Fingerprinting
    # https://jonathansblog.co.uk/os-detection-techniques
    os_data_ttl_wwww = {
        ("Linux (Kernel 2.4 and 2.6)", 64, 5840),
        ("Linux (Kernel 2.4 and 2.6)", 64, 5792),
        ("Linux (Ubuntu/RH/Centos)", 64, 14480),
        ("Linux (Rocky)", 64, 29200),
        ("HP LaseJet", 64, 11680),
        ("Google Linux", 64, 5720),
        ("FreeBSD", 64, 65535),
        ("Raspbian", 64, 65160),
        ("Windows XP", 128, 65535),
        ("Windows XP", 128, 64240),
        ("Windows Vista and 7 (Server 2008)", 128, 8192),
        ("iOS 12.4 (Cisco Routers)", 255, 4128)
    }
    os_data_ttl = {
        ("Linux", 64),
        ("Windows", 128),
        ("iOS 12.4 (Cisco Routers)", 255)
    }
    # Buscamos las coincidencias
    if fingerestructure['ttl'] and fingerestructure['wwww']:
        for ssoo, ttl, tcp_win_size in os_data_ttl_wwww:
            if fingerestructure['ttl'] == "{:0>2X}".format(ttl) and fingerestructure['wwww'] == "{:0>4X}".format(tcp_win_size):
                return ssoo
    elif fingerestructure['ttl']:
        for ssoo, ttl in os_data_ttl:
            if fingerestructure['ttl'] == "{:0>2X}".format(ttl):
                return ssoo
    else:
        return ""


# Creamos un diccionario que mapea nombres de funciones a objetos de función
funciones = {
    "arpping": arpping,
    "icmpping": icmpping,
    "tcpping": tcpping,
    "udpping": udpping,
    "tcpconnectscan": tcpconnectscan,
    "tcpstealthscan": tcpstealthscan,
    "ackscan": ackscan,
    "xmasscan": xmasscan,
    "finscan": finscan,
    "nullscan": nullscan,
    "winscan": winscan
}

# Definimos una función que selecciona y ejecuta una función en función del parámetro de entrada
def seleccionar_funcion(nombre_funcion, parametros, hilos):
    targets = parametros[0]
    ports = parametros[1]
    ifaz = parametros[2]
    sip = parametros[3]
    tout = parametros[4]

    # Buscamos la función correspondiente en el diccionario
    funcion = funciones.get(nombre_funcion)
    if funcion is not None:
        if funcion.__name__ in ["arpping", "icmpping"]:
            with tqdm(total=len(targets)) as pbar:
                threads = []
                for i, target in enumerate(targets):
                    thread = threading.Thread(target=funcion, args=(ifaz, sip, target, tout))
                    thread.start()
                    threads.append(thread)
                    if (i + 1) % hilos == 0:
                        for thread in threads:
                            pbar.update(1)
                            thread.join()
                        threads = []
        else:
            targets_ports = [(target, port) for target in targets for port in raw_ports]
            with tqdm(total=len(targets)*len(ports)) as pbar:
                threads = []
                for i, target_port in enumerate(targets_ports):
                    thread = threading.Thread(target=funcion, args=(ifaz, sip, target_port[0], target_port[1], tout))
                    thread.start()
                    threads.append(thread)
                    if (i + 1) % hilos == 0:
                        for thread in threads:
                            pbar.update(1)
                            thread.join()
                        threads = []

    else:
        print(f"La función {nombre_funcion} no existe")

def salida(targets):
    for target in targets:
        if target.getUP():
            tabla_hosts = PrettyTable()
            tabla_hosts.field_names = ["Equipo", "MAC", "TTL", "Arriba", "TTL:OS", "Firewalled"]
            tabla_hosts.add_row([str(target.ip), str(target.mac), str(target.ttl), str(target.getUP()), str(":".join([str(target.idOS[key]) for key in ["ttl", "OS"]])), str(target.firewalled)])
            print(tabla_hosts)
            tabla_ports = PrettyTable()
            tabla_ports.hrules = ALL
            tabla_ports.field_names = ["Port", "Estado", "TTL", "MAC", "WWWW:MSS:TTL:WS:S:N:D:T:F:LEN:OS", "Banner"]
            tabla_ports.max_width['Banner'] = 50
            tabla_ports.align['Banner'] = 'l'
            for port in target.puertos:
                tabla_ports.add_row([int(port.numero), str(port.estado), str(port.ttl), str(port.mac), str(":".join([str(valor) for valor in port.idOS.values()])) ,str(port.banner).replace('\r','')])

            tabla_ports.sortby = "Port"
            if len(target.puertos) > 0:
                for linea in str((tabla_ports)).split('\n'):
                    print('  ' + linea)

if __name__ == '__main__':
    # Capturamos el Ctrl-C para hacer una salida ordenada
    signal(SIGINT, handler)

    ayuda = 'Programa para realizar un escaneo de la red local'
    parser = argparse.ArgumentParser(description=ayuda)
    parser.add_argument("-p", "--port", help="puertos a escanear", default="22")
    parser.add_argument("--targets",
                        help="direccion a la que realizar el scaneo en formato CIDR:" + get_default_range(),
                        default=get_default_range())
    parser.add_argument("-i", "--interfaz", help="Interfaz por la que hacer el escaneo", choices=get_interfaces(),
                        default=get_work_interface())
    parser.add_argument("-s", "--source", help="IP origen a utilizar:" + get_default_IP(), default=get_default_IP())
    parser.add_argument("--timeout", help="Tiempo de espera para la recepcion de las respuestas: ", type=int,
                        default=5)
    parser.add_argument("-H", "--hilos", help="numero de hilos", type=int, default=1280)
    parser.add_argument('--scantype',
                        default='arpping',
                        const='arpping',
                        nargs='?',
                        choices=['arpping', 'icmpping', 'tcpping', 'udpping', 'tcpconnectscan', 'tcpstealthscan', 'ackscan', 'xmasscan', 'finscan', 'nullscan', 'winscan'],
                        help='Tipo de escaneo (default: %(default)s)')

    # Se procesan los argumentos
    args = parser.parse_args()
    targets = set_targets(args.targets)
    raw_ports = set_ports(args.port)
    scantype = args.scantype
    ifaz = args.interfaz
    sip = set_source(args.source)
    tout = args.timeout
    hilos = args.hilos

    parametros = [targets, raw_ports, ifaz, sip, tout]

    seleccionar_funcion(scantype, parametros, hilos)

    salida(targets)