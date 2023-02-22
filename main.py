# This is a sample Python script.
import argparse
import ipaddress
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import threading
import time
import concurrent.futures
from signal import signal, SIGINT
from scapy.all import *
from sys import platform
from tqdm import tqdm
from copy import copy
import socket


#clase equipo para almacenar los equipos que se encuentren
class Equipo:
    def __init__(self, ip):
        self._ip = ip
        self._up = False
        self.nombre = ""
        self.mac = ""
        self.ttl = 0 # Idea: alamcenar en un set() todos los ttl de los paquetes recibidos. Si el ttl es distinto puede significar que el puerto este filtrado
        self.puertos = []
        self.so = ""
        self.firewalled = False

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
    def __init__(self,numero,tipo):
        self._numero = numero
        self._tipo = tipo #tcp,udp,sctp
        self._estado = "" #open,closed,filtered,open/filtered
        self._banner = ""
    def __hash__(self):
        return hash(self._numero)
    def __eq__(self, other):
        if isinstance(other, Puerto):
            return self._numero == other._numero
        return NotImplemented

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
    '''def setEstado(self, value):
        if not isinstance(value, string):
            raise TypeError("El estado debe ser un string")
        if value not in ["open", "closed", "filtered"]:
            raise TypeError("El estado debe ser open, close, filtered")
        self.estado = value'''

'''
# simple progress indicator callback function
def progress_indicator(future):
    print('.', end='', flush=True)
'''

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


def get_default_range():
    default_ip = get_if_addr(get_work_interface()) + "/24"
    rango = ipaddress.ip_network(default_ip, strict=False)
    return rango.exploded


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


def set_ports(rango_puertos, tipo):
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
    target_ports = set()
    raw_ports = set()
    try:
        for i in rango_puertos.split(','):
            if '-' in i:
                puerto_inicial = 1 if i.split('-')[0] == '' else i.split('-')[0]
                puerto_final = 65535 if i.split('-')[1] == '' else i.split('-')[1]
                for puerto in range(int(puerto_inicial),int(puerto_final)+1):
                    target_ports.add(Puerto(puerto, tipo))
                    raw_ports.add(puerto)
            else:
                target_ports.add(Puerto(i, tipo))
                raw_ports.add(int(i))
    except:
        print("Ups, algo fue mal con los puertos. Revisalos e intentalo de nuevo...")
    return target_ports, raw_ports


def handler(signal, frame):
    print("[!] Ctrl+c pulsado, saliendo del script")
    exit(1)

#dispatch table
# Definimos una serie de funciones
def arpping(ifaz, target, tout):
    # Se emiten los paquetes a broadcast a traves de la interfaz indicada
    #print(
    #    'Se emiten paquetes ARP a traves de la interfaz {0} preguntando su dominio de broadcast por las IP solicitadas '
    #    .format(ifaz))
    #for target in targets:
    #print("se escanea el target:{0}".format(str(target.ip)))
    ans = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(target.ip)), iface=ifaz, timeout=tout, verbose=0)
    # ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%") )
    if ans is not None:
        target.setUp()
        target.mac = ans.hwsrc
    return target

def icmpping(ifaz, target, tout):
    response = srp1(Ether()/IP(dst=str(target.ip))/ICMP(), iface=ifaz, timeout=tout, verbose=0)
    if response is not None:
        #print(f"[+] el equipo {str(target.ip)} esta arriba")
        target.setUp()
        target.ttl = response.ttl
        target.mac = response.src
    return target

def tcpping(target, dst_port, tout):
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
    src_port = RandShort()._fix()
    response = srp1(Ether()/IP(dst=str(target.ip)) / TCP(sport=src_port, dport=dst_port, flags="S"), timeout=tout, verbose=0)
    if response is not None:
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            target.setUp()
            new_port=Puerto(dst_port, 'tcp')
            new_port.estado='open'
            target.add_port(new_port)
            target.ttl = response.ttl
            target.mac = response.src
            response_packet = sr1(IP(dst=str(target.ip))/TCP(sport=src_port, dport=port, flags="R"), timeout=tout, verbose=0)
        else:
            pass # si esta cerrado se recibe un Rst=1, Ack=1 (0x14), win=0, len=0
    return target

def udpping(target, dst_port, tout):
    src_port = RandShort()._fix()
    response = srp1(Ether()/IP(dst=str(target.ip)) / UDP(sport=src_port, dport=dst_port), timeout=tout, verbose=0)

    # Analiza la respuesta
    if response is None:
        #print(F"port {port} open/filtered")
        new_port = Puerto(dst_port, 'udp')
        new_port.estado = 'open/filtered'
        target.add_port(new_port)
    elif response.haslayer(UDP):
        new_port = Puerto(dst_port, 'udp')
        new_port.estado = 'open'
        target.add_port(new_port)
        target.setUp()
        target.ttl = response.ttl
        target.mac = response.src
    elif response.haslayer(ICMP):
        if (int(response.getlayer(ICMP).type) == 3) and int(response.getlayer(ICMP).code) == 3:
            pass
        elif (int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) in [1, 2, 9, 10, 13]):
            new_port = Puerto(dst_port, 'udp')
            new_port.estado = 'filtered'
            target.add_port(new_port)
            target.ttl = response.ttl
            target.mac = response.src

def tcpconnectscan(target, dst_port, tout):
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
    src_port = RandShort()._fix()
    response = srp1(Ether()/IP(dst=str(target.ip)) / TCP(sport=src_port, dport=int(dst_port), flags="S"), timeout=tout, verbose=0)
    if(str(type(response))=="<class 'NoneType'>"):
        pass
    elif(response.haslayer(TCP)):
        if(response.getlayer(TCP).flags == 0x12):
            # este lo manda el SSOO
            send_rst = srp1(Ether()/IP(dst=str(target.ip))/TCP(sport=src_port, dport=int(dst_port), flags="A"), timeout=tout, verbose=0)
            send_rst = srp1(Ether()/IP(dst=str(target.ip))/TCP(sport=src_port, dport=int(dst_port), flags="R"), timeout=tout, verbose=0)
            target.setUp()
            new_port=Puerto(dst_port, 'tcp')
            new_port.estado='open'
            target.add_port(new_port)
            target.ttl = response.ttl
            target.mac = response.src
        elif(response.getlayer(TCP).flags == 0x14):
            pass
    return target

def tcpstealthscan(target, dst_port, tout):
    '''
    Poca diferencia con el connect scan en cuanto intercambio de paquetes.
    En esta ocasion, si no se recibe respuesta o esta es un paquete icmp se clasifica el puerto como filtered
    :param target:
    :param dst_port:
    :param tout:
    :return:
    '''
    src_port = RandShort()._fix()
    response = srp1(Ether()/IP(dst=str(target.ip)) / TCP(sport=src_port, dport=int(dst_port), flags="S"), timeout=tout, verbose=0)
    if response is not None:
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            target.setUp()
            #print(f"[+] stealthscan:Port {dst_port} is open on {str(target.ip)}")
            new_port=Puerto(dst_port, 'tcp')
            new_port.estado='open'
            target.add_port(new_port)
            target.ttl = response.ttl
            target.mac = response.src
            response_packet = srp1(Ether()/IP(dst=str(target.ip))/TCP(sport=src_port, dport=port, flags="R"), timeout=tout, verbose=0)
        elif response.haslayer(TCP) and (response.getlayer(TCP).flags == 0x14):
            #print(f"[+] stealthscan:Port {dst_port} is closed on {str(target.ip)}")
            pass
        elif response.haslayer(ICMP):
            if(int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                #print(f"[+] stealthscan:Port {dst_port} is filtered by icmp on {str(target.ip)}")
                new_port = Puerto(dst_port, 'tcp')
                new_port.estado = 'filtered'
                target.add_port(new_port)
                target.ttl = response.ttl
                target.mac = response.src
    else:
        #print(f"[+] stealthscan:Port {dst_port} is filtered on {str(target.ip)}")
        new_port=Puerto(dst_port, 'tcp')
        new_port.estado='filtered'
        target.add_port(new_port)
    return target

def ackscan(target, dst_port, tout):
    '''
    nmap -sA
    Se busca determinar si el objetivo está detras de un firewall
    :param target:
    :param dst_port:
    :param tout:
    :return:
    '''
    src_port = RandShort()._fix()
    response = srp1(Ether()/IP(dst=str(target.ip)) / TCP(sport=src_port, dport=dst_port, flags="A"), timeout=tout, verbose=0)
    if response is not None:
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x4:
            target.setUp()
            target.firewalled = False
            target.ttl = response.ttl
            target.mac = response.src
            print(f"port {dst_port} no firewall (Reset)")
        elif response.haslayer(ICMP):
            if (int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                target.firewalled = True
                target.ttl = response.ttl
                target.mac = response.src
                print(f"port {dst_port} stateful firewall (ICMP)")
    else:
        target.firewalled = True
        print(f"port {dst_port} stateful firewall (DROP)")
    return target

def xmasscan(target, dst_port, tout):
    '''
    nmap -sX
    :param target:
    :param dst_port:
    :param tout:
    :return:
    '''
    src_port = RandShort()._fix()
    response = srp1(Ether()/IP(dst=str(target.ip)) / TCP(sport=src_port, dport=dst_port, flags="FPU"), timeout=tout, verbose=0)
    if response is None:
        #print(f"port {dst_port} Open/filtered")
        pass
    elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
        # Se supone que si el puerto está cerrado debería responder con un AR, pero por lo menos la raspberry no manda nada
        #print(f"port {dst_port} Closed")
        pass
    elif response.haslayer(ICMP) and int(response.getlayer(ICMP).type)==3:
        #print(F"port {port} filtered")
        new_port = Puerto(dst_port, 'tcp')
        new_port.estado = 'filtered'
        target.add_port(new_port)
        target.ttl = response.ttl
        target.mac = response.src
    else:
        pass

def finscan(target, dst_port, tout):
    '''
    nmap -sF
    :param target:
    :param dst_port:
    :param tout:
    :return:
    '''
    src_port = RandShort()._fix()
    response = srp1(Ether()/IP(dst=str(target.ip)) / TCP(sport=src_port, dport=dst_port, flags="F"), timeout=tout, verbose=0)
    if response is None:
        #print(f"port {dst_port} Open/filtered")
        #target.setUp()
        new_port = Puerto(dst_port, 'tcp')
        new_port.estado = 'open/filtered'
        target.add_port(new_port)
    elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
            #print(f"port {dst_port} Closed")
            pass
    elif response.haslayer(ICMP):
        if int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]:
            #print(f"port {dst_port} filtered")
            target.setUp()
            new_port=Puerto(dst_port, 'tcp')
            new_port.estado='filtered'
            target.add_port(new_port)
            target.ttl = response.ttl
            target.mac = response.src

def nullscan(target, dst_port, tout):
    '''
    nmap -sN
    :param target:
    :param dst_port:
    :param tout:
    :return:
    '''
    src_port = RandShort()._fix()
    response = srp1(Ether()/IP(dst=str(target.ip)) / TCP(sport=src_port, dport=dst_port, flags=0x00), timeout=tout, verbose=0)
    if response is None:
        #print(f"port {dst_port} Open/Filtered")
        #target.setUp()
        new_port = Puerto(dst_port, 'tcp')
        new_port.estado = 'open/filtered'
        target.add_port(new_port)
    elif response.haslayer(TCP) and response.getlayer(TCP).flags == "R":
            #print(f"port {dst_port} Closed")
            pass
    elif response.haslayer(ICMP):
        if int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]:
            #print(f"port {dst_port} filtered")
            target.setUp()
            new_port=Puerto(dst_port, 'tcp')
            new_port.estado='filtered'
            target.add_port(new_port)
            target.ttl = response.ttl
            target.mac = response.src

def winscan(target, dst_port, tout):
    '''
    nmap -sW
    :param target:
    :param dst_port:
    :param tout:
    :return:
    '''
    src_port = RandShort()._fix()
    response = srp1(Ether()/IP(dst=str(target.ip)) / TCP(sport=src_port, dport=dst_port, flags="A"), timeout=tout, verbose=0)
    if response is None:
        target.firewalled = True
        print(f"port {dst_port} stateful firewall")
    elif response.haslayer(TCP):
        if response.getlayer(TCP).window == 0:
            print(f"port closed")
        elif response.getlayer(TCP).window > 0:
            print(f"port {dst_port} Open")
            target.setUp()
            new_port = Puerto(dst_port, 'tcp')
            new_port.estado = 'open'
            target.add_port(new_port)
            target.ttl = response.ttl
            target.mac = response.src
    elif response.haslayer(ICMP):
        if int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]:
            #print(f"port {dst_port} filtered")
            target.setUp()
            new_port=Puerto(dst_port, 'tcp')
            new_port.estado='filtered'
            target.add_port(new_port)
            target.ttl = response.ttl
            target.mac = response.src

def bannergrabbing(target, dst_port, tout):
    #primero buscamos si el puerto para el target esta abierto

    socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        socket.connect((str(target.ip), int(dst_port)))
        socket.settimeout(tout)
        banner = socket.recv(1024)
    except:
        pass

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
    "winscan": winscan,
    "bannergrabbing": bannergrabbing
}

# Definimos una función que selecciona y ejecuta una función en función del parámetro de entrada
def seleccionar_funcion(nombre_funcion, parametros, hilos):
    targets = parametros[0]
    ports = parametros[1]
    ifaz = parametros[2]
    tout = parametros[3]

    # Buscamos la función correspondiente en el diccionario
    funcion = funciones.get(nombre_funcion)
    #print(f"[!] la funcion elegida es {funcion.__name__}")
    #print(f"[!] los objetivos son {targets}")
    # Si la función existe, la ejecutamos
    if funcion is not None:
        if funcion.__name__ in ["arpping", "icmpping"]:
            with tqdm(total=len(targets)) as pbar:
                with concurrent.futures.ThreadPoolExecutor(max_workers=hilos) as executor:
                    futures = [executor.submit(funcion, ifaz, target, tout) for target in targets]
                    for future in concurrent.futures.as_completed(futures):
                        pbar.update(1)
                        target = future.result()
            #funcion()
        else:
            targets_ports = [(target, port) for target in targets for port in raw_ports]
            total_works = len(targets_ports)
            with tqdm(total=len(targets)*len(ports)) as pbar:
                with concurrent.futures.ThreadPoolExecutor(max_workers=hilos) as executor:
                    futures = [executor.submit(funcion, target, port, tout) for target in targets for port in
                               ports if target.getUP()]
                    for future in concurrent.futures.as_completed(futures):
                        pbar.update(1)
                        target = future.result()
            #funcion()
    else:
        print(f"La función {nombre_funcion} no existe")

def seleccionar_funcion2(nombre_funcion, parametros, hilos):
    targets = parametros[0]
    ports = parametros[1]
    ifaz = parametros[2]
    tout = parametros[3]

    # Buscamos la función correspondiente en el diccionario
    funcion = funciones.get(nombre_funcion)
    if funcion is not None:
        if funcion.__name__ in ["arpping", "icmpping"]:
            with tqdm(total=len(targets)) as pbar:
                threads = []
                for i, target in enumerate(targets):
                    if i >= hilos:
                        pass #break
                    thread = threading.Thread(target=funcion, args=(ifaz, target, tout))
                    thread.start()
                    threads.append(thread)
                    if (i + 1) % hilos == 0:
                        for thread in threads:
                            pbar.update(1)
                            thread.join()
                        threads = []
                # Espera a que todos los hilos terminen
                for thread in threads:
                    pbar.update(1)
                    thread.join()
        else:
            targets_ports = [(target, port) for target in targets for port in raw_ports]
            total_works = len(targets_ports)
            with tqdm(total=len(targets)*len(ports)) as pbar:
                threads = []
                for i, target_port in enumerate(targets_ports):
                    if i >= hilos:
                        pass #break
                    thread = threading.Thread(target=funcion, args=(target_port[0], target_port[1], tout))
                    thread.start()
                    threads.append(thread)
                    if (i + 1) % hilos == 0:
                        for thread in threads:
                            pbar.update(1)
                            thread.join()
                        threads = []
                # Espera a que todos los hilos terminen
                for thread in threads:
                    pbar.update(1)
                    thread.join()
    else:
        print(f"La función {nombre_funcion} no existe")


if __name__ == '__main__':
    # Capturamos el Ctrl-C para hacer una salida ordenada
    signal(SIGINT, handler)

    ayuda = 'Programa para realizar un escaneo de la red local'
    parser = argparse.ArgumentParser(description=ayuda)
    parser.add_argument("-p", "--port", help="puertos a escanear", default=22)
    parser.add_argument("--targets",
                        help="direccion a la que realizar el scaneo en formato CIDR:" + get_default_range(),
                        default=get_default_range())
    parser.add_argument("-i", "--interfaz", help="Interfaz por la que hacer el escaneo", choices=get_interfaces(),
                        default=get_work_interface())
    parser.add_argument("--timeout", help="Tiempo de espera para la recepcion de las respuestas: ", type=int,
                        default=5)
    parser.add_argument("-H", "--hilos", help="numero de hilos", type=int, default=1280)
    parser.add_argument('--scantype',
                        default='arpping',
                        const='arpping',
                        nargs='?',
                        choices=['arpping', 'icmpping', 'tcpping', 'udpping', 'tcpconnectscan', 'tcpstealthscan', 'ackscan', 'xmasscan', 'finscan', 'nullscan', 'winscan', 'all'],
                        help='Tipo de escaneo (default: %(default)s)')
    parser.add_argument("--test", help="tipo de escaneo a ejecutar", default="arpscan", )
    # Se procesas los argumentos
    args = parser.parse_args()
    targets = set_targets(args.targets)
    target_ports, raw_ports = set_ports(args.port, 'tcp')
    ifaz = args.interfaz
    tout = args.timeout
    hilos = args.hilos
    scantype = args.scantype

    parametros=[targets, raw_ports, ifaz, tout]

    seleccionar_funcion2(scantype, parametros, hilos)


    for target in targets:
        if target.getUP():
            target.setDown()
            print("equipo {0}, MAC:{1}, ttl:{2} is UP".format(str(target.ip),str(target.mac),str(target.ttl)))
            for port in target.puertos:
                print("\tIP:{0} - Port:{1} => {2}".format(str(target.ip), str(port.numero), str(port.estado)))


