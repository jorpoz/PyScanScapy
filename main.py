# This is a sample Python script.
import argparse
import ipaddress
import logging
import threading
import time
import concurrent.futures
from signal import signal, SIGINT
from scapy.all import *
from sys import platform
from tqdm import tqdm
from copy import copy


# Press Mayús+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
#clase equipo para almacenar los equipos que se encuentren
class Equipo:
    def __init__(self, ip):
        self._ip = ip
        self._up = False
        self.nombre = ""
        self.mac = ""
        self.ttl = 0
        self.puertos = []
        self.so = ""

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
    def getUP(self):
        return self._up
    def arp_scan(self, ifaz, tout):
        # Se emiten los paquetes a broadcast a traves de la interfaz indicada
        print(
            'Se emiten paquetes ARP a traves de la interfaz {0} preguntando su dominio de broadcast por las IP solicitadas '
            .format(ifaz))
        print("se escanea el target:{0}".format(str(self.ip)))
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(self.ip)), iface=ifaz, timeout=tout,
                         verbose=0)
        # ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%") )
        for i in ans:
            # print("{0} esta arriba".format(i[1].psrc))
            self.setUp()
            self.mac = i[1].hwsrc

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
        self._estado = "" #open,closed,filtered
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
        if value not in ["open", "closed", "filtered"]:
            raise TypeError("el valor debe ser open, closed o filtered")
        self._estado = value
    '''def setEstado(self, value):
        if not isinstance(value, string):
            raise TypeError("El estado debe ser un string")
        if value not in ["open", "closed", "filtered"]:
            raise TypeError("El estado debe ser open, close, filtered")
        self.estado = value'''

def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.


# simple progress indicator callback function
def progress_indicator(future):
    print('.', end='', flush=True)


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
    conf.verb = -1  # para evitar mensajes de warning de scapy
    ans = srp1(Ether()/IP(dst=str(target.ip))/ICMP(), iface=ifaz, timeout=tout, verbose=0)
    conf.verb = 1  # para evitar mensajes de warning de scapy
    if ans is not None:
        target.setUp()
        target.ttl = ans.ttl
        target.mac = ans.src
    return target

def ping(host):
    # Enviamos un paquete ICMP a la dirección IP del host
    packet = IP(dst=host)/ICMP()
    reply = sr1(packet, timeout=1, verbose=0)
    # Si recibimos una respuesta, imprimimos la dirección IP del host
    if reply is not None:
        print(f'{host} is up')

def arp_scan2(arguments):
    iface = arguments[0]
    target = arguments[1]
    tout = arguments[2]

    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(target.ip)), iface=iface, timeout=tout, verbose=0)
    # ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%") )
    for i in ans:
        #print("{0} esta arriba".format(i[1].psrc))
        target.setUp()
        target.mac = i[1].hwsrc

def tcp_connect_scan2(target, dst_port, tout):
    src_port = RandShort()
    #response = sr1(IP(dst=str(target.ip))/TCP(sport=src_port,dport=int(dst_port.numero),flags="S"), timeout=tout, verbose=0)
    response = sr1(IP(dst=str(target.ip)) / TCP(sport=src_port, dport=int(dst_port), flags="S"), timeout=tout, verbose=0)
    if(str(type(response))=="<class 'NoneType'>"):
        #dst_port.estado = "closed"
        pass
    elif(response.haslayer(TCP)):
        if(response.getlayer(TCP).flags == 0x12):
            # este lo manda el SSOO
            #send_rst = sr1(IP(dst=str(target.ip))/TCP(sport=src_port,dport=int(dst_port.numero),flags="AR"), timeout=tout, verbose=0)
            send_rst = sr1(IP(dst=str(target.ip)) / TCP(sport=src_port, dport=int(dst_port), flags="R"),
                           timeout=tout, verbose=0)
            #dst_port.estado = "open"
            #target.add_port(copy(dst_port))
            print("paquete {0} open.".format(response.summary()))
            target.add_port(Puerto(dst_port, 'tcp'))
        elif(response.getlayer(TCP).flags == 0x14):
            #dst_port.estado = "closed"
            pass
    return target


def tcpping(target, dst_port, tout):
    src_port = RandShort()
    conf.verb = -1 # para evitar mensajes de warning de scapy
    response = sr1(IP(dst=str(target.ip)) / TCP(sport=src_port, dport=dst_port, flags="S"), timeout=tout, verbose=0)
    if response is not None:
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            target.setUp()
            #print(f"[+] Port {port} is open on {ip}")
            new_port=Puerto(dst_port, 'tcp')
            new_port.estado='open'
            target.add_port(new_port)
            response_packet = sr1(IP(dst=str(target.ip))/TCP(sport=src_port, dport=port, flags="R"), timeout=tout, verbose=0)
        else:
            pass
    conf.verb = 1 # restablecemos los mensajes de warning de scapy
    return target


def tcp_connect_scan_orig(targets, dst_ports):
    src_port = RandShort()
    for target in targets:
        for dst_port in dst_ports:
            response = sr1(IP(dst=str(target.ip))/TCP(src_port=src_port,dport=int(dst_port),flags="S"))
            if(str(type(response)=="<type 'NoneType'>")):
                print(dst_port+": Port Closed")
            elif(response.haslayer(TCP)):
                if(response.getlayer(TCP).flags == 0x12):
                    send_rst = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=int(dst_port),flags="AR"))
                    print(dst_port+": Port Open")
                elif(response.getlayer(TCP).flags == 0x14):
                    print(dst_port+": Port Closed")
    return targets

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
                for puerto in range(int(puerto_inicial),int(puerto_final)):
                    target_ports.add(Puerto(puerto, tipo))
                    raw_ports.add(puerto)
            else:
                target_ports.add(Puerto(i, tipo))
                raw_ports.add(int(i))
    except:
        print("Ups, algo fue mal con los puertos. Revisalos e intentalo de nuevo...")
    return target_ports, raw_ports



# Definimos una función que selecciona y ejecuta una función en función del parámetro de entrada
def seleccionar_funcion(nombre_funcion):
    # Buscamos la función correspondiente en el diccionario
    funcion = funciones.get(nombre_funcion)
    # Si la función existe, la ejecutamos
    if funcion is not None:
        funcion()
    else:
        print(f"La función {nombre_funcion} no existe")


def handler(signal, frame):
    print("[!] Ctrl+c pulsado, saliendo del script")
    exit(1)

#dispatch table
# Definimos una serie de funciones
def udpping():
    print("Has seleccionado la función 1")

def synscan():
    print("Has seleccionado la función 2")

def tcpconnect():
    print("Has seleccionado la función 3")

def ackscan():
    print("Has seleccionado la función 3")


# Creamos un diccionario que mapea nombres de funciones a objetos de función
funciones = {
    "arpping": arpping,
    "icmpping": icmpping,
    "tcpping": tcpping,
    "udpping": udpping,
    "synscan": synscan,
    "tcpconnect": tcpconnect,
    "ackscan": ackscan
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


# Press the green button in the gutter to run the script.
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
    parser.add_argument("-H", "--hilos", help="numero de hilos", type=int, default=128)
    parser.add_argument('--scantype',
                        default='arpping',
                        const='arpping',
                        nargs='?',
                        choices=['arpping', 'icmpping', 'tcpping', 'udpping', 'synscan', 'tcpconnect', 'ackscan', 'all'],
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
    conf.verb = -1  # para evitar mensajes de warning de scapy
    seleccionar_funcion(scantype, parametros, hilos)
    seleccionar_funcion('icmpping', parametros, hilos)
    seleccionar_funcion('tcpping', parametros, hilos)
    conf.verb = 1  # para evitar mensajes de warning de scapy
    '''
    with tqdm(total=len(targets)) as pbar1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=128) as executor:
            #executor.map(arp_scan2, arguments)
            futures = [executor.submit(arp_scan, ifaz, target, tout) for target in targets]
            for future in concurrent.futures.as_completed(futures):
                # get the downloaded url data
                pbar1.update(1)
                #future.add_done_callback(progress_indicator)
                target = future.result()
                #if target.getUP():
                    #print("[!]IP:{0} esta arriba".format(str(target.ip)))
    #targets = arp_scan(ifaz, targets, tout)
    #[print("IP:{0} esta arriba".format(str(target.ip))) for target in targets if target.getUP()]

    targets_ports = [(target, port) for target in targets for port in target_ports if target.getUP()]
    targets_ports = [(target, port) for target in targets for port in raw_ports if target.getUP()]
    with tqdm(total=len(targets_ports)) as pbar2:
        with concurrent.futures.ThreadPoolExecutor(max_workers=128) as executor:
            #futures = [executor.submit(tcp_connect_scan, aux[0], aux[1], tout) for aux in targets_ports]
            #futures = [executor.submit(tcp_connect_scan, target, port, tout) for target in targets for port in target_ports if target.getUP()]
            futures = [executor.submit(tcp_connect_scan, target, port, tout) for target in targets for port in
                       raw_ports if target.getUP()]
            for future in concurrent.futures.as_completed(futures):
                pbar2.update(1)
                target = future.result()
                '''
    for target in targets:
        if target.getUP():
            print("equipo {0}, MAC:{1}, ttl:{2} is UP".format(str(target.ip),str(target.mac),str(target.ttl)))
            for port in target.puertos:
                print("\tIP:{0} - Port:{1} => {2}".format(str(target.ip), str(port.numero), str(port.estado)))
    #equipos = tcp_connect_scan()

    print_hi('PyCharm')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
