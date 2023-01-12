# This is a sample Python script.
import argparse
import ipaddress
from signal import signal, SIGINT
from scapy.all import *
from sys import platform


# Press Mayús+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
#clase equipo para almacenar los equipos que se encuentren
class Equipo:
    def __init__(self, ip):
        self._ip = ip
        self._up = False
        self.nombre = ""
        self.mac = ""
        self.puertos = []
        self.so = ""

    def __hash__(self):
        return hash(self.ip)
    def __eq__(self, other):
        if isinstance(other, Equipo):
            return self.ip == other.ip
        return NotImplemented
    def add_port(self, port):
        self.puertos.append(Puerto)
    def setUp(self):
        self._up = True
    def getUP(self):
        return self._up

#clases tipo puerto para almacenar los puertos abiertos en un equipo
class Puerto:
    def __init__(self,numero):
        self._numero = numero
        self._tipo = "" #tcp,udp,sctp
        self._estado = ""
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

    def tipo(self):
        return self._tipo
    @tipo.setter
    def tipo(self, value):
        if not isinstance(value, string):
            raise TypeError("El tipo debe ser un string")
        if value not in ["tcp", "udp", "stcp"]:
            raise TypeError("el valor debe ser tcp, udp o stcp")
        self._tipo = value

def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.


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


def arp_scan(ifaz, targets, tout):
    # Se emiten los paquetes a broadcast a traves de la interfaz indicada
    print(
        'Se emiten paquetes ARP a traves de la interfaz {0} preguntando su dominio de broadcast por las IP solicitadas '
        .format(
            ifaz))
    for target in targets:
        print("se escanea el target:{0}".format(str(target.ip)))
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(target.ip)), iface=ifaz, timeout=tout, verbose=0)
        # ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%") )
        for i in ans:
            #print("{0} esta arriba".format(i[1].psrc))
            target.setUp()
            target.mac = i[1].hwsrc
    return targets


def tcp_connect_scan(targets, dst_ports):
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
    targets_port = set()
    try:
        for i in puertos.split(','):
            if '-' in i:
                [i.split('-')[0] && puerto_inicial = i.split('-')[0] || puerto_inicial=1]
                [i.split('-')[1] & & puerto_final = i.split('-')[1] || puerto_final=65535]
                for puerto in range(puerto_inicial,puerto_final):
                    targets_port.add(Puerto(puerto))
            else:
                targets_port.add(Puerto(i))
    except:
        print("Ups, algo fue mal con los puertos. Revisalos e intentalo de nuevo...")
    return targets_port



def handler(signal, frame):
    print("[!] Ctrl+c pulsado, saliendo del script")
    exit(1)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    # Capturamos el Ctrl-C para hacer una salida ordenada
    signal(SIGINT, handler)

    ayuda = 'Programa para realizar un escaneo de la red local'
    parser = argparse.ArgumentParser(description=ayuda)
    parser.add_argument("-p", "--port", help="puertos a escanear", default=22)
    parser.add_argument("-d", "--destino",
                        help="direccion a la que realizar el scaneo en formato CIDR:" + get_default_range(),
                        default=get_default_range())
    parser.add_argument("-i", "--interfaz", help="Interfaz por la que hacer el escaneo", choices=get_interfaces(),
                        default=get_work_interface())
    parser.add_argument("-t", "--timeout", help="Tiempo de espera para la recepcion de las respuestas: ", type=int,
                        default=5)
    # Se procesas los argumentos
    args = parser.parse_args()
    targets = set_targets(args.destino)
    #rango = ipaddress.ip_network(args.destino, strict=False) # ¿como queremos que nos pase el usuario las IP's a escanear? ¿un rango? ¿una lista? => cualquiera de las dos formas y en funcion de la entrada generamos un listado de equipos
    ifaz = args.interfaz
    tout = args.timeout
    [print("los targets son:{0}".format(str(target.ip))) for target in targets]

    targets = arp_scan(ifaz, targets, tout)
    [print("IP:{0} esta arriba".format(str(target.ip))) for target in targets if target.up]

    equipos = tcp_connect_scan()



    print_hi('PyCharm')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
