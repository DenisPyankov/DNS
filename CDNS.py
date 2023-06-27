import socket
import struct
import pickle
import time

CACHE_TTL = 300


class CacheEntry:
    def __init__(self, data):
        self.data = data
        self.timestamp = time.time()

    def is_expired(self):
        return time.time() - self.timestamp > CACHE_TTL


cache = {}

try:
    with open('cache.pickle', 'rb') as f:
        cache = pickle.load(f)
except FileNotFoundError:
    pass

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 53))

print('DNS-сервер запущен и прослушивает порт 53...')


def parse_dns_packet(packet):
    dns_header = struct.unpack('!HHHHHH', packet[:12])
    id = dns_header[0]
    qr = (dns_header[1] >> 15) & 1
    opcode = (dns_header[1] >> 11) & 15
    aa = (dns_header[1] >> 10) & 1
    tc = (dns_header[1] >> 9) & 1
    rd = (dns_header[1] >> 8) & 1
    ra = (dns_header[1] >> 7) & 1
    z = (dns_header[1] >> 4) & 7
    rcode = dns_header[1] & 15
    qdcount = dns_header[2]
    ancount = dns_header[3]
    nscount = dns_header[4]
    arcount = dns_header[5]

    offset = 12
    questions = []
    for _ in range(qdcount):
        question, offset = parse_dns_question(packet, offset)
        questions.append(question)

    answers = []
    for _ in range(ancount):
        answer, offset = parse_dns_resource_record(packet, offset)
        answers.append(answer)

    authorities = []
    for _ in range(nscount):
        authority, offset = parse_dns_resource_record(packet, offset)
        authorities.append(authority)

    additional_records = []
    for _ in range(arcount):
        record, offset = parse_dns_resource_record(packet, offset)
        additional_records.append(record)

    return {
        'id': id,
        'qr': qr,
        'opcode': opcode,
        'aa': aa,
        'tc': tc,
        'rd': rd,
        'ra': ra,
        'z': z,
        'rcode': rcode,
        'qdcount': qdcount,
        'ancount': ancount,
        'nscount': nscount,
        'arcount': arcount,
        'questions': questions,
        'answers': answers,
        'authorities': authorities,
        'additional_records': additional_records
    }


def parse_dns_question(packet, offset):
    qname_parts = []
    while True:
        length = packet[offset]
        if length == 0:
            break
        qname_parts.append(packet[offset + 1: offset + length + 1].decode('utf-8'))
        offset += length + 1

    qname = '.'.join(qname_parts)
    qtype, qclass = struct.unpack('!HH', packet[offset + 1: offset + 5])
    return {
        'qname': qname,
        'qtype': qtype,
        'qclass': qclass
    }, offset + 5


def parse_dns_resource_record(packet, offset):
    name_parts = []
    while True:
        length = packet[offset]
        if length >= 192:
            offset += 2
            break
        name_parts.append(packet[offset + 1: offset + length + 1].decode('utf-8'))
        offset += length + 1

    name = '.'.join(name_parts)
    rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', packet[offset: offset + 10])
    rdata = packet[offset + 10: offset + 10 + rdlength]
    offset += 10 + rdlength

    return {
        'name': name,
        'type': rtype,
        'class': rclass,
        'ttl': ttl,
        'rdlength': rdlength,
        'rdata': rdata
    }, offset


def print_dns_packet(dns_packet):
    print('ID:', dns_packet['id'])
    print('QR:', dns_packet['qr'])
    print('Opcode:', dns_packet['opcode'])
    print('AA:', dns_packet['aa'])
    print('TC:', dns_packet['tc'])
    print('RD:', dns_packet['rd'])
    print('RA:', dns_packet['ra'])
    print('Z:', dns_packet['z'])
    print('RCODE:', dns_packet['rcode'])
    print('QDCOUNT:', dns_packet['qdcount'])
    print('ANCOUNT:', dns_packet['ancount'])
    print('NSCOUNT:', dns_packet['nscount'])
    print('ARCOUNT:', dns_packet['arcount'])

    print('Questions:')
    for question in dns_packet['questions']:
        print('  QNAME:', question['qname'])
        print('  QTYPE:', question['qtype'])
        print('  QCLASS:', question['qclass'])

    print('Answers:')
    for answer in dns_packet['answers']:
        print('  NAME:', answer['name'])
        print('  TYPE:', answer['type'])
        print('  CLASS:', answer['class'])
        print('  TTL:', answer['ttl'])
        print('  RDLENGTH:', answer['rdlength'])
        print('  RDATA:', answer['rdata'])

    print('Authorities:')
    for authority in dns_packet['authorities']:
        print('  NAME:', authority['name'])
        print('  TYPE:', authority['type'])
        print('  CLASS:', authority['class'])
        print('  TTL:', authority['ttl'])
        print('  RDLENGTH:', authority['rdlength'])
        print('  RDATA:', authority['rdata'])

    print('Additional Records:')
    for record in dns_packet['additional_records']:
        print('  NAME:', record['name'])
        print('  TYPE:', record['type'])
        print('  CLASS:', record['class'])
        print('  TTL:', record['ttl'])
        print('  RDLENGTH:', record['rdlength'])
        print('  RDATA:', record['rdata'])


while True:
    try:
        data, addr = sock.recvfrom(1024)
        request = data.decode().strip()

        if request in cache and not cache[request].is_expired():
            response = cache[request].data
            print('Запись найдена в кэше:', request, '->', response)
            print('---')
        else:
            upstream_server = ('8.8.8.8', 53)
            upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            upstream_sock.sendto(data, upstream_server)
            response, _ = upstream_sock.recvfrom(1024)
            cache[request] = CacheEntry(response)
            print('Запись добавлена в кэш:', request, '->', response)
            print('---')

        expired_entries = [key for key in cache.keys() if cache[key].is_expired()]
        for key in expired_entries:
            del cache[key]
            print('Запись удалена из кэша', key)
            print('---')

        dns_packet = parse_dns_packet(data)
        print_dns_packet(dns_packet)

        sock.sendto(response, addr)

        with open('cache.pickle', 'wb') as f:
            pickle.dump(cache, f)
    except ConnectionResetError:
        continue
