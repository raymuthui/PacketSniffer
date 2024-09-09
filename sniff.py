import socket
import struct
import sys

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ipv4(addr):
    return '.'.join(map(str, addr))

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    dest_mac = get_mac_addr(dest_mac)
    src_mac = get_mac_addr(src_mac)
    proto = socket.htons(proto)
    return dest_mac, src_mac, proto, data[14:]

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    src = ipv4(src)
    target = ipv4(target)
    return version, header_length, ttl, proto, src, target, data[header_length:]

def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def main():
    try:
        # Create a raw socket
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except PermissionError:
        print("Permission denied: You need to run this script as root.")
        sys.exit(1)
    except Exception as e:
        print(f"Error creating socket: {e}")
        sys.exit(1)

    while True:
        raw_data, addr = sniffer.recvfrom(65535)
        
        # Parse Ethernet Frame
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f'Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')
        
        # Parse IPv4 Packet
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print('IPv4 Packet:')
            print(f'Version: {version}, Header Length: {header_length}, TTL: {ttl}, Protocol: {proto}')
            print(f'Source: {src}, Target: {target}')
            
            # Parse TCP Segment
            if proto == 6:
                src_port, dest_port, sequence, acknowledgement, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                print('TCP Segment:')
                print(f'Source Port: {src_port}, Destination Port: {dest_port}')
                print(f'Sequence: {sequence}, Acknowledgement: {acknowledgement}')
                print(f'Flags: URG={flag_urg}, ACK={flag_ack}, PSH={flag_psh}, RST={flag_rst}, SYN={flag_syn}, FIN={flag_fin}')
                try:
                    data_str = data.decode()
                    print(f'Data: {data_str}')
                except:
                    print('Data: Non-decodable data')
                    
            elif proto == 17:
                # Handle UDP
                src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
                print('UDP Segment:')
                print(f'Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}')
                print(f'Data: {data[8:]}')

if __name__ == '__main__':
    main()

