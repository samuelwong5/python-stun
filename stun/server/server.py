import socket
import os, sys
sys.path.append(os.path.abspath(".."))
from stun import *

# Server configurations
PRIMARY_IP = '172.22.20.6'
SECONDARY_IP = '172.22.20.7'
PRIMARY_PORT = 3478
SECONDARY_PORT = 3479

    
# Main STUN request handler
def stun_request_handler(sock):
    conn, addr = sock.accept()
    print('Connected to ' + addr[0] + ':' + str(addr[1]))
    stun_header = conn.recv(STUN_HEADER_SIZE)
    stun_type, payload_size, t_id_1, t_id_2 = decode_message_header(stun_header)
    if stun_type == STUN_BINDING_REQUEST:
        unknown_attr = []
        while payload_size > 0:
            attr_header = conn.recv(STUN_ATTR_HEADER_SIZE)
            attr_type, attr_size = decode_attribute_header(attr_header)
            attr_value = conn.recv(attr_size)
            response_addr = None
            if attr_type == ATTR_RESPONSE_ADDRESS:
                response_addr = decode_mapped_address(attr_value)
            elif attr_type == ATTR_CHANGE_REQUEST:
                change_flags = decode_change_request(attr_value)
                # Not implemented
            elif attr_type == ATTR_USERNAME:
                pass # TODO
            elif attr_type == ATTR_PASSWORD:
                pass # TODO
            elif attr_type == ATTR_MESSAGE_INTEGRITY:
                pass # TODO
            elif attr_type <= 0x7fff:
                unknown_attr.append(attr_type)
        if len(unknown_attr) > 0:
            error_code = encode_error_code(ERR_UNKNOWN_ATTRIBUTE)
            unkwn_attr = encode_unknown_attributes(unknown_attr)
            response_payload = [error_code, unkwn_attr]
            response_length = reduce(lambda x,y:x+len(y), response_payload, 0)
            response_header = encode_message_header(STUN_BINDING_ERR_RESPONSE, response_length, t_id_1, t_id_2)
        else:
            mapped_addr = encode_mapped_address(addr[0], addr[1])
            source_addr = encode_mapped_address(PRIMARY_IP, PRIMARY_PORT, ATTR_SOURCE_ADDRESS)
            changed_addr = encode_mapped_address(SECONDARY_IP, SECONDARY_PORT, ATTR_CHANGED_ADDRESS)
            response_payload = [mapped_addr, source_addr, changed_addr]
            response_length = reduce(lambda x,y:x+len(y), response_payload, 0)
            response_header = encode_message_header(STUN_BINDING_RESPONSE, response_length, t_id_1, t_id_2)
        conn.sendall(response_header)
        for r in response_payload:
            conn.sendall(r)
    elif stun_type == STUN_SHARED_SECRET_REQUEST:
        # TODO: Implement shared secret
        pass
    else:
        # Server should not receive stun response
        pass
    conn.close()

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((PRIMARY_IP, PRIMARY_PORT))
    s.listen(1)
    while True:
        stun_request_handler(s)
    
if __name__ == '__main__':
    main()

    
# TODO: Generate USERNAME, PASSWORD for TLS
# username = <prefix,rounded-time,clientIP,hmac>
#   Where prefix is some random text string (different for each shared
#   secret request), rounded-time is the current time modulo 20 minutes,
#   clientIP is the source IP address where the Shared Secret Request
#   came from, and hmac is an HMAC [13] over the prefix, rounded-time,
#   and client IP, using a server private key.
# password = <hmac(USERNAME,anotherprivatekey)> (128+ bits)
