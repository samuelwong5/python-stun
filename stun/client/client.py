import random
import socket
import os, sys
sys.path.append(os.path.abspath(".."))
from stun import *

# Client configurations
HOST = '172.22.20.6'
PORT = 3478

def stun_request(sock):
    sock.connect((HOST,PORT))
    t_id_1 = random.randint(0, 2**32-1) # Random 4 byte long
    t_id_2 = random.randint(0, 2**32-1)
    req_header = encode_message_header(STUN_BINDING_REQUEST, 0, t_id_1, t_id_2)
    sock.sendall(req_header)
    stun_header = sock.recv(STUN_HEADER_SIZE)
    stun_type, payload_size, t_id_3, t_id_4 = decode_message_header(stun_header)
    if t_id_1 != t_id_3 or t_id_2 != t_id_4:
        print('Error: Transaction ID does not match.')
        print('Expected: ' + str(t_id_1) + str(t_id_2))
        print('Got:      ' + str(t_id_3) + str(t_id_4))
        return
    if stun_type == STUN_BINDING_RESPONSE:
        while payload_size > 0:
            attr_header = sock.recv(STUN_ATTR_HEADER_SIZE)
            attr_type, attr_size = decode_attribute_header(attr_header)
            attr_value = sock.recv(attr_size)
            response_addr = None
            if attr_type == ATTR_MAPPED_ADDRESS:
                mapped_addr = decode_mapped_address(attr_value)
            elif attr_type == ATTR_SOURCE_ADDRESS:
                source_addr = decode_mapped_address(attr_value)
            elif attr_type == ATTR_CHANGED_ADDRESS:
                changed_addr = decode_mapped_address(attr_value)
            elif attr_type == ATTR_REFLECTED_FROM:
                pass # TODO
            elif attr_type == ATTR_MESSAGE_INTEGRITY:
                pass # TODO
        print('MAPPED-ADDRESS')
        print(mapped_addr)
        print('SOURCE-ADDRESS')
        print(source_addr)
        print('CHANGED-ADDRESS')
        print(changed_addr)
    elif stun_type == STUN_BINDING_ERR_RESPONSE:
        while payload_size > 0:
            attr_header = sock.recv(STUN_ATTR_HEADER_SIZE)
            attr_type, attr_size = decode_attribute_header(attr_header)
            attr_value = sock.recv(attr_size)
            response_addr = None
            if attr_type == ATTR_ERROR_CODE:
                error_code = decode_error_code(attr_value)
                print(error_code)
            elif attr_type == ATTR_UNKNOWN_ATTRIBUTES:
                unknown_attr = decode_unknown_attributes(attr_value)
                print(unknown_attr)
    elif stun_type == STUN_SHARED_SECRET_RESPONSE:
        # TODO: Implement shared secret
        pass
    else:
        # Client should not receive STUN request
        pass
    sock.close()    
    

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    stun_request(s)
    
    
if __name__ == '__main__':
    main()
