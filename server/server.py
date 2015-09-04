import struct

# Server configurations
PRIMARY_IP = ""
SECONDARY_IP = ""
PRIMARY_PORT = 3478
SECONDARY_PORT = 3479

# STUN HEADER
#   0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |      STUN Message Type        |         Message Length        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                            Transaction ID (128bit)
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                                                                   |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
STUN_BINDING_REQUEST            = 0x0001
STUN_BINDING_RESPONSE           = 0x0101
STUN_BINDING_ERR_RESPONSE       = 0x0111
STUN_SHARED_SECRET_REQUEST      = 0x0002
STUN_SHARED_SECRET_RESPONSE     = 0x0102
STUN_SHARED_SECRET_ERR_RESPONSE = 0x0112

# ATTRIBUTES
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |         Type                  |            Length             |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                             Value                             ....
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
ATTR_MAPPED_ADDRESS             = 0x0001
ATTR_RESPONSE_ADDRESS           = 0x0002
ATTR_CHANGE_REQUEST             = 0x0003
ATTR_SOURCE_ADDRESS             = 0x0004
ATTR_CHANGED_ADDRESS            = 0x0005
ATTR_USERNAME                   = 0x0006
ATTR_PASSWORD                   = 0x0007
ATTR_MESSAGE_INTEGRITY          = 0x0008
ATTR_ERROR_CODE                 = 0x0009
ATTR_UNKNOWN_ATTRIBUTES         = 0x000a
ATTR_REFLECTED_FROM             = 0x000b

# Utility functions to convert between string and integer representation of IPv4 address
def ip_string_to_int(ip):
    s = map(int, ip.split('.'))
    return s[0] << 24 | s[1] << 16 | s[2] << 8 | s[3]

def ip_int_to_string(ip):
    return '.'.join(map(str, [(ip & 0xff000000) >> 24, 
                              (ip & 0x00ff0000) >> 16, 
                              (ip & 0x0000ff00) >> 8, 
                              (ip & 0x000000ff)]))

         
# MAPPED-ADDRESS indicates the mapped IP address and port
# RESPONSE-ADDRESS indicates the IP address and port the binding request response should be sent
# CHANGED-ADDRESS indicates the IP address and port if change IP and change port flags are set  
# SOURCE-ADDRESS indicates the IP address and port the server is sending the response from  
# REFLECTED-FROM indicates IP address and port where the request came from (trace; prevent DDoS)
IP_FAMILY = 0x1 # Always 0x01 (IPv4) according to RFC3489  

def encode_mapped_address(ip, port, type=ATTR_MAPPED_ADDRESS):
    attr = struct.pack('!xBHI', IP_FAMILY, port, ip_string_to_int(ip))
    return encode_attribute_header(type, attr) + attr
    
def decode_mapped_address(attr):
    ip_family, port, ip_int = b.unpack('!xBHI', attr)
    return ip_int_to_string(ip_int), port

    
# CHANGE-REQUEST requests a different address and/or port when sending the response   
CHANGE_IP = 0x4
CHANGE_PORT = 0x2
 
def encode_change_request(change_ip, change_port):
    flags = 0x0
    if change_ip:
        flags &= CHANGE_IP
    if change_port:
        flags &= CHANGE_PORT
    attr = struct.pack('!I', flags)
    return encode_attribute_header(ATTR_CHANGE_REQUEST, attr) + attr
    
def decode_change_request(attr):
    flags = struct.unpack('!I', attr)
    return CHANGE_IP & flags, CHANGE_PORT & flags
  
  
# ERROR-CODE is a numeric value (100-699) plus text (UTF-8) indicating the error occurred
ERR_BAD_REQUEST = (400, 'Bad Request') # Malformed request
ERR_UNAUTHORIZED = (401, 'Unauthorized') # Missing MESSAGE-INTEGRITY in Binding Request
ERR_UNKNOWN_ATTRIBUTE = (420, 'Unknown Attribute') # The server did not understand a mandatory attribute
ERR_STALE_CREDENTIALS = (430, 'Stale Credentials') # The shared secret was expired
ERR_INT_CHECK_FAIL = (431, 'Integrity Check Failure') # HMAC not consistent
ERR_MISSING_USERNAME = (432, 'Missing Username') # Missing USERNAME attribute
ERR_USE_TLS = (433, 'Use TLS') # Shared Secret request was not received over TLS
ERR_SERVER_ERROR = (500, 'Server Error') # Server suffered temporary error (Should retry)
ERR_GLOBAL_FAIL = (600, 'Global Failure') # Server refusing the request (Don't retry)

def encode_error_code(err):
    err_code, err_msg = err
    err_class = err_code / 100
    err_numbr = err_code % 100
    attr = struct.pack('!xxBBI', err_class, err_number, err_msg)
    return encode_attribute_header(ATTR_ERROR_CODE, attr) + attr
 
def decode_error_code(attr):
    err_class, err_numbr, err_msg = struct.unpack('!xxBBI', attr)
    err_code = err_class * 100 + err_numbr
    return err_code, err_msg
    
    
# UNKNOWN-ATTRIBUTES is present when the response ERROR-CODE is 420
def encode_unknown_attributes(attr_list):
    if len(attr_list) == 0:
        return
    attr = struct.pack('!H', attr_list[0])
    for attr_list[1:]:
        attr += struct.pack('!H', attr_list[1])    
    if len(attr_list) % 2 == 1: # Repeat a value if odd number of unknown attributes
        attr += struct.pack('!H', attr_list[0])
    return encode_attribute_header(ATTR_UNKNOWN_ATTRIBUTES, attr) + attr
    
def decode_unknown_attributes(attr):
    return struct.unpack('!' + ('H' * len(attr) / 2), attr)


# STUN Message Header
def encode_message_header(type, size, t_id_1, t_id_2):
    attr = struct.pack('!HHQQ', type, size, t_id_1, t_id_2)
    return attr
  
def decode_message_header(attr):
    return struct.unpack('!HHQQ', stun_header)

    
# STUN Attribute Header    
def encode_attribute_header(type, attr_value):
    return struct.pack('!HH', type, len(attr_value))

def decode_attribute_header(attr):
    return struct.unpack('!HH')
    
# Main STUN request handler
STUN_HEADER_SIZE      = 20
STUN_ATTR_HEADER_SIZE = 4

def stun_request_handler():
    conn, addr = s.accept()
    stun_header = conn.recv(STUN_HEADER_SIZE)
    stun_type, payload_size, t_id_1, t_id_2 = decode_message_header(stun_header)
    if stun_type == STUN_BINDING_REQUEST:
        while payload_size > 0:
            attr_header = conn.recv(STUN_ATTR_HEADER_SIZE)
            attr_type, attr_size = decode_attribute_header(attr_header)
            attr_value = conn.recv(attr_size)
            unknown_attr = []
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
            response_length = reduce(lambda x,y:x+len(y), respones_payload, 0)
            response_header = encode_message_header(STUN_BINDING_ERR_RESPONSE, response_length, t_id_1, t_id_2)
        else:
            mapped_addr = encode_mapped_address(addr[0], addr[1])
            source_addr = encode_mapped_address(PRIMARY_IP, PRIMARY_PORT, ATTR_SOURCE_ADDRESS)
            changed_addr = encode_mapped_address(SECONDARY_IP, SECONDARY_PORT, ATTR_CHANGED_ADDRESS)
            response_payload = [mapped_addr, source_addr, changed_addr]
            response_length = reduce(lambda x,y:x+len(y), respones_payload, 0)
            response_header = encode_message_header(STUN_BINDING_RESPONSE, response_length, t_id_1, t_id_2)
        conn.sendall(response_header)
        for r in response_payload:
            conn.sendall(r)
    else if stun_type == STUN_SHARED_SECRET_REQUEST:
        # TODO: Implement shared secret
        pass
    else:
        # Server should not receive stun response
        pass

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((PRIMARY_IP, PRIMARY_PORT))
    s.listen(1)
    while True:
        stun_request_handler()
    
# TODO: Generate USERNAME, PASSWORD for TLS
# username = <prefix,rounded-time,clientIP,hmac>
#   Where prefix is some random text string (different for each shared
#   secret request), rounded-time is the current time modulo 20 minutes,
#   clientIP is the source IP address where the Shared Secret Request
#   came from, and hmac is an HMAC [13] over the prefix, rounded-time,
#   and client IP, using a server private key.
# password = <hmac(USERNAME,anotherprivatekey)> (128+ bits)
