import struct

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
STUN_HEADER_SIZE                = 20

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
STUN_ATTR_HEADER_SIZE           = 4

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
    for attr in attr_list[1:]:
        attr += struct.pack('!H', attr)    
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
    return struct.unpack('!HHQQ', attr)

    
# STUN Attribute Header    
def encode_attribute_header(type, attr_value):
    print(type)
    print(attr_value)
    return struct.pack('!HH', type, len(attr_value))

def decode_attribute_header(attr):
    return struct.unpack('!HH')