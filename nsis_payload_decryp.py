"""
Created by Fortiguard Lion Team
Locky's decryptor for encrypted payload
found in NSIS package
"""

import os
import sys
import struct


def main():
    if len(sys.argv) == 1:
        print 'Usage : %s <encrypted payload>' %os.path.basename(__file__)
        sys.exit(1)

    file_input = sys.argv[1]

    with open(file_input, 'rb') as f:
        buf = f.read(8)

        row = struct.unpack("cccci", buf)
        char1, char2, char3, char4, dsize = row
        key1 = ord(char1)
        key2 = ord(char2)
        key3 = ord(char3)
        key4 = ord(char4)
        encrypted_payload = f.read()

    if len(encrypted_payload) != dsize:
        print 'Not a valid encrypted payload'
        sys.exit(1)

    file_output = '%s.decrypt' %file_input

    with open(file_output, 'wb') as o:
        offset_counter = 0
        key_option = 1
        for b in encrypted_payload:
            b = ord(b)
            if key_option == 1:
                b_result = key1 ^ b
            elif key_option == 2:
                b_result = key2 ^ b
            elif key_option == 3:
                b_result = key3 ^ b
            elif key_option == 4:
                b_result = key4 ^ b
            final_b_result = b_result ^ offset_counter
            final_b_result = final_b_result & 0xff
            offset_counter+=1
            o.write(chr(final_b_result))

            key_option+=1
            if key_option > 4:
                key_option = 1
    print 'Decrypt done. Outfile : %s' %file_output

if __name__ == '__main__':
    main()
