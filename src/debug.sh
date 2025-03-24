#!/bin/bash

HEX_PAYLOAD="0000007b0100000001000012737570706f727465642d76657273696f6e730803322e300e6d61782d6672616d652d73697a6503fcf0060c6361706162696c6974696573080a706970656c696e696e6709656e67696e652d6964082434313237643133372d356132612d343535372d393034382d343965636133306235346639"

# Function to parse varint from hex string starting at offset
parse_varint() {
    local hex_str=$1
    local offset=$2
    local varint_value=0
    local shift=0
    local byte
    local byte_hex

    while :; do
        byte_hex=${hex_str:offset:2}
        [ -z "$byte_hex" ] && break
        byte=$((16#$byte_hex))
        varint_value=$((varint_value | ((byte & 0x7F) << shift)))
        offset=$((offset + 2))
        shift=$((shift + 7))
        if (((byte & 0x80) == 0)); then
            break
        fi
    done

    echo "$varint_value $offset"
}

# Parse frame length (4 bytes)
frame_length_hex=${HEX_PAYLOAD:0:8}
frame_length=$((16#$frame_length_hex))
echo "Frame Length: $frame_length (0x$frame_length_hex)"

# Parse frame type (1 byte)
frame_type_hex=${HEX_PAYLOAD:8:2}
frame_type=$((16#$frame_type_hex))
echo -e "\nFrame Type: 0x$frame_type_hex ($frame_type)"

# Parse flags (4 bytes)
flags_hex=${HEX_PAYLOAD:10:8}
flags=$((16#$flags_hex))
echo -e "Flags: 0x$flags_hex ($flags)"

# Parse Stream ID (varint)
read -r stream_id new_offset < <(parse_varint "$HEX_PAYLOAD" 18)
echo -e "\nStream ID: $stream_id"

# Parse Frame ID (varint)
read -r frame_id new_offset < <(parse_varint "$HEX_PAYLOAD" "$new_offset")
echo -e "Frame ID: $frame_id"

# Extract payload
payload_hex=${HEX_PAYLOAD:$new_offset}
echo -e "\nPayload (hex):\n$payload_hex"

# Convert payload to ASCII
echo -e "\nPayload (ASCII):"
echo -n "$payload_hex" | xxd -r -p | cat -v
echo
