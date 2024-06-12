import logging

def analyze_packet(packet_data):
    try:
        if len(packet_data) < 5:
            logging.warning("Insufficient data to analyze packet")
            return None
        
        protocol, src_ip, dst_ip, src_port, dst_port = packet_data[:5]

        # Example intrusion detection rules
        if protocol == 'TCP' and (src_port == '80' or dst_port == '80'):
            logging.info("Potential HTTP intrusion detected")
            return protocol, src_ip, src_port, dst_ip, dst_port
        
        if protocol == 'UDP' and (dst_port == '53' or dst_port == '5353'):
            logging.info("Potential DNS or mDNS intrusion detected")
            return protocol, src_ip, src_port, dst_ip, dst_port

        # Additional rules
        if protocol == 'TCP' and (src_port == '22' or dst_port == '22'):
            logging.info("Potential SSH intrusion detected")
            return protocol, src_ip, src_port, dst_ip, dst_port
        
        if protocol == 'UDP' and (dst_port == '123' or dst_port == '1234'):
            logging.info("Potential NTP intrusion detected")
            return protocol, src_ip, src_port, dst_ip, dst_port

        # If no intrusion detected
        return None
    except Exception as e:
        logging.error(f"Error analyzing packet: {e}")
        return None
