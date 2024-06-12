from flask import Flask, render_template
from src.packet_capture import capture_packets
from src.packet_analysis import analyze_packet
import logging

app = Flask(__name__)

PAGE_SIZE = 10  # Number of intrusions per page
FILTER_EXPRESSION = 'tcp'  # Set filter expression for TCP traffic

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/intrusions')
@app.route('/intrusions/<int:page>')
async def detect_intrusions(page=1):
    try:
        start_index = (page - 1) * PAGE_SIZE
        end_index = start_index + PAGE_SIZE
        
        intrusions = await get_intrusions(start_index, end_index)
        
        has_prev = page > 1
        has_next = len(intrusions) == PAGE_SIZE
        prev_page = page - 1 if has_prev else None
        next_page = page + 1 if has_next else None
        
        return render_template('intrusions.html', intrusions=intrusions, prev_page=prev_page, next_page=next_page, has_prev=has_prev, has_next=has_next)
    
    except Exception as e:
        logging.error(f"Error detecting intrusions: {e}")
        return render_template('error.html', error=str(e))

async def get_intrusions(start_index, end_index):
    intrusions = []
    filter_expression = 'tcp'  # Set filter expression for TCP traffic
    async for packet_data in capture_packets(interface='Wi-Fi', filter_expression=filter_expression):
        result = analyze_packet(packet_data)
        if result:
            protocol, src_ip, src_port, dst_ip, dst_port = result
            intrusion = {
                "protocol": protocol,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port
            }
            intrusions.append(intrusion)
            if len(intrusions) >= end_index:
                break
    return intrusions

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    app.run(debug=True)
