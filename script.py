import subprocess
import json
import os
import matplotlib.pyplot as plt
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

def analyze_pcap(file_path):
    """Analyzes a PCAP file using TShark CLI instead of Pyshark to avoid asyncio issues."""
    
    # Command to extract protocol statistics
    cmd = ["tshark", "-r", file_path, "-T", "json"]
    
    try:
        # Run TShark as a subprocess (No asyncio issues!)
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        packets = json.loads(result.stdout)
        
        protocol_count = {}
        ip_traffic = {}
        dns_queries = []

        for packet in packets:
            try:
                layers = packet["_source"]["layers"]
                
                # Extract protocol information
                protocol = layers.get("frame", {}).get("frame.protocols", "")
                if protocol:
                    protocol_list = protocol.split(":")
                    for p in protocol_list:
                        protocol_count[p] = protocol_count.get(p, 0) + 1

                # Extract IP traffic
                if "ip" in layers:
                    src_ip = layers["ip"].get("ip.src")
                    if src_ip:
                        ip_traffic[src_ip] = ip_traffic.get(src_ip, 0) + 1
                
                # Extract DNS queries
                if "dns" in layers and "dns.qry.name" in layers["dns"]:
                    dns_queries.append(layers["dns"]["dns.qry.name"])
            except KeyError:
                continue  # Ignore packets with missing fields

        generate_plots(protocol_count, ip_traffic)

        return {
            "protocol_count": protocol_count,
            "ip_traffic": ip_traffic,
            "dns_queries": dns_queries[:10]  # Limit to top 10 queries
        }
    
    except subprocess.CalledProcessError as e:
        return {"error": f"TShark failed: {e}"}
    except json.JSONDecodeError:
        return {"error": "Failed to parse TShark output"}

def generate_plots(protocol_count, ip_traffic):
    """Generates and saves protocol and IP traffic plots."""
    # Ensure 'static/' directory exists
    if not os.path.exists("static"):
        os.makedirs("static")

    # Protocol distribution pie chart
    plt.figure(figsize=(8, 6))
    sorted_protocols = sorted(protocol_count.items(), key=lambda x: x[1], reverse=True)
    labels, sizes = zip(*sorted_protocols[:8])  # Show only the top 8 protocols
    other_sum = sum(value for _, value in sorted_protocols[8:])
    if other_sum > 0:
        labels += ("Others",)
        sizes += (other_sum,)
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, pctdistance=0.85)
    plt.title("Protocol Distribution (Pie Chart)")
    plt.savefig("static/protocol_distribution.png", bbox_inches="tight")
    plt.close()

    # Protocol distribution bar chart
    plt.figure(figsize=(10, 6))
    plt.barh(labels, sizes, color='skyblue')
    plt.xlabel("Packet Count")
    plt.ylabel("Protocols")
    plt.title("Protocol Distribution (Bar Chart)")
    plt.gca().invert_yaxis()  # Invert Y-axis for better readability
    plt.savefig("static/protocol_distribution_bar.png", bbox_inches="tight")
    plt.close()

    # IP traffic bar chart with horizontal labels
    plt.figure(figsize=(10, 6))
    plt.bar(ip_traffic.keys(), ip_traffic.values(), color='skyblue')
    plt.xticks(rotation=0, ha='center')  # Ensure labels are horizontal
    plt.xlabel("IP Addresses")
    plt.ylabel("Packet Count")
    plt.title("IP Traffic")
    plt.savefig("static/ip_traffic.png", bbox_inches="tight")
    plt.close()

@app.route('/')
def index():
    return render_template("index.html", 
                           protocol_plot_pie="/static/protocol_distribution.png", 
                           protocol_plot_bar="/static/protocol_distribution_bar.png", 
                           ip_plot="/static/ip_traffic.png", 
                           selected_chart="pie",
                           analysis_results=None)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']
    file_path = "uploaded.pcap"
    file.save(file_path)

    analysis_results = analyze_pcap(file_path)
    return render_template("index.html", 
                           protocol_plot_pie="/static/protocol_distribution.png", 
                           protocol_plot_bar="/static/protocol_distribution_bar.png", 
                           ip_plot="/static/ip_traffic.png", 
                           selected_chart="pie",
                           analysis_results=analysis_results)

@app.route('/toggle_chart', methods=['POST'])
def toggle_chart():
    """Handles user selection of Pie Chart or Bar Chart."""
    chart_type = request.form.get("chart_type", "pie")  # Default to pie chart
    return render_template("index.html",
                           protocol_plot_pie="/static/protocol_distribution.png",
                           protocol_plot_bar="/static/protocol_distribution_bar.png",
                           ip_plot="/static/ip_traffic.png",
                           selected_chart=chart_type,
                           analysis_results=None)

if __name__ == "__main__":
    # app.run(debug=True)

    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))

