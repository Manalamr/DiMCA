#!/bin/bash

echo "==============================="
echo "🚀 Launching DMCA SD-IoT Testbed"
echo "==============================="

# Step 1: Launch BMv2 P4 switch using simple_switch_grpc
echo "🔧 Starting BMv2 P4 switches..."
gnome-terminal -- bash -c '
sudo simple_switch_grpc \
--no-p4 \
--device-id 1 \
--log-console \
--interface 1@eth1 \
--cpu-port 255 \
--grpc-server-addr 127.0.0.1:50051
'

# Step 2: Launch Ryu Controller with all modules
echo "🧠 Starting Ryu Controller with CPIA, CMLM, MCPA..."
gnome-terminal -- bash -c '
ryu-manager \
controller/ryu/dmca_cpia.py \
controller/ryu/dmca_cmlm.py \
controller/ryu/dmca_mcp_agent.py
'

# Step 3: Launch Mininet-WiFi Topology
echo "📡 Launching Mininet-WiFi Topology..."
sudo python3 topology/dmca_topo.py

echo "✅ All components launched."
