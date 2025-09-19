## To Run N8N using docker in background
/****************  to run in background *************************/

### create docker volume to store n8n settings
docker volume create n8n_data

### run docker command to start n8n
docker run -d --restart unless-stopped  --name n8n  -p 5678:5678  -e GENERIC_TIMEZONE="Asia/Calcutta"  -e TZ="Asia/Calcutta"  -e N8N_ENFORCE_SETTINGS_FILE_PERMISSIONS=true  -e N8N_RUNNERS_ENABLED=true -e N8N_SECURE_COOKIE=false -v n8n_data:/home/node/.n8n  docker.n8n.io/n8nio/n8n

### To run with additional path mounted(pcap)
docker run -d --restart unless-stopped  --name n8n  -p 5678:5678  -e GENERIC_TIMEZONE="Asia/Calcutta"  -e TZ="Asia/Calcutta"  -e N8N_ENFORCE_SETTINGS_FILE_PERMISSIONS=true  -
e N8N_RUNNERS_ENABLED=true -e N8N_SECURE_COOKIE=false -v n8n_data:/home/node/.n8n  -v /home/balaji/n8n/pcap:/data/pcap docker.n8n.io/n8nio/n8n

// Note: set below env to false to access it locally
N8N_SECURE_COOKIE=false

# Check if it's running
docker ps

# View logs (great for debugging)
docker logs n8n

# Follow logs in real-time
docker logs -f n8n

# Stop the container
docker stop n8n

# Start it again
docker start n8n

# Remove the container (if needed)
docker rm n8n


