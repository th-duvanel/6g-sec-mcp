import os
import json
import redis
import time
import threading

MEC_ID = os.getenv("MEC_ID", "MEC-X")
redis_client = redis.Redis(host=os.getenv("REDIS_HOST", "localhost"), port=6379, decode_responses=True)

def listen_swarm_alerts():
    pubsub = redis_client.pubsub()
    pubsub.subscribe("edge/security/alerts")
    print(f"[{MEC_ID}] Escutando inteligencia compartilhada da borda...")
    
    for message in pubsub.listen():
        if message["type"] == "message":
            alert = json.loads(message["data"])
            if alert["source_mec"] != MEC_ID:
                print(f"[{MEC_ID}] Alerta recebido de {alert['source_mec']}: IP {alert['malicious_ip']}")
                print(f"[{MEC_ID}] Acao Proativa: Bloqueio aplicado via MCP.")

threading.Thread(target=listen_swarm_alerts, daemon=True).start()

def simulate_local_detection_and_response():
    print(f"[{MEC_ID}] Lendo telemetria via MCP Resources...")
    time.sleep(2)
    
    malicious_ip = "10.0.0.55"
    print(f"[{MEC_ID}] Ataque detectado. Invocando MCP Tool para bloqueio local...")
    
    alert_payload = {
        "source_mec": MEC_ID,
        "malicious_ip": malicious_ip,
        "threat_type": "DDoS",
        "timestamp": time.time()
    }
    redis_client.publish("edge/security/alerts", json.dumps(alert_payload))
    print(f"[{MEC_ID}] Inteligencia propagada para o Swarm.")

if MEC_ID == "MEC-1":
    time.sleep(3)
    simulate_local_detection_and_response()
    while True:
        time.sleep(1)
else:
    while True:
        time.sleep(1)